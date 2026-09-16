"""F12: scoped API tokens — bearer accepted with Basic-Auth semantics (JSON
errors, CSRF bypass), expired/revoked/tampered refused, scope enforcement
per request, token kinds kept apart (metrics vs API), deactivated owner,
forced-password gate, role ceiling, audit rows, UI page and CLI."""
import base64
from datetime import datetime, timedelta, timezone

import pytest

from app.extensions import db as _db
from app.models.api_token import ApiToken, SCOPES
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services import api_token_service, ca_service, cert_service, metrics_token_service, profile_service

PASSPHRASE = "test-passphrase"
JSON = {"Accept": "application/json"}


@pytest.fixture(autouse=True)
def _seed_profiles(app, db):
    with app.app_context():
        profile_service.ensure_builtins()


def _token(user, scopes=("read",), days=30, name=None):
    plaintext, row = api_token_service.create(user, name or f"t-{'-'.join(scopes)}", list(scopes), days)
    _db.session.commit()
    return plaintext, row


def _bearer(t):
    return {"Authorization": f"Bearer {t}", "Accept": "application/json"}


def _root(name="Token Root"):
    return ca_service.create_root_ca(name=name, subject_attrs={"CN": name}, key_type="EC", key_size=256,
                                     validity_days=3650, passphrase=PASSPHRASE)


class TestService:
    def test_create_stores_hash_and_validates(self, app, db, admin_user):
        with app.app_context():
            pt, row = _token(admin_user, ("read", "issue"))
            assert pt.startswith("chy_api_") and row.token_hash == ApiToken.hash_secret(pt.split("_", 3)[3])
            assert row.scopes == ["issue", "read"] and row.status == "active" and row.has_scope("issue") and not row.has_scope("admin")
            assert "token_hash" not in row.to_dict() and pt not in str(row.to_dict())
            assert api_token_service.verify(pt) is row
            assert api_token_service.verify(pt[:-1] + ("0" if pt[-1] != "0" else "1")) is None
            assert api_token_service.verify("cmt_deadbeef_" + "0" * 64) is None
            for bad in ({"scopes": ("bogus",)}, {"days": 0}, {"days": 9999}, {"name": ""}):
                with pytest.raises(ValueError):
                    api_token_service.create(admin_user, bad.get("name", "x"), list(bad.get("scopes", ("read",))), bad.get("days", 30))
            with pytest.raises(ValueError, match="already has"):
                api_token_service.create(admin_user, row.name, ["read"], 30)
            row2 = AuditLog.query.filter_by(action="create_api_token", target_id=row.id).one()
            assert row2.user_id is None  # created via the service without a request → anonymous row is fine here
            api_token_service.revoke(row)
            db.session.commit()
            assert api_token_service.verify(pt) is None and row.status == "revoked"
            assert AuditLog.query.filter_by(action="revoke_api_token", target_id=row.id).count() == 1
            pt_exp, row_exp = _token(admin_user, ("read",), name="exp")
            row_exp.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
            db.session.commit()
            assert api_token_service.verify(pt_exp) is None and row_exp.status == "expired"

    def test_required_scope_mapping(self, app):
        with app.app_context():
            rs = api_token_service.required_scope
            assert rs("GET", "certificates.list_certs") == "read"
            assert rs("POST", "certificates.create") == "issue" and rs("POST", "csr.sign") == "issue"
            assert rs("POST", "certificates.renew") == "issue"
            assert rs("POST", "certificates.revoke") == "revoke" and rs("POST", "ca.generate_crl") == "revoke"
            assert rs("POST", "ca.create") == "admin" and rs("POST", "users.create_user") == "admin"
            assert rs("GET", "public.download_crl_der") is None and rs("GET", "metrics.metrics") is None


class TestRequests:
    def test_bearer_reads_and_json_errors(self, app, client, admin_user, db):
        with app.app_context():
            _root()
            pt, row = _token(admin_user, ("read",))
            r = client.get("/ca/", headers=_bearer(pt))
            assert r.status_code == 200 and isinstance(r.get_json(), list) and len(r.get_json()) == 1
            db.session.expire_all()
            assert db.session.get(ApiToken, row.id).last_used_at is not None
            assert client.get("/ca/", headers=_bearer("chy_api_nope_bad")).status_code == 401
            assert client.get("/ca/", headers=_bearer("garbage")).status_code == 401
            assert AuditLog.query.filter_by(action="api_token_auth_failed").count() == 2
            # a browser-style request with a bad bearer never gets a redirect to the login page
            r = client.get("/ca/", headers={"Authorization": "Bearer chy_api_x_y"})
            assert r.status_code == 401 and r.is_json

    def test_scopes_are_enforced(self, app, client, admin_user, db):
        with app.app_context():
            root = _root()
            read_only, _ = _token(admin_user, ("read",), name="ro")
            issuer, _ = _token(admin_user, ("read", "issue"), name="iss")
            revoker, _ = _token(admin_user, ("revoke",), name="rev")
            full, _ = _token(admin_user, ("admin",), name="adm")
            data = {"ca_id": str(root.id), "cn": "t.example", "san": "t.example", "key_type": "EC", "key_size": "256", "validity_days": "30"}
            r = client.post("/certificates/create", headers=_bearer(read_only), data=data)
            assert r.status_code == 403 and "'issue' scope" in r.get_json()["error"]
            assert AuditLog.query.filter_by(action="api_token_scope_denied").count() == 1
            r = client.post("/certificates/create", headers=_bearer(issuer), data=data)          # CSRF bypass like Basic Auth
            assert r.status_code == 201, r.data
            cert_id = r.get_json()["id"]
            assert client.post(f"/certificates/{cert_id}/revoke", headers=_bearer(issuer), data={"reason": "superseded"}).status_code == 403
            assert client.get("/ca/", headers=_bearer(revoker)).status_code == 403                   # no read scope
            assert client.post(f"/certificates/{cert_id}/revoke", headers=_bearer(revoker), data={"reason": "superseded"}).status_code == 200
            r = client.post("/ca/create", headers=_bearer(issuer), data={"mode": "generate", "name": "X", "cn": "X", "key_type": "EC",
                                                                         "key_size": "256", "validity_days": "365", "ca_type": "root"})
            assert r.status_code == 403                                                             # admin scope needed
            r = client.post("/ca/create", headers=_bearer(full), data={"mode": "generate", "name": "X", "cn": "X", "key_type": "EC",
                                                                       "key_size": "256", "validity_days": "365", "ca_type": "root"})
            assert r.status_code == 201, r.data
            assert client.get("/ca/", headers=_bearer(full)).status_code == 200                     # admin implies read

    def test_token_never_exceeds_its_owners_role(self, app, client, csr_requester, db):
        with app.app_context():
            pt, _ = _token(csr_requester, ("admin",))
            assert client.get("/csr/", headers=_bearer(pt)).status_code == 200
            assert client.get("/ca/", headers=_bearer(pt)).status_code == 403                       # requester role, not admin
            assert client.get("/users/", headers=_bearer(pt)).status_code == 403

    def test_kinds_are_kept_apart(self, app, client, admin_user, db, monkeypatch):
        with app.app_context():
            monkeypatch.setitem(app.config, "METRICS_ENABLED", True)
            api_pt, _ = _token(admin_user, ("admin",))
            metrics_pt, _ = metrics_token_service.create("scrape", datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1))
            assert client.get("/metrics", headers={"Authorization": f"Bearer {api_pt}"}).status_code == 401
            assert client.get("/metrics", headers={"Authorization": f"Bearer {metrics_pt}"}).status_code == 200
            r = client.get("/ca/", headers=_bearer(metrics_pt))
            assert r.status_code == 401 and "metrics token" in r.get_json()["error"]

    def test_deactivated_owner_and_password_gate(self, app, client, admin_user, db):
        with app.app_context():
            other = User(username="tokenowner", role="admin")
            other.set_password("password-123456")
            db.session.add(other)
            db.session.commit()
            pt, _ = _token(other, ("read",))
            assert client.get("/ca/", headers=_bearer(pt)).status_code == 200
            other.must_change_password = True
            db.session.commit()
            r = client.get("/ca/", headers=_bearer(pt))
            assert r.status_code == 403 and "Password change" in r.get_json()["error"]
            other.must_change_password = False
            other.is_active_user = False
            db.session.commit()
            assert client.get("/ca/", headers=_bearer(pt)).status_code == 401
            with pytest.raises(ValueError, match="deactivated"):
                api_token_service.create(other, "new", ["read"], 30)

    def test_basic_auth_and_sessions_are_not_scope_checked(self, app, client, admin_user, auth_admin, db):
        with app.app_context():
            root = _root()
            creds = base64.b64encode(b"testadmin:adminpass").decode()
            data = {"ca_id": str(root.id), "cn": "b.example", "san": "b.example", "key_type": "EC", "key_size": "256", "validity_days": "30"}
            assert client.post("/certificates/create", headers={"Authorization": f"Basic {creds}"}, data=data).status_code == 201
            assert auth_admin.post("/certificates/create", headers=JSON, data=data).status_code == 201


class TestUiAndCli:
    def test_page_create_and_revoke(self, app, auth_admin, csr_requester, db):
        with app.app_context():
            page = auth_admin.get("/users/api-tokens").get_data(as_text=True)
            assert "Create a token" in page and 'name="scope_issue"' in page
            r = auth_admin.post("/users/api-tokens", data={"name": "ui-token", "expires_in_days": "10", "scope_read": "on", "scope_issue": "on"})
            assert r.status_code == 200 and "chy_api_" in r.get_data(as_text=True) and "will not be shown again" in r.get_data(as_text=True)
            row = ApiToken.query.filter_by(name="ui-token").one()
            assert row.scopes == ["issue", "read"] and row.days_until_expiry in (9, 10)
            # the requester (own session) sees only their own, and cannot revoke the admin's
            requester = app.test_client()
            requester.post("/auth/login", data={"username": "testrequester", "password": "requesterpass"})
            r = requester.post("/users/api-tokens", headers=JSON, data={"name": "req-token", "expires_in_days": "5", "scopes": "read"})
            assert r.status_code == 201 and r.get_json()["token"].startswith("chy_api_")
            mine = requester.get("/users/api-tokens", headers=JSON).get_json()
            assert [t["name"] for t in mine] == ["req-token"]
            assert requester.post(f"/users/api-tokens/{row.id}/revoke", headers=JSON).status_code == 404
            assert auth_admin.get("/users/api-tokens", headers=JSON).get_json().__len__() == 2
            assert auth_admin.post(f"/users/api-tokens/{row.id}/revoke", headers=JSON).get_json()["status"] == "revoked"
            assert auth_admin.post("/users/api-tokens", headers=JSON, data={"name": "bad", "expires_in_days": "9999", "scopes": "read"}).status_code == 400

    def test_cli(self, app, db, admin_user):
        with app.app_context():
            runner = app.test_cli_runner()
            r = runner.invoke(args=["api-token", "create", "--user", "testadmin", "--name", "cli", "--scopes", "read,revoke", "--expires-in-days", "7"])
            assert r.exit_code == 0 and "chy_api_" in r.output, r.output
            pt = [line for line in r.output.splitlines() if line.startswith("chy_api_")][0]
            assert api_token_service.verify(pt) is not None
            r = runner.invoke(args=["api-token", "list", "--user", "testadmin"])
            assert "cli" in r.output and "read,revoke" in r.output
            row = ApiToken.query.filter_by(name="cli").one()
            r = runner.invoke(args=["api-token", "revoke", str(row.id), "--yes"])
            assert r.exit_code == 0 and "Revoked" in r.output
            assert api_token_service.verify(pt) is None
            assert runner.invoke(args=["api-token", "create", "--user", "nobody", "--name", "x", "--expires-in-days", "7"]).exit_code != 0
