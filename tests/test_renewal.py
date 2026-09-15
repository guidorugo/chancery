"""F9: certificate renewal and re-key — service semantics (key reuse vs
re-key, attribute equality, lineage, revoke-old), refusals, dual-control
rules, the HTML/JSON route, and the F10 interplay (superseded certificates
get no expiry reminders)."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from sqlalchemy import inspect as sa_inspect

from app import create_app
from tests.conftest import TestConfig
from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.models.certificate import Certificate
from app.models.user import User
from app.services import (ca_service, cert_service, crl_service, crypto_utils, csr_service,
                          profile_service, scheduler_service, webhook_service)

PASSPHRASE = "test-passphrase"
JSON = {"Accept": "application/json"}
NOW = datetime(2026, 9, 15, 12, 0, 0)


@pytest.fixture(autouse=True)
def _seed_profiles(app, db):
    with app.app_context():
        profile_service.ensure_builtins()


def _root(name="Renew Root", validity_days=3650):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name, "O": "Chancery Tests"}, key_type="RSA", key_size=2048,
        validity_days=validity_days, passphrase=PASSPHRASE)


def _direct(ca, cn="direct.example", days=400, **kw):
    return cert_service.create_certificate(
        ca, {"CN": cn, "O": "Chancery Tests", "OU": "Ops"}, [cn, f"www.{cn}", "IP:10.0.0.9"], days, PASSPHRASE,
        key_usage={"digital_signature": True, "key_encipherment": False, "content_commitment": True,
                   "data_encipherment": False, "key_agreement": False},
        extended_key_usage=["clientAuth", "emailProtection"], ocsp_url="http://pki.example/public/ocsp/1",
        crl_dp_url="http://pki.example/public/crl/1.crl", **kw)


def _from_csr(ca, cn="csr.example", created_by=None, days=200):
    csr_model, _key, _ = csr_service.create_csr({"CN": cn}, [cn], "EC", 256, None, created_by=created_by)
    _db.session.commit()
    return cert_service.sign_csr(csr_model, ca, days, PASSPHRASE, signed_by=created_by)


def _x(cert_model):
    return x509.load_pem_x509_certificate(cert_model.certificate_pem.encode())


def _spki(cert_model):
    return _x(cert_model).public_key().public_bytes(serialization.Encoding.DER,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)


def _ext(cert_model, oid):
    try:
        return _x(cert_model).extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def _renew(old, **kw):
    new = cert_service.renew_certificate(old, PASSPHRASE, **kw)
    _db.session.commit()
    return new


# ---------------------------------------------------------------------------
# service
# ---------------------------------------------------------------------------

class TestService:
    def test_renewal_keeps_identity_and_key_by_default(self, app, db):
        with app.app_context():
            root = _root()
            old = _direct(root)
            new = _renew(old, ocsp_url="http://pki.example/public/ocsp/1", crl_dp_url="http://pki.example/public/crl/1.crl")

            assert new.id != old.id and new.serial_number != old.serial_number
            assert new.renewed_from_id == old.id and old.renewals == [new] and old.superseded_by_id == new.id
            assert new.ca_id == old.ca_id and new.common_name == old.common_name
            assert _x(new).subject == _x(old).subject and _x(new).issuer == _x(old).issuer
            assert _spki(new) == _spki(old)                      # same public key
            assert new.private_key_enc == old.private_key_enc    # escrow carried over verbatim
            assert new.san_json == old.san_json
            assert _ext(new, ExtensionOID.SUBJECT_ALTERNATIVE_NAME) == _ext(old, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            assert _ext(new, ExtensionOID.KEY_USAGE) == _ext(old, ExtensionOID.KEY_USAGE)
            assert _ext(new, ExtensionOID.EXTENDED_KEY_USAGE) == _ext(old, ExtensionOID.EXTENDED_KEY_USAGE)
            assert list(_ext(new, ExtensionOID.EXTENDED_KEY_USAGE)) == [ExtendedKeyUsageOID.CLIENT_AUTH,
                                                                          ExtendedKeyUsageOID.EMAIL_PROTECTION]
            assert _ext(new, ExtensionOID.AUTHORITY_INFORMATION_ACCESS) == _ext(old, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            assert _ext(new, ExtensionOID.CRL_DISTRIBUTION_POINTS) == _ext(old, ExtensionOID.CRL_DISTRIBUTION_POINTS)
            assert new.key_usage_json == old.key_usage_json and new.extended_key_usage_json == old.extended_key_usage_json
            assert new.profile_id == old.profile_id and new.requested_by == old.requested_by
            assert (new.not_after - new.not_before).days == 400      # default = original window
            assert new.not_before >= old.not_before   # same second on a fast machine
            assert new.expiry_notified_at is None and not new.is_revoked and not old.is_revoked
            assert _x(new).signature != _x(old).signature
            # the successor's chain still validates against the CA
            _x(new).verify_directly_issued_by(_x(root))

    def test_rekey_generates_a_fresh_escrowed_key(self, app, db):
        with app.app_context():
            root = _root()
            old = _direct(root)
            new = _renew(old, rekey=True, validity_days=30)
            assert _spki(new) != _spki(old)
            assert new.private_key_enc and new.private_key_enc != old.private_key_enc
            key = crypto_utils.decrypt_private_key(new.private_key_enc, PASSPHRASE)
            assert key.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo) == _spki(new)
            assert (new.key_type, new.key_size) == (old.key_type, old.key_size)
            assert (new.not_after - new.not_before).days == 30

    def test_csr_lineage_reuses_the_owners_key_and_cannot_rekey(self, app, db, admin_user):
        with app.app_context():
            root = _root()
            old = _from_csr(root, created_by=admin_user.id)
            assert old.private_key_enc is None
            new = _renew(old)
            assert _spki(new) == _spki(old) and new.private_key_enc is None
            assert new.key_type == "EC" and new.requested_by == admin_user.id
            assert old.csr and new.csr == []                          # the CSR keeps pointing at the first issuance
            with pytest.raises(ValueError, match="new CSR"):
                cert_service.renew_certificate(new, PASSPHRASE, rekey=True)

    def test_revoke_old_supersedes_on_the_crl(self, app, db):
        with app.app_context():
            root = _root()
            old = _direct(root)
            new = _renew(old, revoke_old=True)
            db.session.expire_all()
            old = db.session.get(Certificate, old.id)
            assert old.is_revoked and old.revocation_reason == "superseded"
            assert not db.session.get(Certificate, new.id).is_revoked
            crl_service.refresh_crl(root, PASSPHRASE)
            crl = x509.load_pem_x509_crl(root.crl_pem.encode())
            entry = crl.get_revoked_certificate_by_serial_number(int(old.serial_number, 16))
            assert entry is not None
            assert entry.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.superseded
            assert crl.get_revoked_certificate_by_serial_number(int(new.serial_number, 16)) is None

    def test_chain_of_renewals_and_force(self, app, db):
        with app.app_context():
            root = _root()
            a = _direct(root)
            b = _renew(a)
            c = _renew(b)
            assert c.renewed_from.renewed_from is a and a.renewals == [b] and b.renewals == [c]
            with pytest.raises(cert_service.AlreadyRenewed, match=f"#{b.id}"):
                cert_service.renew_certificate(a, PASSPHRASE)
            db.session.rollback()
            d = _renew(a, force=True)
            assert d.renewed_from_id == a.id and [r.id for r in a.renewals] == [b.id, d.id]
            assert a.superseded_by_id == d.id

    def test_refusals(self, app, db, monkeypatch):
        with app.app_context():
            root = _root()
            cert = _direct(root)
            # revoked certificate: only with a new key
            crl_service.revoke_certificate(cert.id, "key_compromise", passphrase=PASSPHRASE)
            with pytest.raises(ValueError, match="revoked certificate"):
                cert_service.renew_certificate(cert, PASSPHRASE)
            db.session.rollback()
            renewed = _renew(cert, rekey=True)
            assert _spki(renewed) != _spki(cert)
            # key policy tightened since issuance
            other = _direct(root, cn="weak.example")
            monkeypatch.setitem(app.config, "MIN_RSA_KEY_SIZE", 4096)
            with pytest.raises(ValueError, match="too weak"):
                cert_service.renew_certificate(other, PASSPHRASE)
            db.session.rollback()
            monkeypatch.setitem(app.config, "MIN_RSA_KEY_SIZE", 2048)
            # disabled profile
            client_auth = profile_service.lookup("client_auth")
            prof_cert = cert_service.create_certificate(root, {"CN": "p.example"}, ["p.example"], 100, PASSPHRASE,
                                                        profile=client_auth)
            client_auth.enabled = False
            db.session.commit()
            with pytest.raises(ValueError, match="disabled"):
                cert_service.renew_certificate(prof_cert, PASSPHRASE)
            db.session.rollback()
            client_auth.enabled = True
            db.session.commit()
            # pending / revoked / expired CA
            pending = _root("Pending")
            pcert = _direct(pending, cn="pending.example")
            pending.approval_status = "pending"
            db.session.commit()
            with pytest.raises(ValueError, match="approval"):
                cert_service.renew_certificate(pcert, PASSPHRASE)
            db.session.rollback()
            gone = _root("Gone")
            gcert = _direct(gone, cn="gone.example")
            crl_service.revoke_ca(gone.id, "cessation_of_operation", passphrase=PASSPHRASE)
            with pytest.raises(ValueError, match="CA is revoked"):
                cert_service.renew_certificate(gcert, PASSPHRASE)
            db.session.rollback()
            expired = _root("Expired")
            ecert = _direct(expired, cn="expired.example")
            expired.not_after = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
            db.session.commit()
            with pytest.raises(ValueError, match="expired"):
                cert_service.renew_certificate(ecert, PASSPHRASE)
            db.session.rollback()

    def test_profile_is_re_enforced_and_default_validity_clamped(self, app, db):
        with app.app_context():
            root = _root()
            web = profile_service.lookup("web_server")
            cert = cert_service.create_certificate(root, {"CN": "site.example"}, ["site.example"], 300, PASSPHRASE,
                                                   profile=web)
            web.max_validity_days = 90
            db.session.commit()
            new = _renew(cert)                                   # default window 300 → clamped to 90
            assert (new.not_after - new.not_before).days == 90 and new.profile_id == web.id
            with pytest.raises(ValueError, match="at most 90"):
                cert_service.renew_certificate(cert, PASSPHRASE, validity_days=120, force=True)
            db.session.rollback()
            web.max_validity_days = None
            db.session.commit()


# ---------------------------------------------------------------------------
# route (HTML + JSON) and surface
# ---------------------------------------------------------------------------

class TestRoute:
    def test_json_renew_returns_201_and_audits(self, app, auth_admin, admin_user, db):
        with app.app_context():
            root = _root()
            old = _direct(root)
            r = auth_admin.post(f"/certificates/{old.id}/renew", headers=JSON,
                                data={"validity_days": "45", "revoke_old": "on"})
            assert r.status_code == 201, r.data
            body = r.get_json()
            assert body["renewed_from_id"] == old.id and body["old_id"] == old.id
            assert body["superseded_by_id"] is None and body["issued_by"] == admin_user.id
            assert body["expiry_notified_at"] is None and "warning" not in body
            row = AuditLog.query.filter_by(action="renew_certificate").one()
            details = json.loads(row.details)
            assert details == {"old_id": old.id, "new_id": body["id"], "rekey": False, "revoked_old": True,
                               "validity_days": 45, "profile": None}      # service-created, no profile
            assert row.target_id == body["id"] and row.user_id == admin_user.id
            old_body = auth_admin.get(f"/certificates/{old.id}", headers=JSON).get_json()
            assert old_body["is_revoked"] is True and old_body["superseded_by_id"] == body["id"]
            # a second renewal without force is a conflict
            r = auth_admin.post(f"/certificates/{old.id}/renew", headers=JSON, data={"rekey": "on"})
            assert r.status_code == 409
            r = auth_admin.post(f"/certificates/{old.id}/renew", headers=JSON, data={"rekey": "on", "force": "1"})
            assert r.status_code == 201

    def test_json_errors(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            old = _from_csr(root)
            assert auth_admin.post(f"/certificates/{old.id}/renew", headers=JSON, data={"rekey": "on"}).status_code == 400
            assert auth_admin.post(f"/certificates/{old.id}/renew", headers=JSON, data={"validity_days": "x"}).status_code == 400
            assert auth_admin.post(f"/certificates/{old.id}/renew", headers=JSON, data={"validity_days": "0"}).status_code == 400
            assert auth_admin.post("/certificates/999999/renew", headers=JSON).status_code == 404

    def test_html_form_and_flow(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            old = _direct(root)
            page = auth_admin.get(f"/certificates/{old.id}/renew")
            assert page.status_code == 200
            assert b'name="validity_days"' in page.data and b'value="400"' in page.data
            assert b'name="rekey"' in page.data and b'name="revoke_old"' in page.data and b'name="force"' not in page.data
            r = auth_admin.post(f"/certificates/{old.id}/renew", data={"validity_days": "60"})
            assert r.status_code == 302
            new_id = int(r.headers["Location"].rstrip("/").rsplit("/", 1)[1])
            assert new_id != old.id
            detail = auth_admin.get(f"/certificates/{new_id}").data
            assert b"Renewed From" in detail and f"#{old.id}".encode() in detail
            old_detail = auth_admin.get(f"/certificates/{old.id}").data
            assert b"Superseded By" in old_detail and b">Superseded<" in old_detail
            listing = auth_admin.get("/certificates/").data
            assert b">Superseded<" in listing and listing.count(b"/renew") == 1   # only the successor offers Renew
            page = auth_admin.get(f"/certificates/{old.id}/renew").data
            assert b'name="force"' in page and b"already renewed" in page
            csr_cert = _from_csr(root)
            page = auth_admin.get(f"/certificates/{csr_cert.id}/renew").data
            assert b'name="rekey"' not in page and b"issued from a CSR" in page

    def test_requester_cannot_renew(self, app, client, csr_requester, db):
        with app.app_context():
            root = _root()
            old = _from_csr(root, created_by=csr_requester.id)
            client.post("/auth/login", data={"username": "testrequester", "password": "requesterpass"})
            r = client.post(f"/certificates/{old.id}/renew", headers=JSON)
            assert r.status_code == 403
            assert Certificate.query.count() == 1

    def test_catalog_lists_the_event_and_webhook_sees_it(self, app, auth_admin, db, monkeypatch):
        with app.app_context():
            assert "renew_certificate" in dict(webhook_service.EVENT_CATALOG["Certificates"])
            seen = []
            monkeypatch.setattr(webhook_service, "notify", lambda action, **kw: seen.append(action))
            root = _root()
            old = _direct(root)
            assert auth_admin.post(f"/certificates/{old.id}/renew", headers=JSON).status_code == 201
            assert "renew_certificate" in seen

    def test_migration_and_json_shape(self, app, auth_admin, db):
        with app.app_context():
            from app import _migrate_schema
            _migrate_schema()
            insp = sa_inspect(_db.engine)
            assert "renewed_from_id" in {c["name"] for c in insp.get_columns("certificates")}
            root = _root()
            cert = _direct(root)
            body = auth_admin.get(f"/certificates/{cert.id}", headers=JSON).get_json()
            assert body["renewed_from_id"] is None and body["superseded_by_id"] is None


# ---------------------------------------------------------------------------
# F10 interplay: reminders move to the successor
# ---------------------------------------------------------------------------

class TestExpiryEvents:
    def test_superseded_certificate_gets_no_reminder(self, app, db):
        with app.app_context():
            scheduler_service._state.update({"lease_held": False, "last_tick": None, "last_summary": None})
            root = _root()
            old = _direct(root)
            old.not_after = NOW + timedelta(days=3)
            db.session.commit()
            new = _renew(old, validity_days=365)
            job = scheduler_service.tick(now=NOW, force=True)["jobs"]["expiry_events"]
            assert old.id not in job["certificate_expiring"] and new.id not in job["certificate_expiring"]
            assert AuditLog.query.filter_by(action="certificate_expiring", target_id=old.id).count() == 0
            # the successor is reported on its own schedule
            new.not_after = NOW + timedelta(days=2)
            db.session.commit()
            job = scheduler_service.tick(now=NOW, force=True)["jobs"]["expiry_events"]
            assert job["certificate_expiring"] == [new.id]


# ---------------------------------------------------------------------------
# dual control
# ---------------------------------------------------------------------------

class DualControlConfig(TestConfig):
    DUAL_CONTROL_ENABLED = True


@pytest.fixture(scope="module")
def dc_app():
    return create_app(DualControlConfig)


@pytest.fixture
def dc_db(dc_app):
    with dc_app.app_context():
        _db.drop_all()
        _db.create_all()
        profile_service.ensure_builtins()
        yield _db
        _db.session.remove()


def _user(username, role="admin"):
    u = User(username=username, role=role)
    u.set_password("password-123456")
    _db.session.add(u)
    _db.session.commit()
    return u


def _login(dc_app, username):
    c = dc_app.test_client()
    c.post("/auth/login", data={"username": username, "password": "password-123456"})
    return c


class TestDualControl:
    def test_escrowed_key_renewal_is_direct_creation(self, dc_app, dc_db):
        with dc_app.app_context():
            _user("admin")                    # the exempt bootstrap account
            _user("alice"); _user("bob")      # multi-user → mode active
            root = _root()
            old = _direct(root)
            alice = _login(dc_app, "alice")
            r = alice.post(f"/certificates/{old.id}/renew", headers=JSON)
            assert r.status_code == 403 and "direct creation" in r.get_json()["error"]
            boot = _login(dc_app, "admin")
            assert boot.post(f"/certificates/{old.id}/renew", headers=JSON).status_code == 201

    def test_csr_lineage_renewal_needs_a_different_admin(self, dc_app, dc_db):
        with dc_app.app_context():
            _user("admin")
            alice = _user("alice"); _user("bob")
            root = _root()
            old = _from_csr(root, created_by=alice.id)
            r = _login(dc_app, "alice").post(f"/certificates/{old.id}/renew", headers=JSON)
            assert r.status_code == 403 and "different admin" in r.get_json()["error"]
            r = _login(dc_app, "bob").post(f"/certificates/{old.id}/renew", headers=JSON)
            assert r.status_code == 201 and r.get_json()["requested_by"] == alice.id
