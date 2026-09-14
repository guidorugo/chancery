"""F15: search, filter and pagination on the certificate, CSR and CA lists,
for both the HTML pages and the JSON API (bare array kept for unpaginated
JSON, envelope when `page`/`per_page` is given)."""
from datetime import datetime, timedelta, timezone

import pytest

from app.extensions import db as _db
from app.models.certificate import Certificate
from app.services import ca_service, cert_service, crl_service, csr_service, profile_service

JSON = {"Accept": "application/json"}
PASSPHRASE = "test-passphrase"


@pytest.fixture(autouse=True)
def _seed_profiles(app, db):
    with app.app_context():
        profile_service.ensure_builtins()


def _root(name="List Root"):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name}, key_type="RSA", key_size=2048,
        validity_days=3650, passphrase=PASSPHRASE)


def _cert(ca, cn, sans=None, profile=None, requested_by=None, days=365):
    # 365 days: well outside CERT_EXPIRY_WARNING_DAYS, so a fresh cert is "active", not "expiring".
    cert = cert_service.create_certificate(ca, {"CN": cn}, sans if sans is not None else [cn], days,
                                           PASSPHRASE, profile=profile)
    if requested_by is not None:
        cert.requested_by = requested_by
        _db.session.commit()
    return cert


def _csr(cn, created_by=None, profile_id=None, sans=None):
    csr_model, _k, _ = csr_service.create_csr({"CN": cn}, sans if sans is not None else [cn], "RSA", 2048,
                                              None, created_by=created_by, profile_id=profile_id)
    _db.session.commit()
    return csr_model


def _set_not_after(cert, days_from_now):
    cert.not_after = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=days_from_now)
    _db.session.commit()


# ---------------------------------------------------------------------------
# JSON shape
# ---------------------------------------------------------------------------

class TestJsonShape:
    def test_unpaginated_json_stays_a_bare_array(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            for i in range(3):
                _cert(root, f"h{i}.example")
            body = auth_admin.get("/certificates/", headers=JSON).get_json()
            assert isinstance(body, list) and len(body) == 3

    def test_page_parameter_returns_an_envelope(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            for i in range(5):
                _cert(root, f"h{i}.example")
            r = auth_admin.get("/certificates/?page=2&per_page=2", headers=JSON)
            body = r.get_json()
            assert set(body) == {"items", "page", "per_page", "total", "pages"}
            assert body["page"] == 2 and body["per_page"] == 2
            assert body["total"] == 5 and body["pages"] == 3
            assert len(body["items"]) == 2
            last = auth_admin.get("/certificates/?page=3&per_page=2", headers=JSON).get_json()
            assert len(last["items"]) == 1
            beyond = auth_admin.get("/certificates/?page=9&per_page=2", headers=JSON).get_json()
            assert beyond["items"] == [] and beyond["total"] == 5

    def test_per_page_is_clamped_and_bad_numbers_fall_back(self, app, auth_admin, db):
        with app.app_context():
            _root()
            body = auth_admin.get("/certificates/?per_page=100000", headers=JSON).get_json()
            assert body["per_page"] == 500
            body = auth_admin.get("/certificates/?page=abc&per_page=zzz", headers=JSON).get_json()
            assert body["page"] == 1 and body["per_page"] == 50

    def test_filter_alone_keeps_the_bare_array(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            _cert(root, "a.example")
            _cert(root, "b.example")
            body = auth_admin.get("/certificates/?q=a.example", headers=JSON).get_json()
            assert isinstance(body, list) and [c["common_name"] for c in body] == ["a.example"]


# ---------------------------------------------------------------------------
# certificate filters
# ---------------------------------------------------------------------------

class TestCertificateFilters:
    def test_q_matches_cn_serial_and_san(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            a = _cert(root, "alpha.example", ["alpha.example", "IP:10.1.2.3"])
            _cert(root, "beta.example")
            by_cn = auth_admin.get("/certificates/?q=ALPHA", headers=JSON).get_json()
            assert [c["id"] for c in by_cn] == [a.id]
            by_serial = auth_admin.get(f"/certificates/?q={a.serial_number[:12]}", headers=JSON).get_json()
            assert [c["id"] for c in by_serial] == [a.id]
            by_san = auth_admin.get("/certificates/?q=10.1.2.3", headers=JSON).get_json()
            assert [c["id"] for c in by_san] == [a.id]

    def test_like_metacharacters_are_literal(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            _cert(root, "under_score.example")
            _cert(root, "underXscore.example")
            body = auth_admin.get("/certificates/?q=under_score", headers=JSON).get_json()
            assert [c["common_name"] for c in body] == ["under_score.example"]

    def test_status_filters(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            active = _cert(root, "active.example")
            revoked = _cert(root, "revoked.example")
            crl_service.revoke_certificate(revoked.id, "superseded", passphrase=PASSPHRASE)
            expiring = _cert(root, "expiring.example")
            _set_not_after(expiring, 5)
            expired = _cert(root, "expired.example")
            _set_not_after(expired, -1)

            def ids(status):
                return sorted(c["id"] for c in auth_admin.get(f"/certificates/?status={status}",
                                                              headers=JSON).get_json())
            assert ids("revoked") == [revoked.id]
            assert ids("expired") == [expired.id]
            assert ids("expiring") == [expiring.id]
            assert ids("active") == sorted([active.id, expiring.id])

    def test_ca_and_profile_filters(self, app, auth_admin, db):
        with app.app_context():
            r1, r2 = _root("R1"), _root("R2")
            client = profile_service.lookup("client_auth")
            c1 = _cert(r1, "one.example", profile=client)
            c2 = _cert(r2, "two.example")
            assert [c["id"] for c in auth_admin.get(f"/certificates/?ca_id={r2.id}", headers=JSON).get_json()] == [c2.id]
            assert [c["id"] for c in auth_admin.get("/certificates/?profile=client_auth", headers=JSON).get_json()] == [c1.id]
            assert [c["id"] for c in auth_admin.get(f"/certificates/?profile={client.id}", headers=JSON).get_json()] == [c1.id]

    def test_unknown_filter_values_are_400(self, app, auth_admin, db):
        with app.app_context():
            _root()
            assert auth_admin.get("/certificates/?status=bogus", headers=JSON).status_code == 400
            assert auth_admin.get("/certificates/?ca_id=abc", headers=JSON).status_code == 400
            assert auth_admin.get("/certificates/?profile=nope", headers=JSON).status_code == 400
            r = auth_admin.get("/certificates/?status=bogus")  # HTML: flash + redirect to the plain list
            assert r.status_code == 302 and r.headers["Location"].endswith("/certificates/")

    def test_requester_scoping_survives_filters(self, app, client, admin_user, csr_requester, db):
        with app.app_context():
            root = _root()
            mine = _cert(root, "mine.example", requested_by=csr_requester.id)
            _cert(root, "theirs.example", requested_by=admin_user.id)
            client.post("/auth/login", data={"username": "testrequester", "password": "requesterpass"})
            body = client.get("/certificates/?q=example&status=active", headers=JSON).get_json()
            assert [c["id"] for c in body] == [mine.id]
            body = client.get("/certificates/?q=theirs", headers=JSON).get_json()
            assert body == []


# ---------------------------------------------------------------------------
# CSR and CA filters
# ---------------------------------------------------------------------------

class TestCsrFilters:
    def test_status_q_and_profile(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            email = profile_service.lookup("email")
            pending = _csr("pending.example", profile_id=email.id)
            signed = _csr("signed.example")
            cert_service.sign_csr(signed, root, 30, PASSPHRASE)
            rejected = _csr("rejected.example")
            rejected.status = "rejected"
            db.session.commit()

            def ids(query):
                return sorted(c["id"] for c in auth_admin.get(f"/csr/?{query}", headers=JSON).get_json())
            assert ids("status=pending") == [pending.id]
            assert ids("status=approved") == [signed.id]
            assert ids("status=rejected") == [rejected.id]
            assert ids("q=signed") == [signed.id]
            assert ids("profile=email") == [pending.id]
            assert ids(f"ca_id={root.id}") == [signed.id]
            assert auth_admin.get("/csr/?status=signing", headers=JSON).status_code == 400

    def test_requester_sees_only_own_csrs_with_filters(self, app, client, admin_user, csr_requester, db):
        with app.app_context():
            mine = _csr("mine.example", created_by=csr_requester.id)
            _csr("theirs.example", created_by=admin_user.id)
            client.post("/auth/login", data={"username": "testrequester", "password": "requesterpass"})
            body = client.get("/csr/?status=pending", headers=JSON).get_json()
            assert [c["id"] for c in body] == [mine.id]


class TestCaFilters:
    def test_status_type_backend_and_q(self, app, auth_admin, db):
        with app.app_context():
            root = _root("Alpha Root")
            inter = ca_service.create_intermediate_ca(
                name="Alpha Inter", parent_ca=root, subject_attrs={"CN": "Alpha Inter"},
                key_type="RSA", key_size=2048, validity_days=365, passphrase=PASSPHRASE)
            revoked = _root("Gone Root")
            crl_service.revoke_ca(revoked.id, "cessation_of_operation", passphrase=PASSPHRASE)

            def ids(query):
                return sorted(c["id"] for c in auth_admin.get(f"/ca/?{query}", headers=JSON).get_json())
            assert ids("status=revoked") == [revoked.id]
            assert ids("status=active") == sorted([root.id, inter.id])
            assert ids("type=intermediate") == [inter.id]
            assert ids("type=root") == sorted([root.id, revoked.id])
            assert ids("backend=software") == sorted([root.id, inter.id, revoked.id])
            assert ids("backend=softhsm") == []
            assert ids("q=alpha") == sorted([root.id, inter.id])
            assert auth_admin.get("/ca/?type=leaf", headers=JSON).status_code == 400


# ---------------------------------------------------------------------------
# HTML pages
# ---------------------------------------------------------------------------

class TestHtml:
    def test_filter_bar_and_pager_render(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            for i in range(3):
                _cert(root, f"h{i}.example")
            r = auth_admin.get("/certificates/?per_page=2&q=example")
            assert r.status_code == 200
            assert b'id="cert-filters"' in r.data
            assert b"Page 1 of 2" in r.data
            assert b'value="example"' in r.data          # search box keeps the query
            assert b"Clear" in r.data
            r2 = auth_admin.get("/certificates/?per_page=2&q=example&page=2")
            assert b"Page 2 of 2" in r2.data
            for path in ("/csr/", "/ca/"):
                page = auth_admin.get(path)
                assert page.status_code == 200 and b"Filter" in page.data

    def test_dashboard_cards_link_to_filtered_lists(self, app, auth_admin, db):
        with app.app_context():
            _root()
            r = auth_admin.get("/")
            assert b'href="/certificates/?status=expiring"' in r.data
            assert b'href="/certificates/?status=revoked"' in r.data
            assert b'href="/csr/?status=pending"' in r.data
            assert b'href="/ca/?status=active"' in r.data
