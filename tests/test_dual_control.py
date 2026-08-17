"""Dual-control mode (2.10.0, DUAL_CONTROL_ENABLED).

The shared fixtures pin the flag off (conftest ``DUAL_CONTROL_ENABLED =
False``), so this module builds its own app with it enabled. The mode only
bites while the instance is multi-user, so each test seeds exactly the users
its scenario needs (the ``dc_db`` fixture starts from an empty users table).
"""

import pytest
from flask import g

from app import create_app
from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.models.user import User
from app.services import (ca_service, cert_service, crl_service, csr_service,
                          dual_control_service, ocsp_service)
import ldap3

from tests.conftest import TestConfig
from tests.test_ca_import import _key_pem, _pem, _self_signed_ca
from tests.test_ldap import BASE_LDAP_CONFIG, _ldap_down

PASS = "test-passphrase"


class DualControlConfig(TestConfig):
    DUAL_CONTROL_ENABLED = True


@pytest.fixture(scope="module")
def dc_app():
    return create_app(DualControlConfig)


@pytest.fixture
def dc_db(dc_app):
    with dc_app.app_context():
        # Drop first: create_app seeded the bootstrap admin (in-memory SQLite
        # persists across the module), and each scenario builds its own users.
        _db.drop_all()
        _db.create_all()
        yield _db
        _db.session.rollback()
        _db.drop_all()


def _mk_user(username, role="admin", password="pw-123456789"):
    user = User(username=username, role=role)
    user.set_password(password)
    _db.session.add(user)
    _db.session.commit()
    return user


def _login(client, username, password="pw-123456789"):
    client.post("/auth/login", data={"username": username, "password": password})
    return client


def _mk_ca(name, **kwargs):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name}, key_type="EC", key_size=256,
        validity_days=3650, passphrase=PASS, **kwargs)


def _mk_csr(created_by, cn="dc.example.com"):
    csr_model, _, _ = csr_service.create_csr(
        subject_attrs={"CN": cn}, san_list=[cn], key_type="RSA",
        key_size=2048, created_by=created_by)
    return csr_model


JSON = {"Accept": "application/json"}


# --- Activation condition ---------------------------------------------------

class TestActivation:
    def test_flag_off_is_inactive_even_multiuser(self, app, db, admin_user,
                                                 csr_requester):
        with app.test_request_context():
            assert dual_control_service.is_active() is False

    def test_inactive_with_only_bootstrap_admin(self, dc_app, dc_db):
        with dc_app.test_request_context():
            _mk_user("admin")
            assert dual_control_service.is_active() is False

    def test_active_with_second_active_user(self, dc_app, dc_db):
        with dc_app.test_request_context():
            _mk_user("admin")
            _mk_user("alice")
            assert dual_control_service.is_active() is True

    def test_inactive_when_second_user_deactivated(self, dc_app, dc_db):
        with dc_app.app_context():
            _mk_user("admin")
            alice = _mk_user("alice")
            alice.is_active_user = False
            _db.session.commit()
        with dc_app.test_request_context():
            assert dual_control_service.is_active() is False

    def test_active_with_ldap_enabled(self, dc_app, dc_db):
        with dc_app.test_request_context():
            _mk_user("admin")
            g._ldap_cfg_override = {"LDAP_ENABLED": True}
            assert dual_control_service.is_active() is True

    def test_exempt_is_the_literal_admin_account(self, dc_app, dc_db):
        with dc_app.test_request_context():
            bootstrap = _mk_user("admin")
            alice = _mk_user("alice")
            assert dual_control_service.is_exempt(bootstrap) is True
            assert dual_control_service.is_exempt(alice) is False


# --- Direct certificate creation --------------------------------------------

class TestDirectCreateDisabled:
    def test_refused_html_and_json(self, dc_app, dc_db):
        with dc_app.app_context():
            _mk_user("alice")
            _mk_user("bob")
        with dc_app.test_client() as c:
            _login(c, "alice")
            resp = c.get("/certificates/create")
            assert resp.status_code == 302
            assert "/csr/create" in resp.headers["Location"]
            follow = c.get(resp.headers["Location"])
            assert b"direct certificate creation is disabled" in follow.data

            resp = c.post("/certificates/create", data={"cn": "x"})
            assert resp.status_code == 302

            resp = c.get("/certificates/create", headers=JSON)
            assert resp.status_code == 403
            assert "error" in resp.get_json()

    def test_allowed_while_single_user(self, dc_app, dc_db):
        with dc_app.app_context():
            _mk_user("admin")
        with dc_app.test_client() as c:
            _login(c, "admin")
            assert c.get("/certificates/create").status_code == 200

    def test_entry_buttons_hidden(self, dc_app, dc_db):
        with dc_app.app_context():
            _mk_user("alice")
            _mk_user("bob")
            ca = _mk_ca("DC Button CA")
            ca_id = ca.id
        with dc_app.test_client() as c:
            _login(c, "alice")
            assert b"Create Certificate" not in c.get("/certificates/").data
            assert b"Create Cert" not in c.get("/").data
            assert b"Issue Certificate" not in c.get(f"/ca/{ca_id}").data

    def test_bootstrap_admin_may_create_directly(self, dc_app, dc_db):
        # Break-glass: if LDAP breaks (its being enabled alone keeps the mode
        # active) the bootstrap account may be the only usable login — it must
        # keep the one-step form, not just the CSR-and-self-sign path.
        with dc_app.app_context():
            _mk_user("admin")
            _mk_user("bob")
            ca = _mk_ca("DC Breakglass CA")
            ca_id = ca.id
        with dc_app.test_client() as c:
            _login(c, "admin")
            assert c.get("/certificates/create").status_code == 200
            assert b"Create Certificate" in c.get("/certificates/").data
            assert b"Create Cert" in c.get("/").data
            assert b"Issue Certificate" in c.get(f"/ca/{ca_id}").data

    def test_ldap_outage_admin_keeps_direct_create(self, dc_app, dc_db,
                                                   monkeypatch):
        # The full break-glass story end to end: LDAP being enabled alone
        # keeps dual control active, the directory is unreachable, and the
        # bootstrap admin — the only local account — must still log in
        # (local DB is checked before LDAP) and issue in one step.
        for key, value in BASE_LDAP_CONFIG.items():
            monkeypatch.setitem(dc_app.config, key, value)
        monkeypatch.setattr(ldap3, "Connection", _ldap_down)
        with dc_app.app_context():
            _mk_user("admin")
        with dc_app.test_client() as c:
            _login(c, "admin")
            with dc_app.test_request_context():
                assert dual_control_service.is_active() is True
            assert c.get("/certificates/create").status_code == 200


# --- CSR self-approval -------------------------------------------------------

class TestCsrSelfSign:
    def test_creator_blocked_other_admin_allowed(self, dc_app, dc_db):
        with dc_app.app_context():
            alice = _mk_user("alice")
            bob = _mk_user("bob")
            ca = _mk_ca("DC Sign CA")
            csr_model = _mk_csr(created_by=alice.id)
            ids = (csr_model.id, ca.id, alice.id, bob.id)
        csr_id, ca_id, alice_id, bob_id = ids

        with dc_app.test_client() as c:
            _login(c, "alice")
            resp = c.get(f"/csr/{csr_id}/sign")
            assert resp.status_code == 302
            assert f"/csr/{csr_id}" in resp.headers["Location"]
            resp = c.post(f"/csr/{csr_id}/sign",
                          data={"ca_id": str(ca_id), "validity_days": "365"})
            assert resp.status_code == 302
            resp = c.get(f"/csr/{csr_id}/sign", headers=JSON)
            assert resp.status_code == 403
            assert "different admin" in resp.get_json()["error"]

        with dc_app.test_client() as c:
            _login(c, "bob")
            resp = c.post(f"/csr/{csr_id}/sign",
                          data={"ca_id": str(ca_id), "validity_days": "365"},
                          headers=JSON)
            assert resp.status_code == 201
        with dc_app.app_context():
            from app.models.csr import CertificateSigningRequest
            csr_row = _db.session.get(CertificateSigningRequest, csr_id)
            assert csr_row.status == "approved"
            assert csr_row.signed_by == bob_id

    def test_bootstrap_admin_may_self_sign(self, dc_app, dc_db):
        with dc_app.app_context():
            admin = _mk_user("admin")
            _mk_user("alice")
            ca = _mk_ca("DC Exempt CA")
            csr_model = _mk_csr(created_by=admin.id, cn="exempt.example.com")
            csr_id, ca_id = csr_model.id, ca.id
        with dc_app.test_client() as c:
            _login(c, "admin")
            resp = c.post(f"/csr/{csr_id}/sign",
                          data={"ca_id": str(ca_id), "validity_days": "365"},
                          headers=JSON)
            assert resp.status_code == 201

    def test_self_reject_still_allowed(self, dc_app, dc_db):
        with dc_app.app_context():
            alice = _mk_user("alice")
            _mk_user("bob")
            csr_model = _mk_csr(created_by=alice.id, cn="reject.example.com")
            csr_id = csr_model.id
        with dc_app.test_client() as c:
            _login(c, "alice")
            resp = c.post(f"/csr/{csr_id}/reject")
            assert resp.status_code == 302
        with dc_app.app_context():
            from app.models.csr import CertificateSigningRequest
            assert _db.session.get(CertificateSigningRequest, csr_id).status == "rejected"


# --- CA approval lifecycle ---------------------------------------------------

class TestCaApproval:
    def _pending_ca(self, dc_app, client_user="alice"):
        """Create a root CA through the route as client_user; returns its id."""
        with dc_app.test_client() as c:
            _login(c, client_user)
            resp = c.post("/ca/create", headers=JSON, data={
                "mode": "generate", "name": f"Pending CA {client_user}",
                "cn": "Pending CA", "key_type": "EC", "key_size": "256",
                "validity_days": "365", "ca_type": "root",
            })
            assert resp.status_code == 201
            body = resp.get_json()
            assert body["approval_status"] == "pending"
            return body["id"]

    def test_created_pending_and_cannot_sign(self, dc_app, dc_db):
        with dc_app.app_context():
            _mk_user("alice")
            _mk_user("bob")
        ca_id = self._pending_ca(dc_app)
        with dc_app.app_context():
            ca = _db.session.get(CertificateAuthority, ca_id)
            assert ca.crl_pem is None            # initial CRL deferred
            assert ca.id not in [c.id for c in CertificateAuthority.signing_capable()]
            with pytest.raises(ValueError, match="dual-control approval"):
                cert_service.create_certificate(
                    ca, {"CN": "leaf.example.com"}, ["leaf.example.com"], 365, PASS)
            with pytest.raises(ValueError, match="dual-control approval"):
                crl_service.generate_crl(ca, PASS)
            with pytest.raises(ValueError, match="dual-control approval"):
                ca_service.create_intermediate_ca(
                    "DC Child", ca, {"CN": "DC Child"}, "EC", 256, 365, PASS)
            # Public OCSP endpoint must answer UNAUTHORIZED, not raise.
            der = ocsp_service.build_ocsp_response(b"\x30\x03\x02\x01\x00", ca, PASS)
            assert isinstance(der, bytes) and der

    def test_creator_blocked_second_admin_approves(self, dc_app, dc_db):
        with dc_app.app_context():
            alice = _mk_user("alice")
            bob = _mk_user("bob")
            alice_id, bob_id = alice.id, bob.id
        ca_id = self._pending_ca(dc_app)

        with dc_app.test_client() as c:
            _login(c, "alice")
            resp = c.post(f"/ca/{ca_id}/approve", headers=JSON)
            assert resp.status_code == 403
        with dc_app.app_context():
            assert _db.session.get(CertificateAuthority, ca_id).approval_status == "pending"

        with dc_app.test_client() as c:
            _login(c, "bob")
            resp = c.post(f"/ca/{ca_id}/approve", headers=JSON)
            assert resp.status_code == 200
            assert resp.get_json()["approval_status"] == "approved"
        with dc_app.app_context():
            ca = _db.session.get(CertificateAuthority, ca_id)
            assert ca.approved_by == bob_id
            assert ca.approved_at is not None
            assert ca.crl_pem is not None        # deferred initial CRL published
            assert AuditLog.query.filter_by(action="approve_ca").count() == 1

    def test_bootstrap_admin_may_approve_own(self, dc_app, dc_db):
        with dc_app.app_context():
            _mk_user("admin")
            _mk_user("alice")
        ca_id = self._pending_ca(dc_app, client_user="admin")
        with dc_app.test_client() as c:
            _login(c, "admin")
            assert c.post(f"/ca/{ca_id}/approve", headers=JSON).status_code == 200

    def test_approve_non_pending_409(self, dc_app, dc_db):
        with dc_app.app_context():
            _mk_user("alice")
            _mk_user("bob")
            ca = _mk_ca("Already Approved CA")
            ca_id = ca.id
        with dc_app.test_client() as c:
            _login(c, "bob")
            assert c.post(f"/ca/{ca_id}/approve", headers=JSON).status_code == 409

    def test_approve_when_inactive_by_creator(self, app, db, admin_user):
        # Flag off (shared app): a leftover pending CA may be approved by
        # anyone, including its creator.
        with app.app_context():
            ca = _mk_ca("Leftover Pending CA", created_by=admin_user.id,
                        approval_status="pending")
            ca_id = ca.id
        with app.test_client() as c:
            c.post("/auth/login", data={"username": "testadmin",
                                        "password": "adminpass"})
            resp = c.post(f"/ca/{ca_id}/approve", headers=JSON)
            assert resp.status_code == 200
            assert resp.get_json()["approval_status"] == "approved"

    def test_import_keyed_pending_cert_only_approved(self, dc_app, dc_db):
        with dc_app.app_context():
            _mk_user("alice")
            _mk_user("bob")
        key, cert = _self_signed_ca("Imported Keyed Root")
        _, cert2 = _self_signed_ca("Imported CertOnly Root")
        with dc_app.test_client() as c:
            _login(c, "alice")
            resp = c.post("/ca/create", headers=JSON, data={
                "mode": "upload", "name": "Imported Keyed",
                "import_format": "pem", "cert_pem": _pem(cert),
                "key_pem": _key_pem(key),
            })
            assert resp.status_code == 201
            assert resp.get_json()["approval_status"] == "pending"

            resp = c.post("/ca/create", headers=JSON, data={
                "mode": "upload", "name": "Imported CertOnly",
                "import_format": "pem", "cert_pem": _pem(cert2),
                "cert_only": "on",
            })
            assert resp.status_code == 201
            assert resp.get_json()["approval_status"] == "approved"

    def test_revoke_pending_ca_does_not_500(self, dc_app, dc_db):
        with dc_app.app_context():
            _mk_user("alice")
            _mk_user("bob")
        ca_id = self._pending_ca(dc_app)
        with dc_app.test_client() as c:
            _login(c, "bob")
            resp = c.post(f"/ca/{ca_id}/revoke", headers=JSON,
                          data={"reason": "cessation_of_operation"})
            assert resp.status_code == 200
        with dc_app.app_context():
            assert _db.session.get(CertificateAuthority, ca_id).is_revoked is True

    def test_service_default_stays_approved(self, dc_app, dc_db):
        with dc_app.app_context():
            ca = _mk_ca("Service Default CA")
            assert ca.approval_status == "approved"
