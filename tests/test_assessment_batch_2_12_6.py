"""Regression tests for the 2.12.6 assessment patch batch
(SECURITY_ASSESSMENT_29-08-26 §4.2 / FEATURE_PLAN_14-09-26 §4.2).

One class per finding; each test is the negative case the assessment found
missing (G22-1).
"""
import base64
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, quote, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError

from app import create_app, _migrate_schema
from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.models.certificate import Certificate
from app.models.csr import CertificateSigningRequest
from app.models.user import User
from app.services import ca_service, cert_service, crl_service, csr_service, public_url
from app.services.filenames import content_disposition
from tests.conftest import TestConfig

JSON = {"Accept": "application/json"}
PASSPHRASE = "test-passphrase"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _root(name="Batch Root", cn=None):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": cn or name}, key_type="RSA", key_size=2048,
        validity_days=3650, passphrase=PASSPHRASE)


def _inter(parent, name="Batch Inter"):
    return ca_service.create_intermediate_ca(
        name=name, parent_ca=parent, subject_attrs={"CN": name}, key_type="RSA",
        key_size=2048, validity_days=1825, passphrase=PASSPHRASE)


def _leaf(ca, cn="leaf.example.com"):
    return cert_service.create_certificate(
        ca=ca, subject_attrs={"CN": cn}, san_list=[cn], validity_days=365,
        passphrase=PASSPHRASE)


def _csr(created_by=None, cn="csr.example.com"):
    csr_model, _key_pem, _ = csr_service.create_csr(
        {"CN": cn}, [cn], "RSA", 2048, None, created_by=created_by)
    _db.session.commit()
    return csr_model


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()


def _name(cn):
    return x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])


def _self_signed(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn)).issuer_name(_name(cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _child(cn, parent_key, parent_cert):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn)).issuer_name(parent_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(parent_key, hashes.SHA256())
    )
    return key, cert


def _ocsp_request_der(cert_model, ca_model):
    ca_cert = x509.load_pem_x509_certificate(ca_model.certificate_pem.encode())
    ee_cert = x509.load_pem_x509_certificate(cert_model.certificate_pem.encode())
    return (ocsp.OCSPRequestBuilder().add_certificate(ee_cert, ca_cert, hashes.SHA256())
            .build().public_bytes(serialization.Encoding.DER))


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# G4-2 / G4-6 — sub-CA under a revoked or expired parent
# ---------------------------------------------------------------------------

class TestParentGuards:
    def test_service_refuses_revoked_parent(self, app, db):
        with app.app_context():
            root = _root()
            crl_service.revoke_ca(root.id, "key_compromise", passphrase=PASSPHRASE)
            with pytest.raises(ValueError, match="revoked"):
                _inter(root)

    def test_service_refuses_expired_parent(self, app, db):
        with app.app_context():
            root = _root()
            root.not_after = datetime.now(timezone.utc) - timedelta(days=1)
            db.session.commit()
            with pytest.raises(ValueError, match="expired"):
                _inter(root)

    def test_route_refuses_revoked_parent_id(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            crl_service.revoke_ca(root.id, "key_compromise", passphrase=PASSPHRASE)
            r = auth_admin.post("/ca/create", data={
                "mode": "generate", "name": "Sneaky Inter", "cn": "Sneaky Inter",
                "key_type": "RSA", "key_size": "2048", "validity_days": "365",
                "ca_type": "intermediate", "parent_id": str(root.id),
            }, headers=JSON)
            assert r.status_code == 400
            assert "cannot sign" in r.get_json()["error"]
            assert CertificateAuthority.query.count() == 1


# ---------------------------------------------------------------------------
# G4-7 — an imported CA's parent must have actually issued it
# ---------------------------------------------------------------------------

class TestImportParentVerification:
    def test_explicit_parent_that_did_not_issue_is_refused(self, app, db):
        with app.app_context():
            real_key, real_cert = _self_signed("Real Parent")
            _other_key, other_cert = _self_signed("Other Root")
            other = ca_service.import_ca("Other Root", _pem(other_cert), None, PASSPHRASE)
            child_key, child_cert = _child("Child", real_key, real_cert)
            with pytest.raises(ValueError, match="not issued by the selected parent"):
                ca_service.import_ca("Child", _pem(child_cert), _key_pem(child_key),
                                     PASSPHRASE, parent_id=other.id)

    def test_explicit_parent_that_issued_is_linked(self, app, db):
        with app.app_context():
            real_key, real_cert = _self_signed("Real Parent")
            parent = ca_service.import_ca("Real Parent", _pem(real_cert), None, PASSPHRASE)
            child_key, child_cert = _child("Child", real_key, real_cert)
            child = ca_service.import_ca("Child", _pem(child_cert), _key_pem(child_key),
                                         PASSPHRASE, parent_id=parent.id)
            assert child.parent_id == parent.id

    def test_issuer_name_match_without_valid_signature_is_not_linked(self, app, db):
        with app.app_context():
            real_key, real_cert = _self_signed("Real Parent")
            _imp_key, impostor_cert = _self_signed("Real Parent")  # same name, other key
            ca_service.import_ca("Impostor", _pem(impostor_cert), None, PASSPHRASE)
            child_key, child_cert = _child("Child", real_key, real_cert)
            child = ca_service.import_ca("Child", _pem(child_cert), _key_pem(child_key), PASSPHRASE)
            assert child.parent_id is None

    def test_revoked_parent_refused_on_import(self, app, db):
        with app.app_context():
            root = _root()
            crl_service.revoke_ca(root.id, "key_compromise", passphrase=PASSPHRASE)
            _key, cert = _self_signed("Anything")
            with pytest.raises(ValueError, match="revoked"):
                ca_service.import_ca("Anything", _pem(cert), None, PASSPHRASE, parent_id=root.id)


# ---------------------------------------------------------------------------
# G4-8 — a revoked CA publishes a final CRL valid until its own expiry
# ---------------------------------------------------------------------------

class TestFinalCrl:
    def test_revoked_ca_final_crl_next_update_is_ca_expiry(self, app, db):
        with app.app_context():
            root = _root()
            leaf = _leaf(root)
            crl_service.revoke_ca(root.id, "cessation_of_operation", passphrase=PASSPHRASE)
            crl = x509.load_pem_x509_crl(root.crl_pem.encode())
            delta = abs((crl.next_update_utc - _aware(root.not_after)).total_seconds())
            assert delta < 2, "final CRL must stay valid until the CA certificate expires"
            assert crl.get_revoked_certificate_by_serial_number(int(leaf.serial_number, 16)) is not None


# ---------------------------------------------------------------------------
# G7-1 (first half) — CSR key generation enforces the key floor
# ---------------------------------------------------------------------------

class TestCsrKeyFloor:
    def test_service_rejects_weak_key(self, app, db):
        with app.app_context():
            with pytest.raises(ValueError, match="at least"):
                csr_service.create_csr({"CN": "weak"}, [], "RSA", 1024)

    def test_route_rejects_weak_key_with_400(self, app, auth_admin, db):
        with app.app_context():
            r = auth_admin.post("/csr/create", data={
                "mode": "generate", "cn": "weak.example.com", "key_type": "RSA", "key_size": "1024",
            }, headers=JSON)
            assert r.status_code == 400
            assert "at least" in r.get_json()["error"]
            assert CertificateSigningRequest.query.count() == 0


# ---------------------------------------------------------------------------
# G7-2 — csr routes surface ValueError as 400
# ---------------------------------------------------------------------------

class TestCsrRouteErrors:
    def test_upload_garbage_is_400(self, app, auth_admin, db):
        with app.app_context():
            r = auth_admin.post("/csr/create", data={"mode": "upload", "csr_pem": "not a csr"},
                                headers=JSON)
            assert r.status_code == 400
            assert "error" in r.get_json()

    def test_sign_policy_refusal_is_400_and_leaves_csr_pending(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            csr = _csr()
            r = auth_admin.post(f"/csr/{csr.id}/sign",
                                data={"ca_id": str(root.id), "validity_days": "99999"},
                                headers=JSON)
            assert r.status_code == 400
            assert "error" in r.get_json()
            db.session.refresh(csr)
            assert csr.status == "pending"  # G7-4: the claim was released


# ---------------------------------------------------------------------------
# G7-3 — path_length and revocation reason validation
# ---------------------------------------------------------------------------

class TestInputValidation:
    def test_negative_path_length_is_400(self, app, auth_admin, db):
        with app.app_context():
            r = auth_admin.post("/ca/create", data={
                "mode": "generate", "name": "Neg", "cn": "Neg", "key_type": "RSA",
                "key_size": "2048", "validity_days": "365", "ca_type": "root", "path_length": "-1",
            }, headers=JSON)
            assert r.status_code == 400
            assert "Path length" in r.get_json()["error"]
            assert CertificateAuthority.query.count() == 0

    def test_unknown_reason_rejected_for_certificates(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            leaf = _leaf(root)
            r = auth_admin.post(f"/certificates/{leaf.id}/revoke", data={"reason": "bogus"},
                                headers=JSON)
            assert r.status_code == 400
            db.session.refresh(leaf)
            assert leaf.is_revoked is False

    def test_unknown_reason_rejected_for_cas(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            r = auth_admin.post(f"/ca/{root.id}/revoke", data={"reason": "bogus"}, headers=JSON)
            assert r.status_code == 400
            db.session.refresh(root)
            assert root.is_revoked is False

    def test_service_rejects_unknown_reason(self, app, db):
        with app.app_context():
            root = _root()
            leaf = _leaf(root)
            with pytest.raises(ValueError, match="reason"):
                crl_service.revoke_certificate(leaf.id, "bogus", passphrase=PASSPHRASE)
            with pytest.raises(ValueError, match="reason"):
                crl_service.revoke_ca(root.id, "bogus", passphrase=PASSPHRASE)


# ---------------------------------------------------------------------------
# G7-4 — single-flight CSR signing
# ---------------------------------------------------------------------------

class TestCsrSingleFlight:
    def test_claim_refuses_a_csr_that_is_not_pending(self, app, db):
        with app.app_context():
            root = _root()
            csr = _csr()
            csr.status = "signing"  # another worker holds the claim
            db.session.commit()
            with pytest.raises(cert_service.CsrAlreadyProcessed):
                cert_service.sign_csr(csr, root, 365, PASSPHRASE)
            assert Certificate.query.count() == 0

    def test_failed_signing_releases_the_claim(self, app, db, monkeypatch):
        with app.app_context():
            root = _root()
            csr = _csr()

            def boom(*_args, **_kwargs):
                raise RuntimeError("signer exploded")

            monkeypatch.setattr(cert_service, "_sign_claimed_csr", boom)
            with pytest.raises(RuntimeError):
                cert_service.sign_csr(csr, root, 365, PASSPHRASE)
            db.session.refresh(csr)
            assert csr.status == "pending"

    def test_route_answers_409_when_the_claim_is_lost(self, app, auth_admin, db, monkeypatch):
        with app.app_context():
            root = _root()
            csr = _csr()

            def lost(_csr_model):
                raise cert_service.CsrAlreadyProcessed("This CSR has already been processed.")

            monkeypatch.setattr(cert_service, "_claim_csr", lost)
            r = auth_admin.post(f"/csr/{csr.id}/sign",
                                data={"ca_id": str(root.id), "validity_days": "365"}, headers=JSON)
            assert r.status_code == 409

    def test_successful_signing_ends_approved(self, app, db):
        with app.app_context():
            root = _root()
            csr = _csr()
            cert = cert_service.sign_csr(csr, root, 365, PASSPHRASE)
            db.session.refresh(csr)
            assert csr.status == "approved" and csr.certificate_id == cert.id


# ---------------------------------------------------------------------------
# G7-5 — intermediate without a parent
# ---------------------------------------------------------------------------

class TestIntermediateNeedsParent:
    def test_empty_parent_id_is_400_not_a_root(self, app, auth_admin, db):
        with app.app_context():
            r = auth_admin.post("/ca/create", data={
                "mode": "generate", "name": "Orphan", "cn": "Orphan", "key_type": "RSA",
                "key_size": "2048", "validity_days": "365", "ca_type": "intermediate", "parent_id": "",
            }, headers=JSON)
            assert r.status_code == 400
            assert "parent CA is required" in r.get_json()["error"]
            assert CertificateAuthority.query.count() == 0


# ---------------------------------------------------------------------------
# G8-1 — non-latin-1 names in Content-Disposition
# ---------------------------------------------------------------------------

class TestFilenames:
    def test_non_latin1_name_falls_back_and_carries_rfc5987(self):
        value = content_disposition("Łódź 测试", "crl", fallback="ca-7")
        assert value.startswith('attachment; filename="ca-7.crl"')
        assert "filename*=UTF-8''%C5%81%C3%B3d%C5%BA%20%E6%B5%8B%E8%AF%95.crl" in value
        value.encode("latin-1")  # what gunicorn does with header values

    def test_mixed_name_keeps_the_ascii_part(self):
        value = content_disposition("Zürich-Ost", "pem")
        assert value.startswith('attachment; filename="Z_rich-Ost.pem"')
        assert "filename*=UTF-8''Z%C3%BCrich-Ost.pem" in value

    def test_public_endpoints_serve_a_ca_with_a_non_latin1_name(self, app, client, db):
        with app.app_context():
            root = _root(name="Łódź 测试", cn="Lodz Root")
            for path, ext in ((f"/public/crl/{root.id}.crl", "crl"),
                              (f"/public/crl/{root.id}.pem", "crl.pem"),
                              (f"/public/ca/{root.id}.crt", "crt")):
                r = client.get(path)
                assert r.status_code == 200, path
                cd = r.headers["Content-Disposition"]
                assert f'filename="ca-{root.id}.{ext}"' in cd
                assert "filename*=UTF-8''%C5%81%C3%B3d%C5%BA" in cd
                cd.encode("latin-1")

    def test_admin_download_uses_the_same_helper(self, app, auth_admin, db):
        with app.app_context():
            root = _root(name="Ελλάς", cn="Hellas Root")
            r = auth_admin.get(f"/ca/{root.id}/download?format=pem")
            assert r.status_code == 200
            cd = r.headers["Content-Disposition"]
            assert f'filename="ca-{root.id}.pem"' in cd
            cd.encode("latin-1")


# ---------------------------------------------------------------------------
# G8-2 — OCSP malformed request + GET form
# ---------------------------------------------------------------------------

class TestOcspForms:
    def test_get_form_answers_a_real_request(self, app, client, db):
        with app.app_context():
            root = _root()
            leaf = _leaf(root)
            encoded = quote(base64.b64encode(_ocsp_request_der(leaf, root)).decode(), safe="")
            r = client.get(f"/public/ocsp/{root.id}/{encoded}")
            assert r.status_code == 200
            assert r.mimetype == "application/ocsp-response"
            resp = ocsp.load_der_ocsp_response(r.data)
            assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
            assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD

    def test_get_form_garbage_is_malformed_request(self, app, client, db):
        with app.app_context():
            root = _root()
            r = client.get(f"/public/ocsp/{root.id}/not-base64-at-all!!")
            assert r.status_code == 200
            resp = ocsp.load_der_ocsp_response(r.data)
            assert resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST

    def test_post_empty_body_is_malformed_request(self, app, client, db):
        with app.app_context():
            root = _root()
            r = client.post(f"/public/ocsp/{root.id}", data=b"", content_type="application/ocsp-request")
            assert r.status_code == 200
            resp = ocsp.load_der_ocsp_response(r.data)
            assert resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST

    def test_get_form_unknown_ca_is_404(self, client):
        assert client.get("/public/ocsp/99999/AAAA").status_code == 404


# ---------------------------------------------------------------------------
# G8-3 — loopback hostnames never get baked into certificates
# ---------------------------------------------------------------------------

class _ProdLikeConfig(TestConfig):
    TESTING = False
    DEBUG = False
    SECRET_KEY = "s" * 64
    MASTER_PASSPHRASE = PASSPHRASE
    ADMIN_PASSWORD = "strong-bootstrap-password-123"
    SESSION_COOKIE_SECURE = False
    RATE_LIMIT_ENABLED = False
    UPDATE_CHECK_ENABLED = False
    SERVER_NAME_FOR_OCSP = "localhost:5000"


def _prod_like_client(app2):
    with app2.app_context():
        ops = User(username="ops", role="admin")
        ops.set_password("ops-password-1234")
        _db.session.add(ops)
        _db.session.commit()
    c = app2.test_client()
    c.post("/auth/login", data={"username": "ops", "password": "ops-password-1234"})
    return c


class TestLoopbackRefusal:
    @pytest.mark.parametrize("hostport,expected", [
        ("localhost:5000", True), ("127.0.0.1", True), ("[::1]:5000", True),
        ("127.5.5.5:8080", True), ("ca.localhost", True),
        ("ca.example.com:5000", False), ("192.168.1.10:5000", False), ("10.0.0.5", False),
    ])
    def test_is_loopback(self, hostport, expected):
        assert public_url.is_loopback(hostport) is expected

    def test_host_only_strips_ports(self):
        assert public_url.host_only("[::1]:5000") == "::1"
        assert public_url.host_only("Example.COM:5000") == "example.com"

    def test_testing_mode_keeps_localhost_working(self, app):
        with app.test_request_context("/", base_url="http://localhost:5000"):
            aia, cdp = public_url.issuance_urls(1)
            assert aia == "http://localhost:5000/public/ocsp/1"
            assert cdp == "http://localhost:5000/public/crl/1.crl"

    def test_operator_override_is_checked_too(self, app):
        app.config["TESTING"] = False
        try:
            with app.test_request_context("/", base_url="http://ca.example.com"):
                with pytest.raises(ValueError, match="loopback"):
                    public_url.issuance_urls(1, "http://127.0.0.1:5000/public/crl/1.crl")
        finally:
            app.config["TESTING"] = True

    def test_production_app_refuses_loopback_and_accepts_a_pinned_name(self):
        app2 = create_app(_ProdLikeConfig)
        client = _prod_like_client(app2)
        with app2.app_context():
            root = _root()
            data = {"ca_id": str(root.id), "cn": "svc.example.com", "validity_days": "30",
                    "key_type": "RSA", "key_size": "2048"}
            r = client.post("/certificates/create", data=data, headers=JSON,
                            base_url="http://localhost:5000")
            assert r.status_code == 400
            assert "loopback" in r.get_json()["error"]
            assert Certificate.query.count() == 0

            app2.config["SERVER_NAME_FOR_OCSP"] = "ca.example.com"
            r = client.post("/certificates/create", data=data, headers=JSON,
                            base_url="http://localhost:5000")
            assert r.status_code == 201, r.get_json()
            cert = x509.load_pem_x509_certificate(r.get_json()["certificate_pem"].encode())
            aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            assert any("ca.example.com" in d.access_location.value for d in aia)
            _db.session.remove()


# ---------------------------------------------------------------------------
# G6-2 — admin-set passwords follow the policy and must be rotated
# ---------------------------------------------------------------------------

class TestAdminSetPasswords:
    def test_create_user_enforces_min_length(self, app, auth_admin, db):
        with app.app_context():
            r = auth_admin.post("/users/create", data={
                "username": "shorty", "password": "short", "role": "csr_requester"},
                follow_redirects=True)
            assert b"at least 12" in r.data
            assert User.query.filter_by(username="shorty").first() is None

    def test_reset_password_enforces_min_length(self, app, auth_admin, db):
        with app.app_context():
            user = User(username="resetshort", role="csr_requester")
            user.set_password("old-password-123")
            db.session.add(user)
            db.session.commit()
            r = auth_admin.post(f"/users/{user.id}/reset-password", data={"password": "short"},
                                follow_redirects=True)
            assert b"at least 12" in r.data
            db.session.refresh(user)
            assert user.check_password("old-password-123")
            assert user.must_change_password is False


# ---------------------------------------------------------------------------
# G6-3 — the post-login `next` redirect is honoured
# ---------------------------------------------------------------------------

class TestNextRedirect:
    def test_next_is_path_only_and_round_trips(self, client, admin_user):
        r = client.get("/ca/?page=2")
        assert r.status_code == 302
        target = parse_qs(urlsplit(r.headers["Location"]).query)["next"]
        assert target == ["/ca/?page=2"]  # path-only, never an absolute URL

        r2 = client.post("/auth/login?next=%2Fca%2F%3Fpage%3D2",
                         data={"username": "testadmin", "password": "adminpass"})
        assert r2.status_code == 302
        assert r2.headers["Location"] == "/ca/?page=2"

    def test_absolute_next_is_still_rejected(self, client, admin_user):
        r = client.post("/auth/login?next=https%3A%2F%2Fevil.example",
                        data={"username": "testadmin", "password": "adminpass"})
        assert r.status_code == 302
        assert r.headers["Location"] in ("/", "/dashboard", "/dashboard/")


# ---------------------------------------------------------------------------
# G10-1 — revocation and its audit row survive a CRL refresh failure
# ---------------------------------------------------------------------------

class TestRevocationAuditSurvivesCrlFailure:
    def test_certificate(self, app, auth_admin, db, monkeypatch):
        with app.app_context():
            root = _root()
            leaf = _leaf(root)

            def hsm_down(*_a, **_k):
                raise RuntimeError("HSM unreachable")

            monkeypatch.setattr(crl_service, "generate_crl", hsm_down)
            r = auth_admin.post(f"/certificates/{leaf.id}/revoke",
                                data={"reason": "key_compromise"}, headers=JSON)
            assert r.status_code == 200
            body = r.get_json()
            assert "CRL refresh failed" in body["warning"]
            db.session.refresh(leaf)
            assert leaf.is_revoked is True
            assert AuditLog.query.filter_by(action="revoke_certificate", target_id=leaf.id).count() == 1

    def test_ca(self, app, auth_admin, db, monkeypatch):
        with app.app_context():
            root = _root()
            _leaf(root)

            def hsm_down(*_a, **_k):
                raise RuntimeError("HSM unreachable")

            monkeypatch.setattr(crl_service, "generate_crl", hsm_down)
            r = auth_admin.post(f"/ca/{root.id}/revoke", data={"reason": "ca_compromise"},
                                headers=JSON)
            assert r.status_code == 200
            assert "CRL refresh failed" in r.get_json()["warning"]
            db.session.refresh(root)
            assert root.is_revoked is True
            assert AuditLog.query.filter_by(action="revoke_ca", target_id=root.id).count() == 1

    def test_html_flow_flashes_a_warning(self, app, auth_admin, db, monkeypatch):
        with app.app_context():
            root = _root()
            leaf = _leaf(root)
            monkeypatch.setattr(crl_service, "generate_crl",
                                lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))
            r = auth_admin.post(f"/certificates/{leaf.id}/revoke",
                                data={"reason": "superseded"}, follow_redirects=True)
            assert r.status_code == 200
            assert b"CRL refresh failed" in r.data
            assert b"revoked" in r.data


# ---------------------------------------------------------------------------
# G12-1 — ocsp_server is JSON-escaped inside the inline script
# ---------------------------------------------------------------------------

class TestTemplateEscaping:
    def test_quote_in_server_name_cannot_break_out_of_the_js_string(self, app, auth_admin, db):
        original = app.config.get("SERVER_NAME_FOR_OCSP")
        app.config["SERVER_NAME_FOR_OCSP"] = "evil'host"
        try:
            with app.app_context():
                _root()
                r = auth_admin.get("/certificates/create")
                assert r.status_code == 200
                assert b"evil\\u0027host/public/crl/" in r.data
                assert b"'http://evil'host" not in r.data
        finally:
            app.config["SERVER_NAME_FOR_OCSP"] = original


# ---------------------------------------------------------------------------
# G9-1 — CA serial numbers are unique at the DB level
# ---------------------------------------------------------------------------

class TestCaSerialUniqueness:
    def test_duplicate_serial_is_refused_by_the_database(self, app, db):
        with app.app_context():
            root = _root()
            dup = CertificateAuthority(
                name="Duplicate Serial", common_name="Duplicate Serial",
                serial_number=root.serial_number, certificate_pem=root.certificate_pem,
                private_key_enc=b"", key_type="RSA", key_size=2048,
                not_before=root.not_before, not_after=root.not_after,
            )
            db.session.add(dup)
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()

    def test_migration_creates_the_named_index(self, app, db):
        with app.app_context():
            _migrate_schema()
            names = {ix["name"] for ix in sa_inspect(_db.engine).get_indexes("certificate_authorities")}
            assert "ux_certificate_authorities_serial" in names


# ---------------------------------------------------------------------------
# G13-1 — migrate-to-hsm safety (the token-cleanup half lives in test_softhsm.py)
# ---------------------------------------------------------------------------

class TestMigrateToHsmCli:
    def test_yes_requires_ca_id(self, app):
        with app.app_context():
            result = app.test_cli_runner().invoke(args=["keys", "migrate-to-hsm", "--yes"])
            assert result.exit_code != 0
            assert "--yes requires --ca-id" in result.output


# ---------------------------------------------------------------------------
# G16-1 — startup warnings for weak-looking secrets (never fatal)
# ---------------------------------------------------------------------------

class TestSecretStrengthWarnings:
    def test_short_secrets_warn(self, capsys):
        class Short(_ProdLikeConfig):
            SECRET_KEY = "short-secret-key"     # 16 chars
            MASTER_PASSPHRASE = "short-pass"    # 10 chars

        app2 = create_app(Short)
        assert app2 is not None  # warnings, not a refusal to boot
        err = capsys.readouterr().err
        assert "SECRET_KEY is only 16 characters" in err
        assert "MASTER_PASSPHRASE is only 10 characters" in err

    def test_generator_length_secrets_do_not_warn(self, capsys):
        class Strong(_ProdLikeConfig):
            SECRET_KEY = "a" * 64
            MASTER_PASSPHRASE = "b" * 32

        create_app(Strong)
        err = capsys.readouterr().err
        assert "WARNING: SECRET_KEY" not in err
        assert "WARNING: MASTER_PASSPHRASE" not in err
