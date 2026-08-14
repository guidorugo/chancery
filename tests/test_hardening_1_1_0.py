"""Tests for the 1.1.0 security-hardening batch (B1-B5, C1-C5, D6, E2, L1)."""
import base64
import importlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID
from types import SimpleNamespace

from app.models.ca import CertificateAuthority
from app.services import ca_service, cert_service, crl_service, ocsp_service
from app.services.policy import bounded_not_after, enforce_key_strength
from app.routes.auth import _is_safe_url
from app.services.auth_service import _map_role
from datetime import datetime, timedelta, timezone

PASS = "test-passphrase"


def _root(cn="Hardening Root", days=3650):
    return ca_service.create_root_ca(cn, {"CN": cn}, "RSA", 2048, days, PASS)


# --- B1: CSR proof-of-possession -------------------------------------------

def _valid_csr_pem(cn="poptest.example"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _tampered_csr_pem():
    """A structurally-valid CSR whose signature no longer verifies."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.example")]))
        .sign(key, hashes.SHA256())
    )
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0xFF  # corrupt the trailing signature byte
    tampered = x509.load_der_x509_csr(bytes(der))
    assert tampered.is_signature_valid is False  # precondition for the test
    pem = base64.encodebytes(bytes(der)).decode()
    return f"-----BEGIN CERTIFICATE REQUEST-----\n{pem}-----END CERTIFICATE REQUEST-----\n"


class TestB1CsrProofOfPossession:
    # (Valid-CSR signing is covered by the existing CSR test suites.)

    def test_invalid_signature_csr_rejected(self, db):
        root = _root()
        model = SimpleNamespace(csr_pem=_tampered_csr_pem(), created_by=None, san_json=None)
        with pytest.raises(ValueError, match="proof-of-possession"):
            cert_service.sign_csr(model, root, 365, PASS)


# --- B4/B5: issuance limits & key strength ---------------------------------

class TestB4B5Limits:
    def test_min_rsa_key_enforced(self, app):
        with app.app_context():
            with pytest.raises(ValueError, match="at least 2048"):
                enforce_key_strength("RSA", 1024)

    def test_cert_validity_clamped_to_ca_expiry(self, db):
        root = _root(days=100)  # short-lived CA
        cert = cert_service.create_certificate(
            ca=root, subject_attrs={"CN": "clamp.example"}, san_list=[],
            validity_days=825, passphrase=PASS,  # would outlive the CA
        )
        cert_obj = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        root_cert = x509.load_pem_x509_certificate(root.certificate_pem.encode())
        assert cert_obj.not_valid_after_utc <= root_cert.not_valid_after_utc

    def test_absolute_max_validity_rejected(self, app):
        with app.app_context():
            now = datetime.now(timezone.utc)
            with pytest.raises(ValueError, match="exceeds the maximum"):
                bounded_not_after(now, 99999, is_ca=False)

    def test_weak_rsa_generation_rejected_via_service(self, db):
        with pytest.raises(ValueError, match="at least 2048"):
            cert_service.create_certificate(
                ca=_root(), subject_attrs={"CN": "weak.example"}, san_list=[],
                validity_days=365, passphrase=PASS, key_type="RSA", key_size=1024,
            )


# --- B2/B3: revocation propagates to CRL and OCSP --------------------------

class TestB2B3Revocation:
    def test_revoked_cert_appears_in_cached_crl(self, db):
        root = _root()
        leaf = cert_service.create_certificate(
            ca=root, subject_attrs={"CN": "revme.example"}, san_list=[],
            validity_days=365, passphrase=PASS,
        )
        crl_service.revoke_certificate(leaf.id, "key_compromise", passphrase=PASS)
        db.session.refresh(root)
        crl = x509.load_pem_x509_crl(root.crl_pem.encode())
        assert crl.get_revoked_certificate_by_serial_number(int(leaf.serial_number, 16)) is not None

    def test_revoked_subca_in_parent_crl_and_ocsp(self, db):
        root = _root()
        inter = ca_service.create_intermediate_ca(
            "Revoke Inter", root, {"CN": "Revoke Inter"}, "RSA", 2048, 1825, PASS,
        )
        crl_service.revoke_ca(inter.id, "ca_compromise", passphrase=PASS)
        db.session.refresh(root)

        # B3: parent CRL lists the revoked intermediate's serial
        crl = x509.load_pem_x509_crl(root.crl_pem.encode())
        assert crl.get_revoked_certificate_by_serial_number(int(inter.serial_number, 16)) is not None

        # B3: OCSP against the root for the intermediate's serial => REVOKED
        root_cert = x509.load_pem_x509_certificate(root.certificate_pem.encode())
        inter_cert = x509.load_pem_x509_certificate(inter.certificate_pem.encode())
        req = ocsp.OCSPRequestBuilder().add_certificate(
            inter_cert, root_cert, hashes.SHA1()
        ).build()
        der = ocsp_service.build_ocsp_response(
            req.public_bytes(serialization.Encoding.DER), root, PASS
        )
        resp = ocsp.load_der_ocsp_response(der)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED


# --- C1: read-only public CRL + OCSP unknown-serial ------------------------

class TestC1:
    def test_keyed_ca_has_initial_crl_served_readonly(self, client, db):
        root = _root()
        assert root.crl_pem is not None  # initial CRL at creation
        assert client.get(f"/public/crl/{root.id}.pem").status_code == 200
        assert client.get(f"/public/crl/{root.id}.crl").status_code == 200

    def test_unknown_serial_ocsp_unauthorized(self, db):
        root = _root()
        leaf = cert_service.create_certificate(
            ca=root, subject_attrs={"CN": "known.example"}, san_list=[],
            validity_days=365, passphrase=PASS,
        )
        leaf_cert = x509.load_pem_x509_certificate(leaf.certificate_pem.encode())
        root_cert = x509.load_pem_x509_certificate(root.certificate_pem.encode())
        # Build a request but for a serial the CA never issued
        req = ocsp.OCSPRequestBuilder().add_certificate(
            leaf_cert, root_cert, hashes.SHA256()
        ).build()
        # Point the response at a *different* CA that didn't issue this serial
        other = _root("Other Root")
        der = ocsp_service.build_ocsp_response(
            req.public_bytes(serialization.Encoding.DER), other, PASS
        )
        resp = ocsp.load_der_ocsp_response(der)
        assert resp.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED


# --- C3: leaf key/pkcs12 export POST-only ----------------------------------

class TestC3LeafExport:
    def test_get_key_download_refused(self, auth_admin, db):
        root = _root()
        cert = cert_service.create_certificate(
            ca=root, subject_attrs={"CN": "c3.example"}, san_list=[],
            validity_days=365, passphrase=PASS,
        )
        resp = auth_admin.get(f"/certificates/{cert.id}/download-key")
        assert resp.status_code == 405  # method not allowed (POST-only)

    def test_get_pkcs12_refused(self, auth_admin, db):
        root = _root()
        cert = cert_service.create_certificate(
            ca=root, subject_attrs={"CN": "c3b.example"}, san_list=[],
            validity_days=365, passphrase=PASS,
        )
        resp = auth_admin.get(
            f"/certificates/{cert.id}/download?format=pkcs12&password=x",
            follow_redirects=True,
        )
        assert b"must be submitted via POST" in resp.data

    def test_pkcs12_requires_password(self, auth_admin, db):
        root = _root()
        cert = cert_service.create_certificate(
            ca=root, subject_attrs={"CN": "c3c.example"}, san_list=[],
            validity_days=365, passphrase=PASS,
        )
        resp = auth_admin.post(
            f"/certificates/{cert.id}/download",
            data={"format": "pkcs12", "password": ""}, follow_redirects=True,
        )
        assert b"export password is required" in resp.data


# --- C5: open-redirect hardening -------------------------------------------

class TestC5OpenRedirect:
    @pytest.mark.parametrize("target", ["/dashboard", "/ca/", "/certificates/1"])
    def test_safe_relative_allowed(self, target):
        assert _is_safe_url(target) is True

    @pytest.mark.parametrize("target", [
        "//evil.com", "/\\evil.com", "https://evil.com", "http://evil.com",
        "\\\\evil.com", "/path\\x", "javascript:alert(1)", "",
    ])
    def test_unsafe_rejected(self, target):
        assert _is_safe_url(target) is False


# --- D6: LDAP group gate ----------------------------------------------------

class TestD6LdapGate:
    def test_admin_group_only_does_not_admit_whole_directory(self, app, monkeypatch):
        with app.app_context():
            monkeypatch.setitem(app.config, "LDAP_ADMIN_GROUP_DN", "cn=admins,dc=x")
            monkeypatch.setitem(app.config, "LDAP_REQUESTER_GROUP_DN", "")
            # user in the admin group -> admin
            assert _map_role(["cn=admins,dc=x"]) == "admin"
            # user in NO mapped group -> rejected (was the D6 bug: csr_requester)
            assert _map_role(["cn=someone-else,dc=x"]) is None

    def test_no_groups_configured_defaults_requester(self, app, monkeypatch):
        with app.app_context():
            monkeypatch.setitem(app.config, "LDAP_ADMIN_GROUP_DN", "")
            monkeypatch.setitem(app.config, "LDAP_REQUESTER_GROUP_DN", "")
            assert _map_role([]) == "csr_requester"


# --- C2 / E2 / L1: config & headers ----------------------------------------

class TestHeadersAndConfig:
    def test_security_headers_present(self, client):
        resp = client.get("/auth/login")
        assert "Content-Security-Policy" in resp.headers
        assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
        assert resp.headers.get("Referrer-Policy") == "same-origin"
        assert "max-age=" in resp.headers.get("Strict-Transport-Security", "")

    def _login_token(self, client):
        import re
        page = client.get("/auth/login", base_url="https://localhost")
        m = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', page.data)
        assert m, "login form is missing a csrf_token field"
        return m.group(1).decode()

    def test_https_form_post_with_same_origin_referer_ok(self, app, db, admin_user, monkeypatch):
        # Referrer-Policy: same-origin makes browsers send a same-origin Referer on
        # form POSTs, so Flask-WTF's HTTPS referer check passes -> login works behind
        # a TLS proxy (regression for the "referrer header is missing" 400).
        monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", True)
        client = app.test_client()
        token = self._login_token(client)
        resp = client.post(
            "/auth/login",
            data={"csrf_token": token, "username": "testadmin", "password": "adminpass"},
            base_url="https://localhost",                                  # is_secure -> True
            headers={"Referer": "https://localhost/auth/login"},           # same-origin Referer
            follow_redirects=False)
        assert resp.status_code in (302, 303), resp.data[:200]

    def test_https_form_post_missing_referer_still_rejected(self, app, db, admin_user, monkeypatch):
        # same-origin keeps the referer check ACTIVE (defense-in-depth, not disabled):
        # a token-valid POST over HTTPS with NO Referer is still refused.
        monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", True)
        client = app.test_client()
        token = self._login_token(client)
        resp = client.post(
            "/auth/login",
            data={"csrf_token": token, "username": "testadmin", "password": "adminpass"},
            base_url="https://localhost")                                  # no Referer header
        # The CSRFError handler turns the refusal into a bounce back to login;
        # the login must NOT have gone through (still anonymous afterwards).
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]
        protected = client.get("/", base_url="https://localhost")
        assert protected.status_code == 302
        assert "/auth/login" in protected.headers["Location"]

    def test_max_content_length_configured(self, app):
        assert app.config["MAX_CONTENT_LENGTH"] == 1024 * 1024

    def test_secure_cookie_default_true_in_base_config(self):
        # Base Config (not the HTTP test override) is secure-by-default (L1)
        from app.config import Config
        assert Config.SESSION_COOKIE_SECURE is True

    def test_master_passphrase_file_convention(self, tmp_path, monkeypatch):
        secret = tmp_path / "mp"
        secret.write_text("from-a-file\n")
        monkeypatch.setenv("MASTER_PASSPHRASE_FILE", str(secret))
        import app.config as config_module
        reloaded = importlib.reload(config_module)
        try:
            assert reloaded.Config.MASTER_PASSPHRASE == "from-a-file"
        finally:
            monkeypatch.undo()
            importlib.reload(config_module)
