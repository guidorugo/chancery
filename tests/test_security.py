import pytest
from datetime import timedelta
from unittest.mock import patch

from app import create_app
from app.config import Config
from app.extensions import db as _db
from app.models.user import User
from app.routes.auth import _is_safe_url


class InsecureConfig(Config):
    TESTING = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    WTF_CSRF_ENABLED = False


class TestSecurityDefaults:
    """Insecure defaults are rejected in production."""

    def test_insecure_defaults_rejected_in_production(self):
        with pytest.raises(SystemExit):
            create_app(InsecureConfig)

    def test_insecure_defaults_allowed_in_testing(self):
        class SafeTestConfig(Config):
            TESTING = True
            SQLALCHEMY_DATABASE_URI = "sqlite://"
            SECRET_KEY = "dev-secret-key"
            MASTER_PASSPHRASE = "dev-passphrase"
            WTF_CSRF_ENABLED = False

        app = create_app(SafeTestConfig)
        assert app is not None

    def test_insecure_admin_password_rejected_in_production(self):
        class InsecureAdminConfig(Config):
            TESTING = False
            SQLALCHEMY_DATABASE_URI = "sqlite://"
            SECRET_KEY = "strong-secret-key"
            MASTER_PASSPHRASE = "strong-passphrase"
            ADMIN_PASSWORD = "admin"
            WTF_CSRF_ENABLED = False

        with pytest.raises(SystemExit):
            create_app(InsecureAdminConfig)

    def test_secure_admin_password_accepted_in_production(self):
        class SecureAdminConfig(Config):
            TESTING = False
            SQLALCHEMY_DATABASE_URI = "sqlite://"
            SECRET_KEY = "strong-secret-key"
            MASTER_PASSPHRASE = "strong-passphrase"
            ADMIN_PASSWORD = "strong-admin-password-123"
            WTF_CSRF_ENABLED = False

        app = create_app(SecureAdminConfig)
        assert app is not None

    def test_admin_password_unused_once_admin_exists(self, tmp_path):
        # Once an admin exists, ADMIN_PASSWORD is never used again, so it may be
        # removed from the environment (it then defaults to 'admin') without
        # blocking startup — the insecure-default guard only fires when seeding.
        uri = f"sqlite:///{tmp_path / 'cm.db'}"

        class Boot(Config):
            TESTING = False
            SQLALCHEMY_DATABASE_URI = uri
            SECRET_KEY = "strong-secret-key"
            MASTER_PASSPHRASE = "strong-passphrase"
            ADMIN_PASSWORD = "strong-admin-password-123"
            WTF_CSRF_ENABLED = False

        create_app(Boot)  # seeds the first admin

        class Reboot(Boot):
            ADMIN_PASSWORD = "admin"  # reverted to default / effectively removed

        app = create_app(Reboot)  # admin already exists → no check, no exit
        assert app is not None


class TestSessionConfig:
    """Session cookie security settings."""

    def test_session_cookie_httponly(self, app):
        assert app.config["SESSION_COOKIE_HTTPONLY"] is True

    def test_session_cookie_samesite(self, app):
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    def test_session_lifetime(self, app):
        assert app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(minutes=30)

    def test_session_cookie_secure_default(self, app):
        # Default is False (for dev compatibility)
        assert app.config["SESSION_COOKIE_SECURE"] is False


class TestOpenRedirect:
    """Login open redirect protection."""

    def test_safe_url_internal_path(self):
        assert _is_safe_url("/ca/") is True

    def test_safe_url_relative_rejected(self):
        # Relative paths without leading / are rejected for safety
        assert _is_safe_url("dashboard") is False

    def test_safe_url_rejects_absolute_external(self):
        assert _is_safe_url("https://evil.com") is False

    def test_safe_url_rejects_protocol_relative(self):
        assert _is_safe_url("//evil.com") is False

    def test_safe_url_rejects_empty(self):
        assert _is_safe_url("") is False

    def test_safe_url_rejects_none(self):
        assert _is_safe_url(None) is False

    def test_login_redirects_to_safe_next(self, client, admin_user):
        resp = client.post(
            "/auth/login?next=/ca/",
            data={"username": "testadmin", "password": "adminpass"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/ca/")

    def test_login_blocks_external_redirect(self, client, admin_user):
        resp = client.post(
            "/auth/login?next=https://evil.com",
            data={"username": "testadmin", "password": "adminpass"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "evil.com" not in resp.headers["Location"]

    def test_login_blocks_protocol_relative_redirect(self, client, admin_user):
        resp = client.post(
            "/auth/login?next=//evil.com",
            data={"username": "testadmin", "password": "adminpass"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "evil.com" not in resp.headers["Location"]

    def test_login_no_next_goes_to_dashboard(self, client, admin_user):
        resp = client.post(
            "/auth/login",
            data={"username": "testadmin", "password": "adminpass"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/" in resp.headers["Location"]


class TestTimingAttack:
    """Login timing attack mitigation."""

    def test_dummy_hash_called_for_nonexistent_user(self, client):
        with patch("app.services.auth_service.generate_password_hash") as mock_hash:
            client.post(
                "/auth/login",
                data={"username": "nonexistent_user_xyz", "password": "anypass"},
            )
            mock_hash.assert_called_once_with("dummy-password")


class TestSecurityHeaders:
    """Security response headers."""

    def test_x_content_type_options(self, client):
        resp = client.get("/auth/login")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, client):
        resp = client.get("/auth/login")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_headers_on_api_endpoint(self, client, app):
        # Also present on public endpoints
        resp = client.get("/public/ca/999.crt")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"


class TestPublicEndpointErrorDisclosure:
    """Public endpoints don't leak exception details."""

    def _make_dummy_ca(self, name):
        """Create a CA with invalid crypto data to trigger errors."""
        from datetime import datetime, timezone
        from app.models.ca import CertificateAuthority
        ca = CertificateAuthority(
            name=name, common_name=name,
            serial_number="00", certificate_pem="invalid", crl_pem="invalid",
            private_key_enc=b"invalid", key_type="RSA", key_size=2048,
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
        )
        _db.session.add(ca)
        _db.session.commit()
        return ca.id

    def test_crl_der_error_generic_message(self, client, app):
        with app.app_context():
            ca_id = self._make_dummy_ca("Test CA DER")

        resp = client.get(f"/public/crl/{ca_id}.crl")
        assert resp.status_code == 500
        assert b"Internal server error" in resp.data
        # Must NOT contain exception details
        assert b"Traceback" not in resp.data
        assert b"Error generating CRL:" not in resp.data

    def test_crl_pem_no_leak(self, client, app):
        """The public PEM CRL endpoint is read-only (serves the cached CRL,
        no crypto), so it cannot raise or leak a traceback. A CA with no
        cached CRL returns a clean 404."""
        from app.models.ca import CertificateAuthority
        with app.app_context():
            ca = CertificateAuthority(
                name="Test CA PEM NoCRL", common_name="Test CA PEM NoCRL",
                serial_number="00", certificate_pem="invalid",
                private_key_enc=b"invalid", key_type="RSA", key_size=2048,
                not_before=None, not_after=None,
            )
            # bypass the not-null datetimes for this dummy
            from datetime import datetime, timezone
            ca.not_before = datetime.now(timezone.utc)
            ca.not_after = datetime.now(timezone.utc)
            _db.session.add(ca)
            _db.session.commit()
            ca_id = ca.id

        resp = client.get(f"/public/crl/{ca_id}.pem")
        assert resp.status_code == 404
        assert b"Traceback" not in resp.data

    def test_ocsp_error_generic_message(self, client, app):
        # G8-2: garbage is answered with an OCSP malformedRequest (HTTP 200);
        # nothing about the failure leaks into the body either way.
        from cryptography.x509 import ocsp
        with app.app_context():
            ca_id = self._make_dummy_ca("Test CA OCSP")

        resp = client.post(
            f"/public/ocsp/{ca_id}",
            data=b"invalid-ocsp-request",
            content_type="application/ocsp-request",
        )
        assert resp.status_code == 200
        assert b"OCSP error:" not in resp.data
        assert b"Traceback" not in resp.data
        assert (ocsp.load_der_ocsp_response(resp.data).response_status
                == ocsp.OCSPResponseStatus.MALFORMED_REQUEST)


class TestContentDispositionSanitization:
    """Content-Disposition filenames are sanitized (shared helper since G8-1)."""

    def test_injection_characters_never_reach_the_header(self):
        from app.services.filenames import content_disposition
        result = content_disposition('test"cert;evil\nname', "pem")
        ascii_part = result.split("; filename*=")[0]
        assert ascii_part == 'attachment; filename="test_cert_evil_name.pem"'
        assert "\n" not in result
        result.encode("ascii")  # the whole header value is ASCII

    def test_shell_metacharacters_replaced(self):
        from app.services.filenames import content_disposition
        result = content_disposition("my ca; rm -rf /", "crl")
        assert result.startswith('attachment; filename="my_ca__rm_-rf__.crl"')
        assert "filename*=UTF-8''my%20ca%3B%20rm%20-rf%20%2F.crl" in result

    def test_normal_name_unchanged_without_extended_parameter(self):
        from app.services.filenames import content_disposition
        result = content_disposition("example.com", "pem")
        assert result == 'attachment; filename="example.com.pem"'


class TestSRIHashes:
    """Bootstrap CDN resources have SRI integrity attributes."""

    def test_bootstrap_css_has_integrity(self):
        import os
        base_html_path = os.path.join(
            os.path.dirname(__file__), "..", "app", "templates", "base.html"
        )
        with open(base_html_path) as f:
            content = f.read()
        assert 'integrity="sha384-' in content
        assert 'crossorigin="anonymous"' in content

    def test_bootstrap_js_has_integrity(self):
        import os
        base_html_path = os.path.join(
            os.path.dirname(__file__), "..", "app", "templates", "base.html"
        )
        with open(base_html_path) as f:
            content = f.read()
        # Check that both CSS and JS have integrity (at least 2 occurrences)
        assert content.count('integrity="sha384-') >= 2


class TestIntValidation:
    """int() conversion guards on form inputs."""

    def test_invalid_key_size_certificates(self, auth_admin):
        resp = auth_admin.post("/certificates/create", data={
            "ca_id": "1",
            "cn": "test",
            "key_size": "not-a-number",
            "validity_days": "365",
        }, follow_redirects=True)
        assert b"must be valid numbers" in resp.data

    def test_invalid_validity_days_ca(self, auth_admin):
        resp = auth_admin.post("/ca/create", data={
            "mode": "generate",
            "name": "Test CA",
            "cn": "Test CA",
            "key_type": "RSA",
            "key_size": "not-a-number",
            "validity_days": "3650",
            "ca_type": "root",
        }, follow_redirects=True)
        assert b"must be valid numbers" in resp.data

    def test_invalid_key_size_csr(self, auth_admin):
        resp = auth_admin.post("/csr/create", data={
            "mode": "generate",
            "cn": "test",
            "key_type": "RSA",
            "key_size": "abc",
        }, follow_redirects=True)
        assert b"must be a valid number" in resp.data


class TestOCSPURLScheme:
    """OCSP URL scheme is configurable."""

    def test_default_scheme_is_http(self, app):
        assert app.config.get("OCSP_URL_SCHEME", "http") == "http"
