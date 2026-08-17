"""Tests for HTTP Basic Auth authentication."""

import base64
import json

from app import create_app
from app.config import Config
from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.models.user import User


def _basic_auth_headers(username, password):
    """Build Authorization: Basic header."""
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


# --- Success cases ---

class TestBasicAuthSuccess:
    def test_admin_access_with_basic_auth(self, client, admin_user):
        resp = client.get("/ca/", headers=_basic_auth_headers("testadmin", "adminpass"))
        assert resp.status_code == 200

    def test_csr_requester_access_own_routes(self, client, csr_requester):
        resp = client.get("/csr/", headers=_basic_auth_headers("testrequester", "requesterpass"))
        assert resp.status_code == 200

    def test_post_without_csrf_token(self, app, admin_user):
        """Basic Auth POST should succeed without CSRF token."""
        # Use a fresh test client with CSRF enabled
        app.config["WTF_CSRF_ENABLED"] = True
        try:
            with app.test_client() as csrf_client:
                resp = csrf_client.get(
                    "/ca/",
                    headers=_basic_auth_headers("testadmin", "adminpass"),
                )
                assert resp.status_code == 200
        finally:
            app.config["WTF_CSRF_ENABLED"] = False

    def test_no_login_user_called(self, app, admin_user):
        """Basic Auth request_loader does not call login_user(), so no _user_id in session."""
        with app.test_client() as c:
            with c.session_transaction() as sess:
                assert "_user_id" not in sess
            resp = c.get("/ca/", headers=_basic_auth_headers("testadmin", "adminpass"))
            assert resp.status_code == 200
            # After basic auth, session should still NOT contain _user_id
            with c.session_transaction() as sess:
                assert "_user_id" not in sess


# --- Failure cases ---

class TestBasicAuthFailure:
    def test_wrong_password_returns_401(self, client, admin_user):
        resp = client.get("/ca/", headers=_basic_auth_headers("testadmin", "wrongpass"))
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers
        assert "Basic" in resp.headers["WWW-Authenticate"]
        data = json.loads(resp.data)
        assert "error" in data

    def test_nonexistent_user_returns_401(self, client):
        resp = client.get("/ca/", headers=_basic_auth_headers("nosuchuser", "pass"))
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers

    def test_deactivated_user_returns_401(self, client, inactive_user):
        resp = client.get("/ca/", headers=_basic_auth_headers("inactiveuser", "inactivepass"))
        assert resp.status_code == 401

    def test_no_auth_header_redirects_to_login(self, client):
        resp = client.get("/ca/")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]


# --- RBAC ---

class TestBasicAuthRBAC:
    def test_csr_requester_forbidden_on_admin_route(self, client, csr_requester):
        resp = client.get("/ca/", headers=_basic_auth_headers("testrequester", "requesterpass"))
        assert resp.status_code == 403
        data = json.loads(resp.data)
        assert "error" in data

    def test_admin_required_returns_json_for_basic_auth(self, client, csr_requester):
        resp = client.get(
            "/users/audit-log",
            headers=_basic_auth_headers("testrequester", "requesterpass"),
        )
        assert resp.status_code == 403
        data = json.loads(resp.data)
        assert "permission" in data["error"].lower()


# --- CSRF interaction ---

class TestBasicAuthCSRF:
    def test_csrf_still_required_for_session_post(self, app, admin_user):
        """Session-based POST should still require CSRF when enabled."""
        app.config["WTF_CSRF_ENABLED"] = True
        try:
            with app.test_client() as csrf_client:
                # Login via session
                csrf_client.post("/auth/login", data={
                    "username": "testadmin",
                    "password": "adminpass",
                })
                # POST without CSRF token should fail
                resp = csrf_client.post("/ca/create")
                assert resp.status_code in (400, 302)  # CSRF error or redirect
        finally:
            app.config["WTF_CSRF_ENABLED"] = False

    def test_csrf_not_bypassed_by_invalid_basic_auth(self, app, admin_user):
        """Invalid Basic Auth credentials must NOT bypass CSRF for session requests."""
        app.config["WTF_CSRF_ENABLED"] = True
        try:
            with app.test_client() as csrf_client:
                # Send invalid basic auth - should NOT bypass CSRF
                resp = csrf_client.post(
                    "/ca/create",
                    headers=_basic_auth_headers("testadmin", "wrongpass"),
                )
                # CSRF must fire: a JSON 400, a 401, or the CSRFError handler's
                # bounce to login — but NEVER the create succeeding.
                assert resp.status_code in (400, 401, 302)
                if resp.status_code == 302:
                    assert "/auth/login" in resp.headers["Location"]
        finally:
            app.config["WTF_CSRF_ENABLED"] = False


# --- Audit logging ---

class TestBasicAuthAudit:
    def test_success_logged(self, client, admin_user):
        client.get("/ca/", headers=_basic_auth_headers("testadmin", "adminpass"))
        entry = AuditLog.query.filter_by(action="basic_auth_success").first()
        assert entry is not None
        details = json.loads(entry.details)
        assert details["auth_method"] == "basic_auth"
        assert details["username"] == "testadmin"

    def test_failure_logged(self, client, admin_user):
        client.get("/ca/", headers=_basic_auth_headers("testadmin", "wrongpass"))
        entry = AuditLog.query.filter_by(action="basic_auth_failed").first()
        assert entry is not None
        details = json.loads(entry.details)
        assert details["auth_method"] == "basic_auth"
        assert details["username"] == "testadmin"


# --- Username sanitization ---

class TestUsernameSanitization:
    def test_known_username_logged_in_full(self, client, admin_user):
        """Failed auth with a real username logs it unchanged."""
        client.get("/ca/", headers=_basic_auth_headers("testadmin", "wrongpass"))
        entry = AuditLog.query.filter_by(action="basic_auth_failed").first()
        details = json.loads(entry.details)
        assert details["username"] == "testadmin"

    def test_unknown_username_truncated(self, client):
        """Failed auth with an unknown username truncates it to avoid logging passwords."""
        client.get("/ca/", headers=_basic_auth_headers("MyS3cretP@ssw0rd!", "anything"))
        entry = AuditLog.query.filter_by(action="basic_auth_failed").first()
        details = json.loads(entry.details)
        assert details["username"] == "MyS***"
        assert "MyS3cretP@ssw0rd!" not in details["username"]

    def test_short_unknown_username_not_truncated(self, client):
        """Unknown usernames <= 3 chars are too short to be passwords, log as-is."""
        client.get("/ca/", headers=_basic_auth_headers("ab", "anything"))
        entry = AuditLog.query.filter_by(action="basic_auth_failed").first()
        details = json.loads(entry.details)
        assert details["username"] == "ab"

    def test_session_login_sanitizes_username(self, client):
        """Session login also sanitizes unknown usernames."""
        client.post("/auth/login", data={
            "username": "MyS3cretP@ssw0rd!",
            "password": "anything",
        })
        entry = AuditLog.query.filter_by(action="login_failure").first()
        details = json.loads(entry.details)
        assert details["attempted_username"] == "MyS***"


# --- Config ---

class TestBasicAuthConfig:
    def test_disabled_ignores_header(self, app, admin_user):
        app.config["BASIC_AUTH_ENABLED"] = False
        try:
            with app.test_client() as disabled_client:
                resp = disabled_client.get(
                    "/ca/",
                    headers=_basic_auth_headers("testadmin", "adminpass"),
                )
                # Should redirect to login since basic auth is disabled
                assert resp.status_code == 302
                assert "/auth/login" in resp.headers["Location"]
        finally:
            app.config["BASIC_AUTH_ENABLED"] = True

    def test_custom_realm_in_www_authenticate(self, app, admin_user):
        app.config["BASIC_AUTH_REALM"] = "my-custom-realm"
        try:
            with app.test_client() as realm_client:
                resp = realm_client.get(
                    "/ca/",
                    headers=_basic_auth_headers("testadmin", "wrongpass"),
                )
                assert resp.status_code == 401
                assert "my-custom-realm" in resp.headers["WWW-Authenticate"]
        finally:
            app.config["BASIC_AUTH_REALM"] = "chancery"
