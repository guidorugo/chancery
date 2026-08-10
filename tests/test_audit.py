from app.models.audit_log import AuditLog


class TestAuditLogging:
    """Audit log entries are created for auth actions."""

    def test_login_success_logged(self, client, admin_user, db):
        client.post("/auth/login", data={
            "username": "testadmin",
            "password": "adminpass",
        })
        entry = AuditLog.query.filter_by(action="login_success").first()
        assert entry is not None
        assert entry.username == "testadmin"
        assert entry.target_type == "user"

    def test_login_failure_logged(self, client, db):
        client.post("/auth/login", data={
            "username": "nonexistent",
            "password": "wrong",
        })
        entry = AuditLog.query.filter_by(action="login_failure").first()
        assert entry is not None
        # Unknown usernames are truncated to avoid logging passwords
        assert "non***" in entry.details

    def test_logout_logged(self, auth_admin, admin_user, db):
        auth_admin.post("/auth/logout")
        entry = AuditLog.query.filter_by(action="logout").first()
        assert entry is not None
        assert entry.username == "testadmin"
