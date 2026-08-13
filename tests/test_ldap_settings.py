"""Tests for the DB-backed LDAP settings (admin UI) and env-var precedence.

ldap3 is mocked exactly like tests/test_ldap.py: ldap_service goes through
ldap3.Connection, so tests monkeypatch it with fakes from that module.
"""
import ldap3
import pytest

from app.models import AuditLog, LdapSettings
from app.services import auth_service, crypto_utils, ldap_settings_service
from tests.test_ldap import FakeConnection, _ldap_down


def _base_form(**overrides):
    form = {
        "action": "save",
        "enabled": "on",
        "server_uri": "ldaps://ldap.test:636",
        "tls_verify": "on",
        "user_dn_template": "uid={username},ou=people,dc=test",
        "user_filter": "(uid={username})",
        "group_member_attr": "memberOf",
        "timeout_seconds": "5",
        "admin_group_dn": "cn=cert-admins,ou=groups,dc=test",
        "requester_group_dn": "cn=cert-requesters,ou=groups,dc=test",
    }
    form.update(overrides)
    return form


class TestSecretHelpers:
    def test_round_trip(self):
        enc = crypto_utils.encrypt_secret("s3cret", "passphrase")
        assert enc != b"s3cret"
        assert crypto_utils.decrypt_secret(enc, "passphrase") == "s3cret"


class TestPrecedence:
    def test_env_fallback_without_row(self, app, db):
        with app.test_request_context():
            assert ldap_settings_service.config_source() == "env"
            cfg = ldap_settings_service.effective_config()
            assert cfg["LDAP_ENABLED"] == app.config["LDAP_ENABLED"]

    def test_db_row_wins_over_env(self, app, db, monkeypatch):
        monkeypatch.setitem(app.config, "LDAP_ENABLED", False)
        monkeypatch.setitem(app.config, "LDAP_SERVER_URI", "ldaps://env-server")
        with app.test_request_context():
            cfg = dict(ldap_settings_service.effective_config(),
                       LDAP_ENABLED=True, LDAP_SERVER_URI="ldaps://db-server",
                       LDAP_USER_DN_TEMPLATE="uid={username},ou=people,dc=test",
                       LDAP_BIND_PASSWORD="db-pw", LDAP_TIMEOUT_SECONDS=5)
            ldap_settings_service.save(cfg)
            db.session.commit()
        with app.test_request_context():
            eff = ldap_settings_service.effective_config()
            assert eff["LDAP_ENABLED"] is True
            assert eff["LDAP_SERVER_URI"] == "ldaps://db-server"
            assert eff["LDAP_BIND_PASSWORD"] == "db-pw"
            assert ldap_settings_service.config_source() == "db"

    def test_bind_password_stored_encrypted(self, app, db):
        with app.test_request_context():
            cfg = dict(ldap_settings_service.effective_config(),
                       LDAP_ENABLED=False, LDAP_BIND_PASSWORD="hunter2hunter2",
                       LDAP_TIMEOUT_SECONDS=5)
            ldap_settings_service.save(cfg)
            db.session.commit()
            row = db.session.get(LdapSettings, 1)
            assert b"hunter2hunter2" not in (row.bind_password_enc or b"")
            assert ldap_settings_service.stored_bind_password() == "hunter2hunter2"

    def test_blank_password_keeps_stored(self, app, db):
        with app.test_request_context():
            base = dict(ldap_settings_service.effective_config(),
                        LDAP_ENABLED=False, LDAP_TIMEOUT_SECONDS=5)
            ldap_settings_service.save(dict(base, LDAP_BIND_PASSWORD="first-pw"))
            db.session.commit()
            ldap_settings_service.save(dict(base, LDAP_BIND_PASSWORD=""))
            db.session.commit()
            assert ldap_settings_service.stored_bind_password() == "first-pw"

    def test_reset_reverts_to_env(self, app, db):
        with app.test_request_context():
            cfg = dict(ldap_settings_service.effective_config(),
                       LDAP_ENABLED=False, LDAP_BIND_PASSWORD="",
                       LDAP_TIMEOUT_SECONDS=5)
            ldap_settings_service.save(cfg)
            db.session.commit()
            assert ldap_settings_service.config_source() == "db"
            ldap_settings_service.reset()
            db.session.commit()
            assert ldap_settings_service.config_source() == "env"


class TestValidation:
    def _cfg(self, **overrides):
        cfg = {
            "LDAP_ENABLED": True,
            "LDAP_SERVER_URI": "ldaps://ldap.test:636",
            "LDAP_USE_STARTTLS": False,
            "LDAP_TLS_VERIFY": True,
            "LDAP_ALLOW_PLAINTEXT": False,
            "LDAP_CA_CERT_FILE": "",
            "LDAP_CA_CERT_PEM": "",
            "LDAP_USER_DN_TEMPLATE": "uid={username},ou=people,dc=test",
            "LDAP_BIND_DN": "",
            "LDAP_BIND_PASSWORD": "",
            "LDAP_USER_SEARCH_BASE": "",
            "LDAP_USER_FILTER": "(uid={username})",
            "LDAP_ADMIN_GROUP_DN": "",
            "LDAP_REQUESTER_GROUP_DN": "",
            "LDAP_GROUP_MEMBER_ATTR": "memberOf",
            "LDAP_TIMEOUT_SECONDS": 5,
        }
        cfg.update(overrides)
        return cfg

    def test_valid_config_passes(self):
        assert ldap_settings_service.validate(self._cfg()) == []

    def test_disabled_skips_validation(self):
        assert ldap_settings_service.validate(
            self._cfg(LDAP_ENABLED=False, LDAP_SERVER_URI="")) == []

    def test_missing_uri(self):
        errors = ldap_settings_service.validate(self._cfg(LDAP_SERVER_URI=""))
        assert any("Server URI" in e for e in errors)

    def test_plaintext_refused(self):
        errors = ldap_settings_service.validate(
            self._cfg(LDAP_SERVER_URI="ldap://ldap.test"))
        assert any("cleartext" in e for e in errors)

    def test_plaintext_allowed_with_starttls(self):
        assert ldap_settings_service.validate(
            self._cfg(LDAP_SERVER_URI="ldap://ldap.test", LDAP_USE_STARTTLS=True)) == []

    def test_both_modes_rejected(self):
        errors = ldap_settings_service.validate(
            self._cfg(LDAP_USER_SEARCH_BASE="ou=people,dc=test",
                      LDAP_BIND_DN="cn=svc,dc=test"))
        assert any("not both" in e for e in errors)

    def test_neither_mode_rejected(self):
        errors = ldap_settings_service.validate(self._cfg(LDAP_USER_DN_TEMPLATE=""))
        assert any("direct bind" in e for e in errors)

    def test_template_needs_placeholder(self):
        errors = ldap_settings_service.validate(
            self._cfg(LDAP_USER_DN_TEMPLATE="uid=admin,ou=people,dc=test"))
        assert any("{username}" in e for e in errors)

    def test_search_mode_needs_bind_dn(self):
        errors = ldap_settings_service.validate(
            self._cfg(LDAP_USER_DN_TEMPLATE="",
                      LDAP_USER_SEARCH_BASE="ou=people,dc=test"))
        assert any("service account" in e for e in errors)


class TestRoutes:
    def test_requester_denied(self, auth_csr_requester):
        r = auth_csr_requester.get("/users/ldap")
        assert r.status_code == 302  # flash + redirect to dashboard

    def test_anonymous_denied(self, client, db):
        r = client.get("/users/ldap")
        assert r.status_code == 302
        assert "/auth/login" in r.headers["Location"]

    def test_get_renders(self, auth_admin):
        r = auth_admin.get("/users/ldap")
        assert r.status_code == 200
        assert b"LDAP Authentication" in r.data

    def test_save_persists_and_audits(self, app, auth_admin, db):
        r = auth_admin.post("/users/ldap", data=_base_form(),
                            follow_redirects=True)
        assert r.status_code == 200
        assert b"saved" in r.data.lower()
        with app.app_context():
            row = db.session.get(LdapSettings, 1)
            assert row is not None and row.enabled is True
            assert AuditLog.query.filter_by(action="update_ldap_settings").count() == 1

    def test_save_validation_error_not_persisted(self, app, auth_admin, db):
        r = auth_admin.post("/users/ldap",
                            data=_base_form(server_uri=""), follow_redirects=True)
        assert b"Server URI is required" in r.data
        with app.app_context():
            assert db.session.get(LdapSettings, 1) is None

    def test_bind_password_never_echoed(self, app, auth_admin, db):
        auth_admin.post("/users/ldap",
                        data=_base_form(bind_password="super-secret-bind-pw"),
                        follow_redirects=True)
        r = auth_admin.get("/users/ldap")
        assert b"super-secret-bind-pw" not in r.data

    def test_reset_route(self, app, auth_admin, db):
        auth_admin.post("/users/ldap", data=_base_form(), follow_redirects=True)
        r = auth_admin.post("/users/ldap/reset", follow_redirects=True)
        assert r.status_code == 200
        with app.app_context():
            assert db.session.get(LdapSettings, 1) is None
            assert AuditLog.query.filter_by(action="reset_ldap_settings").count() == 1


class TestTestConnection:
    def test_full_credentials_success(self, app, auth_admin, db, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", FakeConnection)
        r = auth_admin.post("/users/ldap", data=_base_form(
            action="test", test_username="alice", test_password="alice-pw"))
        assert b"Test succeeded" in r.data
        assert b"uid=alice,ou=people,dc=test" in r.data
        assert b"Mapped role:</strong> admin" in r.data  # from cert-admins group

    def test_bad_credentials_reported(self, app, auth_admin, db, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", FakeConnection)
        r = auth_admin.post("/users/ldap", data=_base_form(
            action="test", test_username="alice", test_password="wrong"))
        assert b"Test failed" in r.data
        assert b"rejected" in r.data

    def test_server_down_reported(self, app, auth_admin, db, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", _ldap_down)
        r = auth_admin.post("/users/ldap", data=_base_form(
            action="test", test_username="alice", test_password="alice-pw"))
        assert b"Test failed" in r.data
        assert b"unreachable" in r.data

    def test_nothing_saved_by_test(self, app, auth_admin, db, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", FakeConnection)
        auth_admin.post("/users/ldap", data=_base_form(
            action="test", test_username="alice", test_password="alice-pw"))
        with app.app_context():
            assert db.session.get(LdapSettings, 1) is None


class TestAuthIntegration:
    def test_login_uses_db_config(self, app, db, monkeypatch):
        """LDAP login works from a saved row even with env LDAP disabled."""
        monkeypatch.setitem(app.config, "LDAP_ENABLED", False)
        monkeypatch.setattr(ldap3, "Connection", FakeConnection)
        with app.test_request_context():
            cfg = dict(ldap_settings_service.effective_config(),
                       LDAP_ENABLED=True, LDAP_SERVER_URI="ldaps://ldap.test:636",
                       LDAP_USER_DN_TEMPLATE="uid={username},ou=people,dc=test",
                       LDAP_ADMIN_GROUP_DN="cn=cert-admins,ou=groups,dc=test",
                       LDAP_REQUESTER_GROUP_DN="cn=cert-requesters,ou=groups,dc=test",
                       LDAP_BIND_PASSWORD="", LDAP_TIMEOUT_SECONDS=5)
            ldap_settings_service.save(cfg)
            db.session.commit()
        with app.test_request_context():
            result = auth_service.authenticate("alice", "alice-pw")
            assert result.ok
            assert result.user.role == "admin"
            assert result.auth_method == "ldap"

    def test_row_disabled_blocks_ldap(self, app, db, monkeypatch):
        """A row with enabled=False turns LDAP off even if env enables it."""
        monkeypatch.setitem(app.config, "LDAP_ENABLED", True)
        monkeypatch.setitem(app.config, "LDAP_SERVER_URI", "ldaps://ldap.test:636")
        monkeypatch.setitem(app.config, "LDAP_USER_DN_TEMPLATE",
                            "uid={username},ou=people,dc=test")
        monkeypatch.setattr(ldap3, "Connection", FakeConnection)
        with app.test_request_context():
            cfg = dict(ldap_settings_service.effective_config(),
                       LDAP_ENABLED=False, LDAP_BIND_PASSWORD="",
                       LDAP_TIMEOUT_SECONDS=5)
            ldap_settings_service.save(cfg)
            db.session.commit()
        with app.test_request_context():
            result = auth_service.authenticate("alice", "alice-pw")
            assert not result.ok
