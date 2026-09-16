"""F13: TOTP second factor + session versioning (G6-4/G6-5).

RFC 6238 vectors, window/replay, the two-step login, recovery codes (single
use), lockout on 2FA failures, enrolment/disable/regenerate, forced admin
enrolment, Basic-Auth refusal (API tokens still work), session invalidation
on password change / admin reset / 2FA change, admin + CLI reset, migration.
"""
import base64
import json
import time
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services import api_token_service, auth_service, crypto_utils, passphrase_service, totp_service

PASSPHRASE = "test-passphrase"
SECRET = "JBSWY3DPEHPK3PXP"                      # any base32 secret
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()   # RFC 6238 appendix B
JSON = {"Accept": "application/json"}


@pytest.fixture(autouse=True)
def _restore_cfg(app):
    saved = {k: app.config.get(k) for k in ("LOGIN_LOCKOUT_THRESHOLD", "LOGIN_LOCKOUT_MINUTES", "REQUIRE_2FA_FOR_ADMINS")}
    yield
    app.config.update(saved)


def _enable(user, secret=SECRET):
    codes, hashes = totp_service.generate_recovery_codes()
    user.totp_secret_enc = crypto_utils.encrypt_secret(secret, PASSPHRASE)
    user.totp_enabled = True
    user.totp_confirmed_at = datetime.now(timezone.utc)
    user.recovery_codes_json = json.dumps(hashes)
    _db.session.commit()
    return codes


def _code(secret=SECRET, offset=0):
    return totp_service.hotp(secret, totp_service.current_step() + offset)


def _login(client, username, password):
    return client.post("/auth/login", data={"username": username, "password": password})


def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode(), **JSON}


def _logged_in(client):
    return client.get("/").status_code == 200


def _fresh(uid):
    """Requests commit in their own session; re-read the row."""
    _db.session.expire_all()
    return _db.session.get(User, uid)


class TestAlgorithm:
    @pytest.mark.parametrize("t,expected", [(59, "287082"), (1111111109, "081804"), (1111111111, "050471"),
                                            (1234567890, "005924"), (2000000000, "279037"), (20000000000, "353130")])
    def test_rfc6238_vectors(self, t, expected):
        assert totp_service.totp(RFC_SECRET, now=t) == expected

    def test_window_and_replay(self):
        now = 1_700_000_000
        step = totp_service.current_step(now)
        for off in (-1, 0, 1):
            assert totp_service.verify(RFC_SECRET, totp_service.hotp(RFC_SECRET, step + off), now=now) == step + off
        for off in (-2, 2):
            assert totp_service.verify(RFC_SECRET, totp_service.hotp(RFC_SECRET, step + off), now=now) is None
        # a code at or before the last accepted step is a replay
        assert totp_service.verify(RFC_SECRET, totp_service.hotp(RFC_SECRET, step), last_step=step, now=now) is None
        assert totp_service.verify(RFC_SECRET, totp_service.hotp(RFC_SECRET, step - 1), last_step=step, now=now) is None
        assert totp_service.verify(RFC_SECRET, totp_service.hotp(RFC_SECRET, step + 1), last_step=step, now=now) == step + 1
        for bad in ("", "12345", "1234567", "abcdef", None):
            assert totp_service.verify(RFC_SECRET, bad, now=now) is None
        # spaces / lowercase secrets are tolerated (manual entry)
        assert totp_service.verify(RFC_SECRET.lower(), "  " + totp_service.hotp(RFC_SECRET, step) + " ", now=now) == step

    def test_secret_and_url(self):
        s = totp_service.generate_secret()
        assert len(s) == 32 and s == s.upper() and totp_service.generate_secret() != s
        url = totp_service.otpauth_url("Chancery Lab", "al ice", s)
        assert url.startswith("otpauth://totp/Chancery%20Lab%3Aal%20ice?secret=" + s) and "issuer=Chancery%20Lab" in url
        svg = totp_service.qr_svg(url)
        assert svg is None or svg.lstrip().startswith("<svg")

    def test_recovery_codes(self):
        codes, hashes = totp_service.generate_recovery_codes()
        assert len(codes) == 8 == len(set(codes)) and all(len(c) == 11 and c[5] == "-" for c in codes)
        assert all(h.startswith(("scrypt:", "pbkdf2:")) for h in hashes)
        remaining, ok = totp_service.consume_recovery_code(hashes, codes[3].lower().replace("-", " "))
        assert ok and len(remaining) == 7
        assert totp_service.consume_recovery_code(remaining, codes[3]) == (remaining, False)
        assert totp_service.consume_recovery_code(remaining, "nope") == (remaining, False)


class TestLoginFlow:
    def test_password_alone_does_not_log_in(self, app, client, admin_user):
        _enable(admin_user)
        r = _login(client, "testadmin", "adminpass")
        assert r.status_code == 302 and r.headers["Location"].endswith("/auth/2fa")
        assert not _logged_in(client)
        assert AuditLog.query.filter_by(action="login_success").count() == 0
        with client.session_transaction() as sess:
            assert sess["pre_2fa"]["uid"] == admin_user.id and "_user_id" not in sess

    def test_totp_completes_login_and_stamps_session(self, app, client, admin_user):
        _enable(admin_user)
        _login(client, "testadmin", "adminpass")
        r = client.post("/auth/2fa", data={"code": _code()})
        assert r.status_code == 302 and r.headers["Location"] == "/"
        assert _logged_in(client)
        with client.session_transaction() as sess:
            assert sess["sv"] == admin_user.session_version and "pre_2fa" not in sess
        row = AuditLog.query.filter_by(action="login_success").one()
        assert json.loads(row.details)["second_factor"] == "totp"
        assert _fresh(admin_user.id).totp_last_step == totp_service.current_step() or \
            _fresh(admin_user.id).totp_last_step == totp_service.current_step() - 1

    def test_next_is_honoured_after_second_factor(self, app, client, admin_user):
        _enable(admin_user)
        client.post("/auth/login?next=/ca/", data={"username": "testadmin", "password": "adminpass"})
        r = client.post("/auth/2fa", data={"code": _code()})
        assert r.headers["Location"].endswith("/ca/")

    def test_replay_refused(self, app, client, admin_user):
        _enable(admin_user)
        code = _code()
        _login(client, "testadmin", "adminpass")
        client.post("/auth/2fa", data={"code": code})
        client.post("/auth/logout")
        _login(client, "testadmin", "adminpass")
        r = client.post("/auth/2fa", data={"code": code})
        assert r.status_code == 200 and not _logged_in(client)
        assert AuditLog.query.filter_by(action="login_2fa_failed").count() == 1
        # the next step's code is fine
        r = client.post("/auth/2fa", data={"code": _code(offset=1)})
        assert r.status_code == 302 and _logged_in(client)

    def test_wrong_code_counts_toward_lockout(self, app, client, csr_requester):
        app.config["LOGIN_LOCKOUT_THRESHOLD"] = 3
        _enable(csr_requester)
        _login(client, "testrequester", "requesterpass")
        for _ in range(3):
            client.post("/auth/2fa", data={"code": "000000"})
        u = _fresh(csr_requester.id)
        assert u.locked_until is not None   # D1 resets the counter when the lock is set
        assert AuditLog.query.filter_by(action="login_2fa_failed").count() == 3
        r = client.post("/auth/2fa", data={"code": _code()})
        assert r.status_code == 200 and b"Too many failed attempts" in r.data and not _logged_in(client)
        # and the password step is locked too
        assert auth_service.authenticate("testrequester", "requesterpass").reason == auth_service.REASON_LOCKED

    def test_recovery_code_is_single_use(self, app, client, admin_user):
        codes = _enable(admin_user)
        _login(client, "testadmin", "adminpass")
        r = client.post("/auth/2fa", data={"code": codes[0]})
        assert r.status_code == 302 and _logged_in(client)
        assert json.loads(AuditLog.query.filter_by(action="login_success").one().details)["second_factor"] == "recovery"
        assert len(_fresh(admin_user.id).recovery_codes) == 7
        client.post("/auth/logout")
        _login(client, "testadmin", "adminpass")
        r = client.post("/auth/2fa", data={"code": codes[0]})
        assert r.status_code == 200 and not _logged_in(client)
        r = client.post("/auth/2fa", data={"code": codes[1]})
        assert r.status_code == 302 and _logged_in(client)

    def test_pending_step_expires_and_needs_password_first(self, app, client, admin_user):
        _enable(admin_user)
        r = client.get("/auth/2fa")
        assert r.status_code == 302 and r.headers["Location"].endswith("/auth/login")
        _login(client, "testadmin", "adminpass")
        with client.session_transaction() as sess:
            sess["pre_2fa"]["exp"] = int(time.time()) - 1
        r = client.post("/auth/2fa", data={"code": _code()})
        assert r.status_code == 302 and r.headers["Location"].endswith("/auth/login") and not _logged_in(client)

    def test_deactivated_between_steps(self, app, client, admin_user, csr_requester):
        _enable(csr_requester)
        _login(client, "testrequester", "requesterpass")
        csr_requester.is_active_user = False
        _db.session.commit()
        r = client.post("/auth/2fa", data={"code": _code()})
        assert r.status_code == 302 and r.headers["Location"].endswith("/auth/login") and not _logged_in(client)

    def test_user_without_totp_logs_in_directly(self, app, client, admin_user):
        r = _login(client, "testadmin", "adminpass")
        assert r.headers["Location"] == "/" and _logged_in(client)
        with client.session_transaction() as sess:
            assert sess["sv"] == 1


class TestEnrolment:
    def test_setup_confirm_shows_codes_once(self, app, auth_admin, admin_user):
        r = auth_admin.get("/auth/2fa/setup")
        assert r.status_code == 200 and b"otpauth://totp/Chancery%3Atestadmin" in r.data
        with auth_admin.session_transaction() as sess:
            secret = sess["totp_setup_secret"]
        assert secret.encode() in r.data
        # a wrong code keeps the same pending secret
        r = auth_admin.post("/auth/2fa/setup", data={"code": "000000"})
        assert r.status_code == 200 and b"not accepted" in r.data and secret.encode() in r.data
        assert not _fresh(admin_user.id).totp_enabled
        r = auth_admin.post("/auth/2fa/setup", data={"code": _code(secret)})
        assert r.status_code == 200 and b"Recovery codes" in r.data
        u = _fresh(admin_user.id)
        assert u.totp_enabled and u.totp_confirmed_at and u.session_version == 2 and len(u.recovery_codes) == 8
        assert crypto_utils.decrypt_secret(u.totp_secret_enc, PASSPHRASE) == secret
        assert secret.encode() not in auth_admin.get("/auth/2fa/setup").data   # not shown again
        assert AuditLog.query.filter_by(action="totp_enabled", target_id=u.id).count() == 1
        assert _logged_in(auth_admin)   # the enrolling session survives the version bump
        assert "totp_secret_enc" not in u.to_dict() and u.to_dict()["totp_enabled"] is True

    def test_enrolment_logs_out_other_sessions(self, app, client, admin_user):
        other = app.test_client()
        _login(other, "testadmin", "adminpass")
        _login(client, "testadmin", "adminpass")
        assert _logged_in(other)
        client.get("/auth/2fa/setup")
        with client.session_transaction() as sess:
            secret = sess["totp_setup_secret"]
        client.post("/auth/2fa/setup", data={"code": _code(secret)})
        assert _logged_in(client) and not _logged_in(other)

    def test_disable_needs_password_and_code(self, app, auth_admin, admin_user):
        _enable(admin_user)
        r = auth_admin.post("/auth/2fa/disable", data={"password": "wrong", "code": _code()}, follow_redirects=True)
        assert b"Current password is incorrect" in r.data and _fresh(admin_user.id).totp_enabled
        r = auth_admin.post("/auth/2fa/disable", data={"password": "adminpass", "code": "000000"}, follow_redirects=True)
        assert b"not accepted" in r.data and _fresh(admin_user.id).totp_enabled
        r = auth_admin.post("/auth/2fa/disable", data={"password": "adminpass", "code": _code()}, follow_redirects=True)
        assert b"is disabled" in r.data
        u = _fresh(admin_user.id)
        assert not u.totp_enabled and u.totp_secret_enc is None and u.recovery_codes == [] and u.totp_last_step is None
        assert AuditLog.query.filter_by(action="totp_disabled").count() == 1 and _logged_in(auth_admin)

    def test_regenerate_recovery_codes(self, app, auth_admin, admin_user):
        old = _enable(admin_user)
        r = auth_admin.post("/auth/2fa/recovery-codes", data={"code": "000000"}, follow_redirects=True)
        assert b"not accepted" in r.data
        r = auth_admin.post("/auth/2fa/recovery-codes", data={"code": _code()})
        assert r.status_code == 200 and b"Recovery codes" in r.data and old[0].encode() not in r.data
        hashes = _fresh(admin_user.id).recovery_codes
        assert len(hashes) == 8 and not totp_service.consume_recovery_code(hashes, old[0])[1]
        assert AuditLog.query.filter_by(action="recovery_codes_regenerated").count() == 1

    def test_forced_admin_enrolment(self, app, client, admin_user, csr_requester):
        app.config["REQUIRE_2FA_FOR_ADMINS"] = True
        _login(client, "testadmin", "adminpass")
        r = client.get("/ca/")
        assert r.status_code == 302 and r.headers["Location"].endswith("/auth/2fa/setup")
        r = client.get("/auth/2fa/setup")
        assert r.status_code == 200 and b"Administrators on this Chancery must use a second factor" in r.data
        assert client.post("/auth/logout").status_code == 302   # logout stays reachable
        # requesters are not forced
        _login(client, "testrequester", "requesterpass")
        assert client.get("/").status_code == 200
        # once enrolled the admin is through
        other = app.test_client()
        _login(other, "testadmin", "adminpass")
        other.get("/auth/2fa/setup")
        with other.session_transaction() as sess:
            secret = sess["totp_setup_secret"]
        other.post("/auth/2fa/setup", data={"code": _code(secret)})
        assert other.get("/ca/").status_code == 200


class TestProgrammaticAccess:
    def test_basic_auth_refused_api_token_works(self, app, client, admin_user):
        assert client.get("/ca/", headers=_basic("testadmin", "adminpass")).status_code == 200
        _enable(admin_user)
        r = client.get("/ca/", headers=_basic("testadmin", "adminpass"))
        assert r.status_code == 403 and "API token" in r.get_json()["error"]
        r = client.get("/ca/", headers=_basic("testadmin", "wrong"))
        assert r.status_code == 401
        plaintext, _row = api_token_service.create(admin_user, "script", ["read"], 30)
        _db.session.commit()
        assert client.get("/ca/", headers={"Authorization": f"Bearer {plaintext}", **JSON}).status_code == 200


class TestSessionVersioning:
    def test_password_change_drops_other_sessions(self, app, client, admin_user):
        other = app.test_client()
        _login(other, "testadmin", "adminpass")
        _login(client, "testadmin", "adminpass")
        r = client.post("/auth/change-password", data={"current_password": "adminpass",
                                                       "new_password": "a-much-longer-password", "confirm_password": "a-much-longer-password"})
        assert r.status_code == 302
        assert _logged_in(client) and not _logged_in(other)
        assert _fresh(admin_user.id).session_version == 2

    def test_admin_reset_password_drops_sessions_and_basic_cache(self, app, auth_admin, admin_user, csr_requester):
        victim = app.test_client()
        _login(victim, "testrequester", "requesterpass")
        assert _logged_in(victim)
        # warm the Basic-Auth cache with the old password
        assert victim.get("/csr/", headers=_basic("testrequester", "requesterpass")).status_code == 200
        assert "testrequester" in app.basic_auth_cache._entries
        auth_admin.post(f"/users/{csr_requester.id}/reset-password", data={"password": "brand-new-password-1"})
        assert not _logged_in(victim)
        assert "testrequester" not in app.basic_auth_cache._entries
        assert victim.get("/csr/", headers=_basic("testrequester", "requesterpass")).status_code == 401

    def test_bump_helper(self, app, admin_user):
        app.basic_auth_cache.put("testadmin", "adminpass", admin_user.id, "local")
        auth_service.bump_session_version(admin_user)
        _db.session.commit()
        assert admin_user.session_version == 2 and app.basic_auth_cache.get("testadmin", "adminpass") is None


class TestAdminReset:
    def test_route(self, app, auth_admin, admin_user, csr_requester):
        r = auth_admin.post(f"/users/{csr_requester.id}/reset-2fa", headers=JSON)
        assert r.status_code == 409
        _enable(csr_requester)
        victim = app.test_client()
        _login(victim, "testrequester", "requesterpass")
        victim.post("/auth/2fa", data={"code": _code()})
        assert _logged_in(victim)
        r = auth_admin.get(f"/users/{csr_requester.id}/edit")
        assert b"Reset two-factor" in r.data
        r = auth_admin.post(f"/users/{csr_requester.id}/reset-2fa", headers=JSON)
        assert r.status_code == 200 and r.get_json()["totp_enabled"] is False
        u = _fresh(csr_requester.id)
        assert not u.totp_enabled and u.totp_secret_enc is None and u.session_version == 2
        assert not _logged_in(victim)
        assert json.loads(AuditLog.query.filter_by(action="totp_reset", target_id=u.id).one().details)["username"] == "testrequester"
        assert auth_admin.post("/users/999/reset-2fa", headers=JSON).status_code == 404

    def test_requester_cannot_reset(self, app, auth_csr_requester, admin_user):
        _enable(admin_user)
        r = auth_csr_requester.post(f"/users/{admin_user.id}/reset-2fa", headers=JSON)
        assert r.status_code == 403 and _fresh(admin_user.id).totp_enabled

    def test_cli(self, app, admin_user):
        runner = app.test_cli_runner()
        r = runner.invoke(args=["users", "reset-2fa", "testadmin"])
        assert r.exit_code == 0 and "not enabled" in r.output
        _enable(admin_user)
        r = runner.invoke(args=["users", "reset-2fa", "testadmin"])
        assert r.exit_code == 0 and "Cleared" in r.output, r.output
        u = _fresh(admin_user.id)
        assert not u.totp_enabled and u.session_version == 2
        row = AuditLog.query.filter_by(action="totp_reset").one()
        assert row.username == "cli"
        assert runner.invoke(args=["users", "reset-2fa", "nobody"]).exit_code != 0


class TestSchemaAndRegistry:
    def test_registry_has_totp_secret(self):
        assert ("users", "totp_secret_enc") in {(m.__tablename__, c) for m, _a, c, _k in passphrase_service.registered()}

    def test_migration_adds_columns(self, app, db):
        from app import _migrate_schema
        for col in ("totp_secret_enc", "totp_enabled", "totp_confirmed_at", "totp_last_step",
                    "recovery_codes_json", "session_version"):
            db.session.execute(text(f"ALTER TABLE users DROP COLUMN {col}"))
        db.session.commit()
        _migrate_schema()
        cols = {r[1] for r in db.session.execute(text("PRAGMA table_info(users)"))}
        assert {"totp_secret_enc", "totp_enabled", "totp_confirmed_at", "totp_last_step",
                "recovery_codes_json", "session_version"} <= cols
        u = User(username="legacy", role="admin")
        u.set_password("legacy-password-1")
        db.session.add(u)
        db.session.commit()
        assert db.session.get(User, u.id).session_version == 1 and not db.session.get(User, u.id).totp_enabled
