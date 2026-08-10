"""D1: brute-force login lockout for local accounts."""
from datetime import datetime, timedelta, timezone

import pytest

from app.services import auth_service
from app.models.user import User


@pytest.fixture(autouse=True)
def _restore_lockout_cfg(app):
    saved = (app.config.get("LOGIN_LOCKOUT_THRESHOLD"),
             app.config.get("LOGIN_LOCKOUT_MINUTES"))
    yield
    app.config["LOGIN_LOCKOUT_THRESHOLD"], app.config["LOGIN_LOCKOUT_MINUTES"] = saved


def _mk_user(db, username, password="rightpass"):
    # csr_requester, not admin: DoS-2 exempts the *last active admin* from hard
    # lockout, so these lockout-mechanics tests use a non-admin to exercise the
    # lock path itself (locking is role-agnostic).
    u = User(username=username, role="csr_requester", auth_source="local")
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    return u


def test_lockout_after_threshold(app, db):
    with app.app_context():
        app.config["LOGIN_LOCKOUT_THRESHOLD"] = 3
        app.config["LOGIN_LOCKOUT_MINUTES"] = 15
        u = _mk_user(db, "bob")
        for _ in range(3):
            assert auth_service.authenticate("bob", "wrong").reason == auth_service.REASON_INVALID
        # Locked now — even the correct password is refused.
        r = auth_service.authenticate("bob", "rightpass")
        assert not r.ok and r.reason == auth_service.REASON_LOCKED
        db.session.refresh(u)
        assert u.locked_until is not None


def test_success_resets_counter(app, db):
    with app.app_context():
        app.config["LOGIN_LOCKOUT_THRESHOLD"] = 5
        u = _mk_user(db, "alice")
        auth_service.authenticate("alice", "wrong")
        auth_service.authenticate("alice", "wrong")
        db.session.refresh(u)
        assert u.failed_login_count == 2
        assert auth_service.authenticate("alice", "rightpass").ok
        db.session.refresh(u)
        assert u.failed_login_count == 0 and u.locked_until is None


def test_expired_lock_allows_login(app, db):
    with app.app_context():
        u = _mk_user(db, "carol")
        u.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)  # in the past
        db.session.commit()
        assert auth_service.authenticate("carol", "rightpass").ok


def test_threshold_zero_disables_lockout(app, db):
    with app.app_context():
        app.config["LOGIN_LOCKOUT_THRESHOLD"] = 0
        u = _mk_user(db, "dave")
        for _ in range(10):
            auth_service.authenticate("dave", "wrong")
        db.session.refresh(u)
        assert u.locked_until is None
        assert auth_service.authenticate("dave", "rightpass").ok


def test_basic_auth_shares_lockout(app, db):
    with app.app_context():
        app.config["LOGIN_LOCKOUT_THRESHOLD"] = 2
        _mk_user(db, "eve")
        # Basic Auth goes through authenticate() on cache miss -> same lockout.
        auth_service.authenticate_basic("eve", "wrong")
        auth_service.authenticate_basic("eve", "wrong")
        assert auth_service.authenticate_basic("eve", "rightpass").reason == auth_service.REASON_LOCKED
