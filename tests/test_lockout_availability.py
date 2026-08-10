"""DoS-2 / AUTH-4: the sole admin is never hard-locked, and lockouts can be
cleared via password reset, reactivation, and `flask users unlock`."""

from datetime import datetime, timedelta, timezone

from app.services import auth_service
from app.models.user import User


def _locked_future():
    return datetime.now(timezone.utc) + timedelta(minutes=15)


# ---- DoS-2 ----------------------------------------------------------------

def test_dos2_last_admin_is_never_locked(app, db):
    with app.app_context():
        User.query.filter_by(role="admin").delete()   # deterministic: exactly one admin
        admin = User(username="soleadmin", role="admin")
        admin.set_password("adminpass1234")
        db.session.add(admin)
        db.session.commit()
        for _ in range(8):                       # well past the default threshold of 5
            auth_service.authenticate("soleadmin", "wrong-password")
        db.session.refresh(admin)
        assert admin.locked_until is None        # sole admin stays reachable


def test_dos2_non_last_admin_still_locks(app, db):
    with app.app_context():
        User.query.filter_by(role="admin").delete()   # start from a known admin set
        a1 = User(username="admin1", role="admin"); a1.set_password("adminpass1234")
        a2 = User(username="admin2", role="admin"); a2.set_password("adminpass1234")
        db.session.add_all([a1, a2])
        db.session.commit()
        for _ in range(6):
            auth_service.authenticate("admin1", "wrong-password")
        db.session.refresh(a1)
        assert a1.locked_until is not None       # not the last admin -> locked


def test_dos2_non_admin_still_locks(app, db):
    with app.app_context():
        u = User(username="req", role="csr_requester"); u.set_password("reqpass123456")
        db.session.add(u)
        db.session.commit()
        for _ in range(6):
            auth_service.authenticate("req", "wrong-password")
        db.session.refresh(u)
        assert u.locked_until is not None


# ---- AUTH-4 ---------------------------------------------------------------

def test_auth4_reset_password_clears_lockout(app, auth_admin, db):
    with app.app_context():
        u = User(username="lockeduser", role="csr_requester")
        u.set_password("oldpass123456")
        u.locked_until = _locked_future()
        u.failed_login_count = 3
        db.session.add(u)
        db.session.commit()
        uid = u.id
    auth_admin.post(f"/users/{uid}/reset-password", data={"password": "newpass1234567"})
    with app.app_context():
        u = db.session.get(User, uid)
        assert u.locked_until is None
        assert u.failed_login_count == 0


def test_auth4_reactivation_clears_lockout(app, auth_admin, db):
    with app.app_context():
        u = User(username="reactme", role="csr_requester", is_active_user=False)
        u.set_password("pass1234567890")
        u.locked_until = _locked_future()
        db.session.add(u)
        db.session.commit()
        uid = u.id
    auth_admin.post(f"/users/{uid}/toggle-active")   # reactivates
    with app.app_context():
        u = db.session.get(User, uid)
        assert u.is_active_user is True
        assert u.locked_until is None


def test_auth4_cli_unlock(app, db):
    with app.app_context():
        u = User(username="clilocked", role="csr_requester")
        u.set_password("pass1234567890")
        u.locked_until = _locked_future()
        u.failed_login_count = 5
        db.session.add(u)
        db.session.commit()
    result = app.test_cli_runner().invoke(args=["users", "unlock", "clilocked"])
    assert result.exit_code == 0
    with app.app_context():
        u = User.query.filter_by(username="clilocked").first()
        assert u.locked_until is None
        assert u.failed_login_count == 0


def test_auth4_cli_unlock_unknown_user_errors(app, db):
    result = app.test_cli_runner().invoke(args=["users", "unlock", "ghost"])
    assert result.exit_code != 0
