"""Forced password change on first login + self-service change-password."""

import pytest

from app.models.user import User


@pytest.fixture
def must_change_admin(db):
    u = User(username="bootstrapadmin", role="admin")
    u.set_password("seedpass123456")
    u.must_change_password = True
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, username, password):
    return client.post(
        "/auth/login", data={"username": username, "password": password}
    )


def test_login_redirects_to_change_password_when_flagged(client, must_change_admin):
    resp = _login(client, "bootstrapadmin", "seedpass123456")
    assert resp.status_code == 302
    assert "/auth/change-password" in resp.headers["Location"]


def test_guard_blocks_other_pages_until_changed(client, must_change_admin):
    _login(client, "bootstrapadmin", "seedpass123456")
    resp = client.get("/ca/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/auth/change-password" in resp.headers["Location"]


def test_logout_still_allowed_while_must_change(client, must_change_admin):
    _login(client, "bootstrapadmin", "seedpass123456")
    resp = client.post("/auth/logout", follow_redirects=False)
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]


def test_change_password_success_clears_flag_and_unblocks(client, must_change_admin, db):
    _login(client, "bootstrapadmin", "seedpass123456")
    resp = client.post(
        "/auth/change-password",
        data={
            "current_password": "seedpass123456",
            "new_password": "a-brand-new-strong-password",
            "confirm_password": "a-brand-new-strong-password",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/auth/change-password" not in resp.headers["Location"]
    u = db.session.get(User, must_change_admin.id)
    assert u.must_change_password is False
    assert u.check_password("a-brand-new-strong-password")
    # guard no longer redirects
    assert client.get("/ca/").status_code == 200


def test_change_password_wrong_current(client, must_change_admin, db):
    _login(client, "bootstrapadmin", "seedpass123456")
    resp = client.post(
        "/auth/change-password",
        data={
            "current_password": "not-the-password",
            "new_password": "a-brand-new-strong-password",
            "confirm_password": "a-brand-new-strong-password",
        },
    )
    assert resp.status_code == 200
    assert b"Current password is incorrect" in resp.data
    assert db.session.get(User, must_change_admin.id).must_change_password is True


def test_change_password_mismatch(client, must_change_admin):
    _login(client, "bootstrapadmin", "seedpass123456")
    resp = client.post(
        "/auth/change-password",
        data={
            "current_password": "seedpass123456",
            "new_password": "a-brand-new-strong-password",
            "confirm_password": "totally-different-value",
        },
    )
    assert b"do not match" in resp.data


def test_change_password_too_short(client, must_change_admin):
    _login(client, "bootstrapadmin", "seedpass123456")
    resp = client.post(
        "/auth/change-password",
        data={
            "current_password": "seedpass123456",
            "new_password": "short",
            "confirm_password": "short",
        },
    )
    assert b"at least" in resp.data


def test_change_password_same_as_current_rejected(client, must_change_admin):
    _login(client, "bootstrapadmin", "seedpass123456")
    resp = client.post(
        "/auth/change-password",
        data={
            "current_password": "seedpass123456",
            "new_password": "seedpass123456",
            "confirm_password": "seedpass123456",
        },
    )
    assert b"different from the current" in resp.data


def test_self_service_change_for_unflagged_admin(auth_admin, admin_user, db):
    resp = auth_admin.post(
        "/auth/change-password",
        data={
            "current_password": "adminpass",
            "new_password": "another-strong-password",
            "confirm_password": "another-strong-password",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert db.session.get(User, admin_user.id).check_password("another-strong-password")


def test_change_password_page_renders(auth_admin):
    resp = auth_admin.get("/auth/change-password")
    assert resp.status_code == 200
    assert b"Change Password" in resp.data


def test_bootstrap_admin_is_flagged():
    # _create_default_admin sets the flag on the seeded admin.
    from app import create_app
    from tests.conftest import TestConfig

    class SeedConfig(TestConfig):
        ADMIN_USERNAME = "seedadmin"
        ADMIN_PASSWORD = "seed-admin-password"

    app = create_app(SeedConfig)
    with app.app_context():
        seeded = User.query.filter_by(username="seedadmin").first()
        assert seeded is not None
        assert seeded.must_change_password is True
