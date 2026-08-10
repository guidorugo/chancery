"""Batch 3 hardening: AUTH-2 (no lockout/username oracle), TMPL-3 (logout is
POST+CSRF), PKI-6 (intermediate honours the parent pathLenConstraint)."""

from datetime import datetime, timedelta, timezone

import pytest

from app.services import ca_service
from app.models.user import User


# ---- AUTH-2: locked and invalid logins look identical ---------------------

def test_auth2_locked_and_invalid_are_indistinguishable(app, client, db):
    with app.app_context():
        u = User(username="lockme", role="csr_requester")
        u.set_password("rightpass12345")
        u.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        db.session.add(u)
        db.session.commit()

    # Correct password but locked → generic message, NOT a distinct "locked" one.
    r_locked = client.post("/auth/login",
                           data={"username": "lockme", "password": "rightpass12345"},
                           follow_redirects=True)
    assert b"temporarily locked" not in r_locked.data
    assert b"Invalid username or password" in r_locked.data

    # Unknown username → the same generic message.
    r_invalid = client.post("/auth/login",
                            data={"username": "ghost", "password": "whatever"},
                            follow_redirects=True)
    assert b"Invalid username or password" in r_invalid.data


# ---- TMPL-3: logout is POST-only and CSRF-protected -----------------------

def test_tmpl3_logout_is_post_only(auth_admin):
    assert auth_admin.get("/auth/logout").status_code == 405
    r = auth_admin.post("/auth/logout", follow_redirects=False)
    assert r.status_code == 302
    assert "/auth/login" in r.headers["Location"]


def test_tmpl3_navbar_renders_logout_form(auth_admin):
    r = auth_admin.get("/")
    assert b'action="/auth/logout"' in r.data      # a POST form, not a GET link


# ---- PKI-6: parent pathLenConstraint is honoured --------------------------

def _root(name, path_length_col):
    ca = ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name}, key_type="RSA", key_size=2048,
        validity_days=3650, passphrase="test-passphrase")
    ca.path_length = path_length_col   # drive the guard off the stored constraint
    return ca


def test_pki6_pathlen_zero_parent_cannot_issue_subca(app, db):
    from app.extensions import db as _db
    with app.app_context():
        parent = _root("Path0", 0)
        _db.session.commit()
        with pytest.raises(ValueError, match="path length"):
            ca_service.create_intermediate_ca(
                name="child0", parent_ca=parent, subject_attrs={"CN": "child0"},
                key_type="RSA", key_size=2048, validity_days=1825,
                passphrase="test-passphrase")


def test_pki6_child_pathlen_clamped_to_parent(app, db):
    from app.extensions import db as _db
    with app.app_context():
        parent = _root("Path1", 1)
        _db.session.commit()
        child = ca_service.create_intermediate_ca(
            name="child1", parent_ca=parent, subject_attrs={"CN": "child1"},
            key_type="RSA", key_size=2048, validity_days=1825,
            passphrase="test-passphrase", path_length=5)   # over-large request
        assert child.path_length == 0                      # clamped to parent(1) - 1
