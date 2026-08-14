"""CSRFError handling: an expired session must not surface a raw 400.

The shared fixtures disable CSRF (conftest ``WTF_CSRF_ENABLED = False``), so
this module builds its own app with it enabled and drives the real forms,
extracting tokens from the rendered pages.
"""

import re

import pytest

from app import create_app
from app.extensions import db as _db
from app.models.user import User
from tests.conftest import TestConfig


class CSRFConfig(TestConfig):
    WTF_CSRF_ENABLED = True


@pytest.fixture(scope="module")
def csrf_app():
    return create_app(CSRFConfig)


@pytest.fixture
def csrf_client(csrf_app):
    with csrf_app.app_context():
        _db.create_all()
        user = User(username="csrfadmin", role="admin")
        user.set_password("adminpass")
        _db.session.add(user)
        _db.session.commit()
        yield csrf_app.test_client()
        _db.session.rollback()
        _db.drop_all()


def _get_csrf_token(client, path):
    page = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page)
    assert match, f"no csrf_token field found on {path}"
    return match.group(1)


def _login(client):
    token = _get_csrf_token(client, "/auth/login")
    response = client.post(
        "/auth/login",
        data={"username": "csrfadmin", "password": "adminpass", "csrf_token": token},
    )
    assert response.status_code == 302


def test_logout_with_expired_session_redirects_to_login(csrf_client):
    # No session at all (the cookie expired and was dropped): the POSTed form
    # has no matching server-side token. Must land on login, not a 400.
    response = csrf_client.post("/auth/logout", data={"csrf_token": "stale"})
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]

    follow = csrf_client.get(response.headers["Location"])
    assert b"session has expired" in follow.data


def test_login_form_after_session_expiry_redirects_not_400(csrf_client):
    # A login page left open past the session lifetime submits a token the
    # fresh session can't verify — same handler, same friendly redirect.
    response = csrf_client.post(
        "/auth/login",
        data={"username": "csrfadmin", "password": "adminpass", "csrf_token": "stale"},
    )
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_authenticated_bad_token_redirects_back_with_flash(csrf_client):
    _login(csrf_client)
    response = csrf_client.post(
        "/auth/logout",
        data={"csrf_token": "tampered"},
        headers={"Referer": "http://localhost/dashboard/"},
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard/")

    follow = csrf_client.get("/")
    assert b"security token was missing or expired" in follow.data
    # The logout must NOT have executed — the session is still authenticated
    # (a dashboard GET serves the page rather than bouncing to login).
    assert csrf_client.get("/").status_code == 200


def test_authenticated_bad_token_ignores_cross_host_referer(csrf_client):
    _login(csrf_client)
    response = csrf_client.post(
        "/auth/logout",
        data={"csrf_token": "tampered"},
        headers={"Referer": "http://evil.example/phish"},
    )
    assert response.status_code == 302
    assert "evil.example" not in response.headers["Location"]


def test_json_client_gets_json_400(csrf_client):
    response = csrf_client.post(
        "/auth/logout",
        data={"csrf_token": "stale"},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 400
    assert response.is_json
    assert "error" in response.get_json()


def test_valid_logout_still_works(csrf_client):
    _login(csrf_client)
    token = _get_csrf_token(csrf_client, "/")
    response = csrf_client.post("/auth/logout", data={"csrf_token": token})
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]
