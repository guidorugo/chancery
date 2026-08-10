"""API-4/CORE-6 (JSON-aware 401/403/404/405/500), API-3 (Basic-Auth CSRF
exemption withheld cross-site), AUTH-3 (Basic Auth blocked while a password
change is forced)."""

import base64

from app.models.user import User

JSON = {"Accept": "application/json"}
HTML = {"Accept": "text/html"}


def _basic(username, password):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


# ---- API-4 / CORE-6 -------------------------------------------------------

def test_api4_forbidden_is_json_for_json_client(auth_csr_requester):
    # A session csr_requester hitting an admin route with Accept: json now gets
    # a JSON 403 (previously an HTML redirect, since it wasn't Basic Auth).
    r = auth_csr_requester.get("/users/", headers=JSON)
    assert r.status_code == 403 and r.is_json


def test_api4_unauthorized_is_json_for_json_client(client):
    r = client.get("/ca/", headers=JSON)
    assert r.status_code == 401 and r.is_json


def test_api4_unauthorized_redirects_browser(client):
    r = client.get("/ca/", headers=HTML, follow_redirects=False)
    assert r.status_code == 302        # browser still redirected to login


def test_api4_routing_404_json_vs_html(auth_admin):
    assert auth_admin.get("/no-such-path", headers=JSON).is_json
    assert auth_admin.get("/no-such-path", headers=JSON).status_code == 404
    html = auth_admin.get("/no-such-path", headers=HTML)
    assert html.status_code == 404 and "text/html" in html.content_type


def test_api4_405_is_json(auth_admin):
    r = auth_admin.get("/auth/logout", headers=JSON)   # POST-only route
    assert r.status_code == 405 and r.is_json


# ---- AUTH-3 ---------------------------------------------------------------

def test_auth3_basic_auth_blocked_while_password_change_forced(app, client, db):
    with app.app_context():
        u = User(username="mustchg", role="admin")
        u.set_password("seedpass123456")
        u.must_change_password = True
        db.session.add(u)
        db.session.commit()
    r = client.get("/ca/", headers=_basic("mustchg", "seedpass123456"))
    assert r.status_code == 403
    assert "change" in r.get_json()["error"].lower()


# ---- API-3 ----------------------------------------------------------------

def test_api3_crosssite_basic_auth_is_not_csrf_exempt(app, admin_user, client):
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        creds = _basic("testadmin", "adminpass")
        # Cross-site browser context → CSRF is enforced even with Basic Auth.
        xs = client.post("/users/create",
                         data={"username": "rogue", "password": "roguepass123"},
                         headers={**creds, "Sec-Fetch-Site": "cross-site"})
        assert xs.status_code == 400        # CSRF token missing → rejected

        # A non-browser client (no Sec-Fetch-Site) keeps the exemption.
        api = client.post("/users/create",
                          data={"username": "apiuser", "password": "apipass1234"},
                          headers=creds)
        assert api.status_code != 400       # CSRF skipped → view ran (redirects)
    finally:
        app.config["WTF_CSRF_ENABLED"] = False
