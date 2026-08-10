"""Unauthenticated /health endpoint: cheap DB probe, 200/503, JSON only, no
secrets, reachable without auth and past the forced-password-change guard."""

from app.models.user import User


def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.is_json
    body = r.get_json()
    assert body["status"] == "ok"
    assert body["checks"]["database"] == "ok"


def test_health_requires_no_auth(client):
    # Anonymous — must not redirect to the login page.
    r = client.get("/health", follow_redirects=False)
    assert r.status_code == 200


def test_health_always_json_even_for_browser(client):
    r = client.get("/health", headers={"Accept": "text/html"})
    assert r.status_code == 200
    assert "application/json" in r.content_type


def test_health_exposes_no_secrets(client):
    body = client.get("/health").get_json()
    # Only status + checks — no version, config, or secret material.
    assert set(body.keys()) == {"status", "checks"}
    assert set(body["checks"].keys()) == {"database"}


def test_health_db_down_returns_503(client, monkeypatch):
    from app.extensions import db

    def boom(*args, **kwargs):
        raise Exception("db down")

    monkeypatch.setattr(db.session, "execute", boom)
    r = client.get("/health")
    assert r.status_code == 503
    body = r.get_json()
    assert body["status"] == "unhealthy"
    assert body["checks"]["database"] == "error"


def test_health_reachable_under_password_change_guard(app, client, db):
    with app.app_context():
        u = User(username="mustchange", role="admin")
        u.set_password("changeme123456")
        u.must_change_password = True
        db.session.add(u)
        db.session.commit()
    client.post("/auth/login", data={"username": "mustchange", "password": "changeme123456"})
    # A normal page redirects the flagged user to change-password...
    assert client.get("/", follow_redirects=False).status_code == 302
    # ...but /health is exempt and answers normally.
    r = client.get("/health", follow_redirects=False)
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"
