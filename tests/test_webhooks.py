"""Webhook notifications (2.10.0).

No real network anywhere: delivery tests monkeypatch either the module's
``_post`` (with a synchronous fake Thread, so notify() runs inline) or
``urllib.request.urlopen`` (to inspect the exact signed request ``_post``
builds).
"""

import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest
from flask import g

from app._version import __version__
from app.models.audit_log import AuditLog
from app.models.webhook_settings import WebhookSettings
from app.services import webhook_service
from app.services.crypto_utils import encrypt_secret


def _cfg(**overrides):
    cfg = {
        "WEBHOOK_ENABLED": True,
        "WEBHOOK_URL": "http://receiver.example/hook",
        "WEBHOOK_SECRET": "",
        "WEBHOOK_EVENTS": "all",
        "WEBHOOK_TIMEOUT_SECONDS": 5,
    }
    cfg.update(overrides)
    return cfg


class _SyncThread:
    """Runs the target inline on start() so tests see the result immediately."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._target, self._args, self._kwargs = target, args, kwargs or {}

    def start(self):
        self._target(*self._args, **self._kwargs)


@pytest.fixture
def posts(monkeypatch):
    """Capture _post calls; notify() delivers synchronously."""
    calls = []

    def fake_post(url, body, timeout, secret=None, secret_enc=None, passphrase=None):
        calls.append({"url": url, "body": body, "timeout": timeout,
                      "secret": secret, "secret_enc": secret_enc,
                      "passphrase": passphrase})

    monkeypatch.setattr(webhook_service, "_post", fake_post)
    monkeypatch.setattr(webhook_service, "threading",
                        SimpleNamespace(Thread=_SyncThread))
    return calls


# --- event selection ---------------------------------------------------------

class TestSelection:
    def test_selected_action_fires_others_do_not(self, app, posts):
        with app.test_request_context():
            g._webhook_cfg_override = _cfg(WEBHOOK_EVENTS="sign_csr, create_ca")
            webhook_service.notify("sign_csr", target_type="csr", target_id=1)
            webhook_service.notify("revoke_certificate", target_type="certificate")
        assert len(posts) == 1
        assert json.loads(posts[0]["body"])["event"] == "sign_csr"

    @pytest.mark.parametrize("sentinel", ["all", "*"])
    def test_all_sentinel(self, app, posts, sentinel):
        with app.test_request_context():
            g._webhook_cfg_override = _cfg(WEBHOOK_EVENTS=sentinel)
            webhook_service.notify("anything_even_future_actions")
        assert len(posts) == 1

    def test_empty_events_means_none(self, app, posts):
        with app.test_request_context():
            g._webhook_cfg_override = _cfg(WEBHOOK_EVENTS="")
            webhook_service.notify("sign_csr")
        assert posts == []

    def test_disabled_means_none(self, app, posts):
        with app.test_request_context():
            g._webhook_cfg_override = _cfg(WEBHOOK_ENABLED=False)
            webhook_service.notify("sign_csr")
        assert posts == []


# --- payload -----------------------------------------------------------------

class TestPayload:
    def test_shape(self, app, posts):
        with app.test_request_context():
            g._webhook_cfg_override = _cfg()
            webhook_service.notify("revoke_certificate", target_type="certificate",
                                   target_id=42, details={"reason": "superseded"},
                                   actor_username="alice")
        payload = json.loads(posts[0]["body"])
        assert payload["event"] == "revoke_certificate"
        assert payload["actor"] == "alice"
        assert payload["target"] == {"type": "certificate", "id": 42}
        assert payload["details"] == {"reason": "superseded"}
        assert payload["app"] == "cert-manager"
        assert payload["version"] == __version__
        assert "timestamp" in payload

    def test_anonymous_actor_default(self, app, posts):
        with app.test_request_context():
            g._webhook_cfg_override = _cfg()
            webhook_service.notify("login_failure")
        assert json.loads(posts[0]["body"])["actor"] == "anonymous"


# --- transport & signature ---------------------------------------------------

@pytest.fixture
def urlopen_capture(monkeypatch):
    captured = {}

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        captured["req"] = req
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(webhook_service.urllib.request, "urlopen", fake_urlopen)
    return captured


def _signature_header(req):
    for key, value in req.header_items():
        if key.lower() == "x-certmanager-signature":
            return value
    return None


class TestTransport:
    def test_post_signs_with_plain_secret(self, urlopen_capture):
        body = b'{"event": "test"}'
        webhook_service._post("http://h.example/hook", body, 3, secret="k3y")
        expected = hmac.new(b"k3y", body, hashlib.sha256).hexdigest()
        req = urlopen_capture["req"]
        assert _signature_header(req) == f"sha256={expected}"
        assert req.data == body
        assert urlopen_capture["timeout"] == 3

    def test_post_decrypts_stored_secret_in_worker(self, urlopen_capture):
        body = b'{"event": "test"}'
        enc = encrypt_secret("k3y", "test-passphrase")
        webhook_service._post("http://h.example/hook", body, 3,
                              secret_enc=enc, passphrase="test-passphrase")
        expected = hmac.new(b"k3y", body, hashlib.sha256).hexdigest()
        assert _signature_header(urlopen_capture["req"]) == f"sha256={expected}"

    def test_post_no_secret_no_header(self, urlopen_capture):
        webhook_service._post("http://h.example/hook", b"{}", 3)
        assert _signature_header(urlopen_capture["req"]) is None

    def test_post_swallows_errors(self, monkeypatch):
        def boom(req, timeout=None):
            raise OSError("connection refused")

        monkeypatch.setattr(webhook_service.urllib.request, "urlopen", boom)
        webhook_service._post("http://h.example/hook", b"{}", 3)  # must not raise

    def test_notify_survives_post_failure(self, app, monkeypatch):
        def boom(*args, **kwargs):
            raise OSError("dead receiver")

        monkeypatch.setattr(webhook_service, "_post", boom)
        monkeypatch.setattr(webhook_service, "threading",
                            SimpleNamespace(Thread=_SyncThread))
        with app.test_request_context():
            g._webhook_cfg_override = _cfg()
            webhook_service.notify("sign_csr")  # must not raise


# --- settings precedence / persistence ---------------------------------------

class TestSettings:
    def test_env_fallback(self, app, db):
        with app.test_request_context():
            cfg = webhook_service.effective_config()
            assert cfg["WEBHOOK_ENABLED"] is False
            assert webhook_service.config_source() == "env"

    def test_saved_row_wins_and_secret_encrypted(self, app, db):
        with app.test_request_context():
            webhook_service.save(_cfg(WEBHOOK_SECRET="hunter2hunter2",
                                      WEBHOOK_EVENTS="sign_csr"))
            db.session.commit()
        with app.test_request_context():
            cfg = webhook_service.effective_config()
            assert cfg["WEBHOOK_ENABLED"] is True
            assert cfg["WEBHOOK_EVENTS"] == "sign_csr"
            assert webhook_service.config_source() == "db"
            row = db.session.get(WebhookSettings, 1)
            assert b"hunter2hunter2" not in (row.secret_enc or b"")
            assert webhook_service.stored_secret() == "hunter2hunter2"

    def test_blank_secret_keeps_stored(self, app, db):
        with app.test_request_context():
            webhook_service.save(_cfg(WEBHOOK_SECRET="firstsecret"))
            db.session.commit()
            webhook_service.save(_cfg(WEBHOOK_SECRET=""))
            db.session.commit()
            assert webhook_service.stored_secret() == "firstsecret"

    def test_reset_reverts_to_env(self, app, db):
        with app.test_request_context():
            webhook_service.save(_cfg())
            db.session.commit()
            webhook_service.reset()
            db.session.commit()
            assert webhook_service.config_source() == "env"
            assert webhook_service.effective_config()["WEBHOOK_ENABLED"] is False

    def test_validate_rules(self, app):
        with app.test_request_context():
            assert webhook_service.validate(_cfg(WEBHOOK_ENABLED=False)) == []
            assert any("URL is required" in e
                       for e in webhook_service.validate(_cfg(WEBHOOK_URL="")))
            assert any("http:// or https://" in e
                       for e in webhook_service.validate(_cfg(WEBHOOK_URL="ftp://x/y")))
            assert any("Timeout" in e
                       for e in webhook_service.validate(
                           _cfg(WEBHOOK_TIMEOUT_SECONDS="abc")))


# --- routes / UI -------------------------------------------------------------

def _base_form(**overrides):
    form = {
        "action": "save",
        "enabled": "on",
        "url": "http://receiver.example/hook",
        "secret": "hunter2hunter2",
        "timeout_seconds": "5",
        "event_sign_csr": "on",
        "event_create_ca": "on",
    }
    form.update(overrides)
    return form


class TestRoutes:
    def test_get_renders(self, app, auth_admin):
        r = auth_admin.get("/users/webhooks")
        assert r.status_code == 200
        assert b"Webhook Notifications" in r.data

    def test_save_persists_and_audits(self, app, auth_admin, db):
        r = auth_admin.post("/users/webhooks", data=_base_form(),
                            follow_redirects=True)
        assert r.status_code == 200
        assert b"saved" in r.data.lower()
        with app.app_context():
            row = db.session.get(WebhookSettings, 1)
            assert row is not None and row.enabled is True
            assert set(row.events.split(",")) == {"sign_csr", "create_ca"}
            assert AuditLog.query.filter_by(action="update_webhook_settings").count() == 1

    def test_all_events_switch(self, app, auth_admin, db):
        auth_admin.post("/users/webhooks",
                        data=_base_form(all_events="on"), follow_redirects=True)
        with app.app_context():
            assert db.session.get(WebhookSettings, 1).events == "all"

    def test_secret_never_echoed(self, app, auth_admin):
        auth_admin.post("/users/webhooks", data=_base_form(), follow_redirects=True)
        r = auth_admin.get("/users/webhooks")
        assert b"hunter2hunter2" not in r.data
        assert b"unchanged" in r.data  # write-only placeholder hints a stored secret

    def test_validation_error_not_persisted(self, app, auth_admin, db):
        r = auth_admin.post("/users/webhooks", data=_base_form(url=""),
                            follow_redirects=True)
        assert b"URL is required" in r.data
        with app.app_context():
            assert db.session.get(WebhookSettings, 1) is None

    def test_test_button(self, app, auth_admin, db, monkeypatch):
        monkeypatch.setattr(webhook_service, "send_test",
                            lambda cfg: {"ok": True,
                                         "message": "Test event delivered (HTTP 200)."})
        r = auth_admin.post("/users/webhooks",
                            data=_base_form(action="test"), follow_redirects=True)
        assert b"Test succeeded" in r.data
        with app.app_context():
            assert db.session.get(WebhookSettings, 1) is None  # test saves nothing
            assert AuditLog.query.filter_by(action="test_webhook").count() == 1

    def test_reset_route(self, app, auth_admin, db):
        auth_admin.post("/users/webhooks", data=_base_form(), follow_redirects=True)
        r = auth_admin.post("/users/webhooks/reset", follow_redirects=True)
        assert r.status_code == 200
        with app.app_context():
            assert db.session.get(WebhookSettings, 1) is None
            assert AuditLog.query.filter_by(action="reset_webhook_settings").count() == 1
        assert b"Using environment config" in auth_admin.get("/users/webhooks").data

    def test_requester_denied(self, app, auth_csr_requester):
        r = auth_csr_requester.get("/users/webhooks")
        assert r.status_code in (302, 403)

    def test_anonymous_denied(self, app, client):
        r = client.get("/users/webhooks")
        assert r.status_code == 302
        assert "/auth/login" in r.headers["Location"]


# --- end-to-end through the audit stream -------------------------------------

class TestIntegration:
    def test_login_fires_selected_webhook(self, app, db, admin_user, posts):
        with app.test_request_context():
            webhook_service.save(_cfg(WEBHOOK_EVENTS="login_success"))
            db.session.commit()
        with app.test_client() as c:
            c.post("/auth/login", data={"username": "testadmin",
                                        "password": "adminpass"})
        assert len(posts) == 1
        payload = json.loads(posts[0]["body"])
        assert payload["event"] == "login_success"
        assert payload["actor"] == "testadmin"

    def test_unselected_action_does_not_fire(self, app, db, admin_user, posts):
        with app.test_request_context():
            webhook_service.save(_cfg(WEBHOOK_EVENTS="revoke_certificate"))
            db.session.commit()
        with app.test_client() as c:
            c.post("/auth/login", data={"username": "testadmin",
                                        "password": "adminpass"})
        assert posts == []
