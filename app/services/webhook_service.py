"""Webhook notifications for audit actions (2.10.0).

Design goals, mirroring update_service and ldap_settings_service:

- Settings precedence: admin-saved WebhookSettings row (id=1) > WEBHOOK_*
  environment variables; the effective config is cached on flask.g per
  request, with a g._webhook_cfg_override hook for tests.
- Delivery is fire-and-forget: the payload is built on the request thread,
  then POSTed from a daemon thread (stdlib urllib, no new dependency) that
  swallows every error — a dead receiver must never break or slow a page.
- The stored secret is Fernet-encrypted under MASTER_PASSPHRASE; decrypting
  costs a 600k-iteration PBKDF2, so it is deliberately done INSIDE the worker
  thread (crypto_utils.decrypt_secret is a pure function), never on the
  request path. When a secret resolves, the raw body is signed with
  HMAC-SHA256 into the X-CertManager-Signature header ("sha256=<hex>").
"""

import hashlib
import hmac
import json
import logging
import threading
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

from flask import current_app, g

from ..extensions import db
from ..models.webhook_settings import WebhookSettings
from .._version import __version__
from . import crypto_utils

logger = logging.getLogger(__name__)

CONFIG_KEYS = [
    "WEBHOOK_ENABLED",
    "WEBHOOK_URL",
    "WEBHOOK_SECRET",
    "WEBHOOK_EVENTS",
    "WEBHOOK_TIMEOUT_SECONDS",
]

# Values of WEBHOOK_EVENTS that select every action, present and future.
_ALL_SENTINELS = {"all", "*"}

# (action, label) per UI group. This is the checkbox catalog for the
# Preferences → Webhooks page; the env CSV also accepts any action name not
# listed here, so future actions need no code change to be selectable.
EVENT_CATALOG = {
    "Certificate Authorities": [
        ("create_ca", "CA created"),
        ("import_ca", "CA imported"),
        ("approve_ca", "CA approved (dual control)"),
        ("revoke_ca", "CA revoked"),
        ("generate_crl", "CRL generated"),
        ("download_ca_private_key", "CA private key exported"),
        ("export_ca_pkcs12", "CA PKCS#12 exported"),
    ],
    "Certificates": [
        ("create_certificate", "Certificate issued directly"),
        ("revoke_certificate", "Certificate revoked"),
        ("download_certificate", "Certificate downloaded"),
        ("download_private_key", "Private key downloaded"),
    ],
    "CSRs": [
        ("create_csr", "CSR created"),
        ("import_csr", "CSR imported"),
        ("sign_csr", "CSR signed (certificate issued)"),
        ("reject_csr", "CSR rejected"),
    ],
    "Users & authentication": [
        ("create_user", "User created"),
        ("update_user_role", "User role changed"),
        ("activate_user", "User activated"),
        ("deactivate_user", "User deactivated"),
        ("reset_user_password", "User password reset"),
        ("change_password", "Password changed"),
        ("login_success", "Login succeeded"),
        ("login_failure", "Login failed (can be noisy)"),
        ("logout", "Logout"),
        ("basic_auth_failed", "Basic Auth failed (can be noisy)"),
        ("ldap_user_provisioned", "LDAP user provisioned"),
        ("ldap_role_synced", "LDAP role re-synced"),
    ],
    "Configuration": [
        ("update_ldap_settings", "LDAP settings saved"),
        ("reset_ldap_settings", "LDAP settings reset"),
        ("update_webhook_settings", "Webhook settings saved"),
        ("reset_webhook_settings", "Webhook settings reset"),
    ],
}


def catalog_actions():
    return [action for group in EVENT_CATALOG.values() for action, _ in group]


# --- settings (precedence / persistence) ------------------------------------

def get_row():
    return db.session.get(WebhookSettings, 1)


def _env_config():
    return {k: current_app.config.get(k) for k in CONFIG_KEYS}


def effective_config(include_secret=False):
    """The webhook config in effect: test override > DB row > environment.

    The decrypted secret is NOT part of the cached config (decrypting it costs
    a 600k-iteration PBKDF2); notify() hands the encrypted bytes to its worker
    thread instead. Pass include_secret=True only where the plaintext is
    genuinely needed synchronously (the test-send path).
    """
    override = g.get("_webhook_cfg_override")
    if override is not None:
        return override
    cached = g.get("_webhook_cfg_cache")
    if cached is None:
        row = get_row()
        if row is not None:
            cached = {
                "WEBHOOK_ENABLED": row.enabled,
                "WEBHOOK_URL": row.url,
                "WEBHOOK_SECRET": "",          # never decrypted on this path
                "WEBHOOK_EVENTS": row.events,
                "WEBHOOK_TIMEOUT_SECONDS": row.timeout_seconds,
            }
        else:
            cached = _env_config()
        g._webhook_cfg_cache = cached
    if include_secret and config_source() == "db":
        cfg = dict(cached)
        cfg["WEBHOOK_SECRET"] = stored_secret()
        return cfg
    return cached


def config_source():
    """'db' when the admin-saved row is in effect, else 'env'."""
    return "db" if get_row() is not None else "env"


def stored_secret():
    """The currently effective signing secret ('' if none)."""
    row = get_row()
    if row is None:
        return current_app.config.get("WEBHOOK_SECRET", "")
    if not row.secret_enc:
        return ""
    return crypto_utils.decrypt_secret(
        row.secret_enc, current_app.config["MASTER_PASSPHRASE"]
    )


def validate(cfg):
    """Sanity rules for a candidate config; list of errors (may be empty)."""
    errors = []
    if not cfg["WEBHOOK_ENABLED"]:
        return errors
    url = (cfg["WEBHOOK_URL"] or "").strip()
    if not url:
        errors.append("A webhook URL is required when notifications are enabled.")
    else:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            errors.append("The webhook URL must be an http:// or https:// URL.")
    try:
        if int(cfg["WEBHOOK_TIMEOUT_SECONDS"]) < 1:
            errors.append("Timeout must be at least 1 second.")
    except (TypeError, ValueError):
        errors.append("Timeout must be a number of seconds.")
    return errors


def save(cfg, updated_by=None):
    """Persist a validated config dict as the single settings row.

    An empty WEBHOOK_SECRET keeps the currently stored secret (the form field
    is write-only); the caller commits (with its audit entry).
    """
    row = get_row()
    if row is None:
        row = WebhookSettings(id=1)
        db.session.add(row)
    row.enabled = cfg["WEBHOOK_ENABLED"]
    row.url = (cfg["WEBHOOK_URL"] or "").strip()
    row.events = cfg["WEBHOOK_EVENTS"] or ""
    row.timeout_seconds = int(cfg["WEBHOOK_TIMEOUT_SECONDS"])
    row.updated_by = updated_by
    if cfg["WEBHOOK_SECRET"]:
        row.secret_enc = crypto_utils.encrypt_secret(
            cfg["WEBHOOK_SECRET"], current_app.config["MASTER_PASSPHRASE"]
        )
    g.pop("_webhook_cfg_cache", None)
    return row


def reset():
    """Delete the row, reverting the app to the environment configuration."""
    row = get_row()
    if row is not None:
        db.session.delete(row)
    g.pop("_webhook_cfg_cache", None)


def selected_events(cfg):
    """The selected action set: None means ALL actions, empty set means none."""
    raw = (cfg.get("WEBHOOK_EVENTS") or "").strip()
    if not raw:
        return set()
    names = {part.strip() for part in raw.split(",") if part.strip()}
    if names & _ALL_SENTINELS:
        return None
    return names


# --- delivery ----------------------------------------------------------------

def _build_body(action, target_type, target_id, details, actor_username):
    payload = {
        "event": action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor_username or "anonymous",
        "target": {"type": target_type, "id": target_id},
        "details": details or {},
        "app": "cert-manager",
        "version": __version__,
    }
    return json.dumps(payload).encode("utf-8")


def _post(url, body, timeout, secret=None, secret_enc=None, passphrase=None):
    """POST the payload; ALL failures are swallowed (logged at debug).

    Runs on a worker thread with plain values only — no app context, no DB.
    The expensive secret decryption (PBKDF2) happens here, off the request.
    """
    try:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "cert-manager-webhook",
        }
        if secret_enc and passphrase:
            secret = crypto_utils.decrypt_secret(secret_enc, passphrase)
        if secret:
            sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-CertManager-Signature"] = f"sha256={sig}"
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout):  # nosec B310 (admin-configured URL)
            pass
    except Exception as exc:
        logger.debug("Webhook delivery to %s failed: %s", url, exc)


def notify(action, target_type=None, target_id=None, details=None,
           actor_username=None):
    """Queue a webhook for an audit action. Never raises, never blocks."""
    try:
        cfg = effective_config()
        if not cfg.get("WEBHOOK_ENABLED") or not cfg.get("WEBHOOK_URL"):
            return
        selected = selected_events(cfg)
        if selected is not None and action not in selected:
            return
        body = _build_body(action, target_type, target_id, details, actor_username)
        timeout = int(cfg.get("WEBHOOK_TIMEOUT_SECONDS") or 5)
        secret = None
        secret_enc = None
        passphrase = None
        if config_source() == "db":
            row = get_row()
            if row is not None and row.secret_enc:
                secret_enc = row.secret_enc
                passphrase = current_app.config["MASTER_PASSPHRASE"]
        else:
            secret = cfg.get("WEBHOOK_SECRET") or None
        threading.Thread(
            target=_post,
            args=(cfg["WEBHOOK_URL"], body, timeout),
            kwargs={"secret": secret, "secret_enc": secret_enc,
                    "passphrase": passphrase},
            daemon=True,
        ).start()
    except Exception:
        logger.debug("Webhook notify(%s) failed", action, exc_info=True)


def send_test(cfg):
    """Synchronously POST a test event with the given (candidate) config.

    Returns {"ok": bool, "message": str} for the settings page alert.
    """
    errors = validate(cfg)
    if errors:
        return {"ok": False, "message": " ".join(errors)}
    if not cfg["WEBHOOK_ENABLED"]:
        return {"ok": False, "message": "Enable notifications before testing."}
    body = _build_body("test", "config", None,
                       {"note": "cert-manager webhook test event"}, None)
    try:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "cert-manager-webhook",
        }
        secret = cfg.get("WEBHOOK_SECRET") or ""
        if secret:
            sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-CertManager-Signature"] = f"sha256={sig}"
        req = urllib.request.Request(cfg["WEBHOOK_URL"], data=body,
                                     headers=headers, method="POST")
        timeout = int(cfg.get("WEBHOOK_TIMEOUT_SECONDS") or 5)
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            return {"ok": True,
                    "message": f"Test event delivered (HTTP {resp.status})."}
    except Exception as exc:
        return {"ok": False, "message": f"Delivery failed: {exc}"}
