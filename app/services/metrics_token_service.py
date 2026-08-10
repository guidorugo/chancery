"""Lifecycle for the dedicated Prometheus ``/metrics`` bearer tokens.

Create / list / revoke are driven from the ``flask metrics-token`` CLI (and could
be driven from a request); ``verify`` and ``touch`` are called ONLY by the
``/metrics`` view, which is what keeps a metrics token least-privilege — it grants
access to nothing else.

Audit rows are written directly (not via ``audit_service.log_action``) because
that helper reads ``request``/``current_user``, which don't exist under the CLI.
"""
import json
from datetime import datetime, timezone

from flask import has_request_context, request
from flask_login import current_user

from ..extensions import db
from ..models.audit_log import AuditLog
from ..models.metrics_token import MetricsToken

# A scrape can hit /metrics every few seconds; only persist last_used_at at most
# this often so a busy scraper doesn't turn every request into a write.
_TOUCH_THROTTLE_SECONDS = 60


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _audit(action, target_id=None, details=None):
    """Write an audit entry that works with or without a request context."""
    if has_request_context() and current_user and current_user.is_authenticated:
        user_id, username = current_user.id, current_user.username
        ip = request.remote_addr or "unknown"
    else:
        user_id, username, ip = None, "cli", "cli"
    db.session.add(AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        target_type="metrics_token",
        target_id=target_id,
        details=json.dumps(details) if details else None,
        ip_address=ip,
    ))


def create(name, expires_at, created_by=None):
    """Create a metrics token. Returns ``(plaintext, row)``; the plaintext secret
    is shown once and never recoverable. Raises ``ValueError`` on a bad/duplicate
    name or a missing expiry."""
    name = (name or "").strip()
    if not name:
        raise ValueError("A token name is required.")
    if expires_at is None:
        raise ValueError("An expiry is required.")
    if MetricsToken.query.filter_by(name=name).first() is not None:
        raise ValueError(f"A metrics token named '{name}' already exists.")

    plaintext, row = MetricsToken.generate(name, expires_at, created_by=created_by)
    db.session.add(row)
    db.session.flush()  # assign row.id for the audit target
    _audit("metrics_token_created", target_id=row.id,
           details={"name": name, "expires_at": row.expires_at.isoformat()})
    db.session.commit()
    return plaintext, row


def revoke(name_or_id):
    """Revoke a token by name or id. Returns the row (or None if not found)."""
    row = get(name_or_id)
    if row is None:
        return None
    if not row.revoked:
        row.revoked = True
        _audit("metrics_token_revoked", target_id=row.id, details={"name": row.name})
        db.session.commit()
    return row


def list_all():
    return MetricsToken.query.order_by(MetricsToken.created_at.desc()).all()


def verify(presented):
    """Return the valid ``MetricsToken`` for a presented bearer secret, else None.

    Rejects unknown/tampered/expired/revoked tokens. Constant-time on the secret.
    """
    token_id, secret = MetricsToken.split(presented)
    if token_id is None:
        return None
    row = MetricsToken.query.filter_by(token_id=token_id).first()
    if row is None or not row.is_valid(_now()):
        return None
    if not row.matches(secret):
        return None
    return row


def touch(row):
    """Best-effort, throttled ``last_used_at`` update. Never raises — a failed
    bookkeeping write must not fail the scrape."""
    try:
        now = _now()
        if row.last_used_at is None or \
                (now - row.last_used_at).total_seconds() >= _TOUCH_THROTTLE_SECONDS:
            row.last_used_at = now
            db.session.commit()
    except Exception:
        db.session.rollback()


def get(name_or_id):
    """Look up a token by exact name, or by numeric id. None if not found."""
    row = MetricsToken.query.filter_by(name=name_or_id).first()
    if row is None:
        try:
            row = db.session.get(MetricsToken, int(name_or_id))
        except (ValueError, TypeError):
            row = None
    return row
