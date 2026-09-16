"""Lifecycle and verification of scoped API tokens (F12, 2.26.0).

`verify()` is called by the request hook in `app/__init__.py` for every
`Authorization: Bearer chy_api_…` header; `required_scope()` maps a request to
the scope it needs so the hook can refuse a token that lacks it. Session and
Basic-Auth requests are never scope-checked — only tokens are.
"""
import json
from datetime import datetime, timedelta, timezone

from flask import current_app, has_request_context, request
from flask_login import current_user

from ..extensions import db
from ..models.api_token import ApiToken, SCOPES
from ..models.user import User
from . import audit_service

_TOUCH_THROTTLE_SECONDS = 60

# Endpoints whose non-GET requests need a scope other than `admin`. Everything
# else that writes needs `admin`; every GET/HEAD/OPTIONS needs `read`.
ISSUE_ENDPOINTS = {
    "certificates.create", "certificates.renew",
    "csr.create", "csr.sign",
}
REVOKE_ENDPOINTS = {
    "certificates.revoke", "ca.revoke", "ca.generate_crl",
}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def max_days():
    try:
        return int(current_app.config.get("API_TOKEN_MAX_DAYS", 365))
    except RuntimeError:
        return 365


def normalise_scopes(scopes):
    scopes = [s.strip().lower() for s in (scopes or []) if s and s.strip()]
    unknown = sorted(set(scopes) - set(SCOPES))
    if unknown:
        raise ValueError(f"Unknown scope(s): {', '.join(unknown)}. Valid scopes: {', '.join(SCOPES)}.")
    if not scopes:
        raise ValueError("At least one scope is required.")
    return sorted(set(scopes))


def create(user, name, scopes, expires_in_days, created_by=None, actor=None):
    """Create a token for `user`. Returns (plaintext, row). The plaintext is
    shown once. Flushes and audits (`create_api_token`); the caller commits."""
    name = (name or "").strip()
    if not name:
        raise ValueError("A token name is required.")
    if len(name) > 100:
        raise ValueError("The token name must be 100 characters or fewer.")
    scopes = normalise_scopes(scopes)
    try:
        days = int(expires_in_days)
    except (TypeError, ValueError):
        raise ValueError("Expiry (days) must be a whole number.")
    if days < 1 or days > max_days():
        raise ValueError(f"Expiry must be between 1 and {max_days()} days.")
    if not user.is_active:
        raise ValueError("Cannot create a token for a deactivated account.")
    if ApiToken.query.filter_by(user_id=user.id, name=name).first() is not None:
        raise ValueError(f"'{user.username}' already has a token named '{name}'.")
    expires_at = _now() + timedelta(days=days)
    plaintext, row = ApiToken.generate(user.id, name, scopes, expires_at, created_by=created_by)
    db.session.add(row)
    db.session.flush()
    if actor is None and not has_request_context():
        actor = "system"  # service call outside a request (tests, jobs): audit as a system actor
    audit_service.log_action("create_api_token", target_type="api_token", target_id=row.id,
                             details={"user_id": user.id, "username": user.username, "name": name,
                                      "scopes": scopes, "expires_at": expires_at.isoformat()}, actor=actor)
    return plaintext, row


def revoke(row, actor=None):
    if not row.revoked:
        row.revoked = True
        if actor is None and not has_request_context():
            actor = "system"
        audit_service.log_action("revoke_api_token", target_type="api_token", target_id=row.id,
                                 details={"user_id": row.user_id, "name": row.name}, actor=actor)
        db.session.flush()
    return row


def list_for_user(user):
    return ApiToken.query.filter_by(user_id=user.id).order_by(ApiToken.created_at.desc()).all()


def list_all():
    return ApiToken.query.order_by(ApiToken.created_at.desc()).all()


def get(token_id_or_pk):
    row = ApiToken.query.filter_by(token_id=str(token_id_or_pk)).first()
    if row is None:
        try:
            row = db.session.get(ApiToken, int(token_id_or_pk))
        except (ValueError, TypeError):
            row = None
    return row


def verify(presented):
    """The valid ApiToken for a presented bearer string, or None. A revoked
    or expired token, a tampered secret, or a deactivated owner all fail."""
    token_id, secret = ApiToken.split(presented)
    if token_id is None:
        return None
    row = ApiToken.query.filter_by(token_id=token_id).first()
    if row is None or not row.is_valid(_now()) or not row.matches(secret):
        return None
    if row.user is None or not row.user.is_active:
        return None
    return row


def touch(row):
    try:
        now = _now()
        if row.last_used_at is None or (now - row.last_used_at).total_seconds() >= _TOUCH_THROTTLE_SECONDS:
            row.last_used_at = now
            db.session.commit()
    except Exception:
        db.session.rollback()


def required_scope(method, endpoint):
    """The scope a request needs. `None` for endpoints outside the app's
    authenticated surface (public, health, metrics, static, auth)."""
    if not endpoint:
        return "read"
    blueprint = endpoint.split(".", 1)[0]
    if blueprint in ("public", "health", "metrics", "static", "auth"):
        return None
    if method in ("GET", "HEAD", "OPTIONS"):
        return "read"
    if endpoint in ISSUE_ENDPOINTS:
        return "issue"
    if endpoint in REVOKE_ENDPOINTS:
        return "revoke"
    return "admin"
