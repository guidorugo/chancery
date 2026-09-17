"""Dual-control (four-eyes) mode — 2.10.0.

With ``DUAL_CONTROL_ENABLED=true`` the restrictions only bite while the
instance is genuinely multi-user: at least one other ACTIVE account besides
the literal ``ADMIN_USERNAME`` bootstrap account exists, or LDAP is in effect
(directory users can appear at any login). A single-user box keeps the normal
flow even with the flag on, so enabling it ahead of onboarding is safe.

The bootstrap account itself is exempt from the "different person" checks —
it is the break-glass path when no second admin is available.
"""

from datetime import datetime, timedelta, timezone

from flask import current_app, g

from ..extensions import db
from ..models.user import User
from . import ldap_settings_service


def is_enabled() -> bool:
    """The raw config flag (not whether the restrictions currently apply)."""
    return bool(current_app.config.get("DUAL_CONTROL_ENABLED"))


def is_exempt(user) -> bool:
    """True for the literal bootstrap admin account (break-glass)."""
    return (
        user is not None
        and getattr(user, "username", None)
            == current_app.config.get("ADMIN_USERNAME", "admin")
    )


def is_active() -> bool:
    """Whether dual-control restrictions apply to this request (g-cached)."""
    cached = g.get("_dual_control_active")
    if cached is not None:
        return cached
    active = False
    if is_enabled():
        admin_username = current_app.config.get("ADMIN_USERNAME", "admin")
        other_users = db.session.query(
            User.query.filter(
                User.is_active_user.is_(True),
                User.username != admin_username,
            ).exists()
        ).scalar()
        active = bool(other_users) or bool(
            ldap_settings_service.effective_config().get("LDAP_ENABLED")
        )
    g._dual_control_active = active
    return active


def cooldown_hours() -> int:
    return int(current_app.config.get("DUAL_CONTROL_COOLDOWN_HOURS", 24) or 0)


def can_approve(approver, creator_id) -> bool:
    """F19: may `approver` approve something that `creator_id` set up?

    Never the creator themselves; and not an account the creator created or
    password-reset within DUAL_CONTROL_COOLDOWN_HOURS — otherwise an admin
    could mint an approver and use it at once. The bootstrap account is
    exempt. Only meaningful while is_active(); callers check that.
    """
    if approver is None:
        return False
    if is_exempt(approver):
        return True
    if creator_id is None:
        return True
    if approver.id == creator_id:
        return False
    hours = cooldown_hours()
    if hours <= 0:
        return True
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    created_at = getattr(approver, "created_at", None)
    if getattr(approver, "created_by", None) == creator_id and created_at and _naive(created_at) >= cutoff:
        return False
    reset_at = getattr(approver, "password_reset_at", None)
    if getattr(approver, "password_reset_by", None) == creator_id and reset_at and _naive(reset_at) >= cutoff:
        return False
    return True


def _naive(dt):
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


def refuse_reason(approver, creator_id, what="this"):
    """A human message for a refused approval, or None when allowed."""
    if can_approve(approver, creator_id):
        return None
    if approver.id == creator_id:
        return f"Dual-control mode: {what} must be approved by a different admin than the one who set it up."
    return (f"Dual-control mode: your account was created or reset by that admin less than "
            f"{cooldown_hours()} hours ago and cannot approve {what} yet.")
