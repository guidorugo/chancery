"""Dual-control (four-eyes) mode — 2.10.0.

With ``DUAL_CONTROL_ENABLED=true`` the restrictions only bite while the
instance is genuinely multi-user: at least one other ACTIVE account besides
the literal ``ADMIN_USERNAME`` bootstrap account exists, or LDAP is in effect
(directory users can appear at any login). A single-user box keeps the normal
flow even with the flag on, so enabling it ahead of onboarding is safe.

The bootstrap account itself is exempt from the "different person" checks —
it is the break-glass path when no second admin is available.
"""

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
