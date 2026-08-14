import json

from flask import request
from flask_login import current_user

from ..extensions import db
from ..models.audit_log import AuditLog

_MAX_LOGGED_USERNAME_LEN = 3


def sanitize_username_for_log(attempted_username):
    """Truncate an unrecognised username to avoid logging passwords.

    When a user accidentally types their password into the username field,
    the raw value ends up in the audit log in cleartext.  To mitigate this
    we truncate the attempted value to the first few characters — enough to
    correlate brute-force patterns, but not enough to expose a full password.

    If the value matches an existing account we return it unchanged (it is a
    real username, not a password).
    """
    from ..models.user import User

    if not attempted_username:
        return ""
    if User.query.filter_by(username=attempted_username).first() is not None:
        return attempted_username
    if len(attempted_username) <= _MAX_LOGGED_USERNAME_LEN:
        return attempted_username
    return attempted_username[:_MAX_LOGGED_USERNAME_LEN] + "***"


def log_action(action, target_type=None, target_id=None, details=None):
    """Create an audit log entry. Caller is responsible for db.session.commit()."""
    if current_user and current_user.is_authenticated:
        user_id = current_user.id
        username = current_user.username
    else:
        user_id = None
        username = "anonymous"

    ip_address = request.remote_addr or "unknown"

    entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=json.dumps(details) if details else None,
        ip_address=ip_address,
    )
    db.session.add(entry)

    # Webhook notifications (2.10.0) piggyback on the audit stream — one choke
    # point covers every action. notify() is fire-and-forget and never raises,
    # but a notification must never break the audited request either.
    # Note this runs before the caller's commit: if that commit later rolls
    # back, a spurious notification may already be out (accepted trade-off —
    # receivers should treat events as hints, not transactional truth).
    try:
        from . import webhook_service
        webhook_service.notify(action, target_type=target_type,
                               target_id=target_id, details=details,
                               actor_username=username)
    except Exception:
        pass
