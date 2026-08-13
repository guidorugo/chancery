"""Shared authentication for username/password logins.

Order: local database first — so the bootstrap admin keeps working even when
the directory is down — then LDAP when LDAP_ENABLED is true. Local accounts
never fall through to LDAP, so a directory entry cannot shadow the
break-glass admin.

Follows the audit_service convention: may log audit entries but never
commits; callers commit as part of their transaction.
"""
import hashlib
import hmac
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Optional

from flask import current_app
from werkzeug.security import generate_password_hash

from ..extensions import db
from ..models.user import User
from . import audit_service, ldap_service, ldap_settings_service
from .ldap_service import LdapUnavailableError

# Failure reasons returned in AuthResult.reason
REASON_INVALID = "invalid_credentials"
REASON_DEACTIVATED = "account_deactivated"
REASON_LDAP_UNREACHABLE = "ldap_unreachable"
REASON_LDAP_NO_ROLE = "ldap_no_role"
REASON_LOCKED = "account_locked"


@dataclass
class AuthResult:
    user: Optional[User]
    reason: Optional[str]  # None on success
    auth_method: str  # "local" or "ldap"

    @property
    def ok(self):
        return self.user is not None and self.reason is None


def authenticate(username, password):
    """Authenticate a username/password pair. Returns an AuthResult."""
    if not username or not password:
        _burn_hash()
        return AuthResult(None, REASON_INVALID, "local")

    user = User.query.filter_by(username=username).first()

    # Local accounts authenticate locally only.
    if user is not None and user.auth_source == "local":
        # D1: reject while the account is in a brute-force lockout window.
        if _is_locked(user):
            return AuthResult(user, REASON_LOCKED, "local")
        if not user.check_password(password):
            _register_failed_attempt(user)
            return AuthResult(None, REASON_INVALID, "local")
        if not user.is_active:
            return AuthResult(user, REASON_DEACTIVATED, "local")
        _reset_lockout(user)
        return AuthResult(user, None, "local")

    if not ldap_settings_service.effective_config()["LDAP_ENABLED"]:
        # Unknown user, or an LDAP-provisioned user with LDAP now disabled.
        _burn_hash()
        return AuthResult(None, REASON_INVALID, "local")

    try:
        ldap_result = ldap_service.authenticate_ldap(username, password)
    except LdapUnavailableError:
        return AuthResult(None, REASON_LDAP_UNREACHABLE, "ldap")

    if ldap_result is None:
        return AuthResult(None, REASON_INVALID, "ldap")

    role = _map_role(ldap_result.groups)
    if role is None:
        return AuthResult(None, REASON_LDAP_NO_ROLE, "ldap")

    if user is None:
        user = _provision_user(username, role, ldap_result.dn)
    else:
        _sync_role(user, role)

    if not user.is_active:
        # Local deactivation always wins over directory state.
        return AuthResult(user, REASON_DEACTIVATED, "ldap")

    return AuthResult(user, None, "ldap")


def _burn_hash():
    """Equalize response timing when no real hash comparison happens."""
    generate_password_hash("dummy-password")


def _now():
    return datetime.now(timezone.utc)


def _is_locked(user):
    """True while a brute-force lockout window is active (D1)."""
    lu = user.locked_until
    if lu is None:
        return False
    if lu.tzinfo is None:  # SQLite stores naive UTC
        lu = lu.replace(tzinfo=timezone.utc)
    return lu > _now()


def _register_failed_attempt(user):
    """Count a failed local login and lock the account past the threshold (D1).

    Commits directly (unlike audit logging) so the counter survives the
    stateless Basic-Auth path and concurrent workers. LOGIN_LOCKOUT_THRESHOLD<=0
    disables lockout.
    """
    threshold = current_app.config.get("LOGIN_LOCKOUT_THRESHOLD", 5)
    if threshold <= 0:
        return
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= threshold:
        if _is_last_active_admin(user):
            # DoS-2: never hard-lock the sole administrator — otherwise an
            # unauthenticated attacker could lock the only admin out of the whole
            # app (a self-DoS). Reset the window and keep serving; the
            # per-attempt hash cost + a strong password remain the throttle.
            user.failed_login_count = 0
        else:
            minutes = current_app.config.get("LOGIN_LOCKOUT_MINUTES", 15)
            user.locked_until = _now() + timedelta(minutes=minutes)
            user.failed_login_count = 0
    db.session.add(user)
    db.session.commit()


def _is_last_active_admin(user):
    """True if `user` is the only remaining active admin (mirrors the deactivate
    / demote guards in the users routes)."""
    if user.role != "admin":
        return False
    return User.query.filter_by(role="admin", is_active_user=True).count() <= 1


def _reset_lockout(user):
    """Clear the failure counter / lock on a successful login (D1)."""
    if user.failed_login_count or user.locked_until:
        user.failed_login_count = 0
        user.locked_until = None
        db.session.add(user)
        db.session.commit()


def clear_lockout(user):
    """Clear the failure counter and any active lock (AUTH-4: admin unlock,
    password reset, reactivation). Does NOT commit — the caller commits as part
    of its own transaction."""
    user.failed_login_count = 0
    user.locked_until = None
    db.session.add(user)


def map_ldap_role(groups):
    """Role the current LDAP group mapping would assign (settings test UI)."""
    return _map_role(groups)


def _map_role(groups):
    """Map LDAP group DNs to an application role.

    - Member of LDAP_ADMIN_GROUP_DN -> admin
    - Member of LDAP_REQUESTER_GROUP_DN -> csr_requester
    - Any group gate configured but user in none of the mapped groups -> None
      (rejected). D6: configuring only LDAP_ADMIN_GROUP_DN must NOT admit the
      whole directory as csr_requester — a configured admin group also gates.
    - No group gate configured at all -> csr_requester (open to any directory
      user who can bind).
    """
    ldap_cfg = ldap_settings_service.effective_config()
    admin_group = (ldap_cfg["LDAP_ADMIN_GROUP_DN"] or "").strip().lower()
    requester_group = (ldap_cfg["LDAP_REQUESTER_GROUP_DN"] or "").strip().lower()

    if admin_group and admin_group in groups:
        return "admin"
    if requester_group and requester_group in groups:
        return "csr_requester"
    if admin_group or requester_group:
        return None  # a gate is configured and the user matched no mapped group
    return "csr_requester"


def _provision_user(username, role, dn):
    user = User(username=username, role=role, auth_source="ldap")
    user.set_unusable_password()
    db.session.add(user)
    db.session.flush()  # assign user.id for the audit log target
    audit_service.log_action(
        "ldap_user_provisioned",
        target_type="user",
        target_id=user.id,
        details={"username": username, "role": role, "dn": dn},
    )
    return user


def _sync_role(user, role):
    if user.role == role:
        return
    old_role = user.role
    user.role = role
    audit_service.log_action(
        "ldap_role_synced",
        target_type="user",
        target_id=user.id,
        details={"username": user.username, "old_role": old_role, "new_role": role},
    )


class CredentialCache:
    """Short-TTL in-memory cache of verified Basic Auth credentials.

    Basic Auth is stateless, so without a cache every request pays a full
    credential verification: an LDAP bind for directory users, an expensive
    password-hash check for local ones. This cache stores an HMAC of the
    credentials (never the password; the HMAC key is random per process) keyed
    by username, together with the verified user id and auth backend.

    A hit only skips the credential verification — the User row is re-read on
    every request, so deactivation, role changes, and deletion apply
    immediately. Failed authentications are never cached. A TTL of 0 disables
    caching entirely.
    """

    def __init__(self, ttl_seconds, max_entries=256):
        self._ttl = ttl_seconds
        self._max = max_entries
        self._key = os.urandom(32)  # per-process; cache empties on restart
        self._entries = {}  # username -> (mac, user_id, auth_method, expires_at)
        self._lock = threading.Lock()

    @property
    def enabled(self):
        return self._ttl > 0

    def _mac(self, username, password):
        message = f"{username}\x00{password}".encode()
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def get(self, username, password):
        """Return (user_id, auth_method) for a valid cached entry, else None."""
        if not self.enabled:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(username)
            if entry is None:
                return None
            mac, user_id, auth_method, expires_at = entry
            if now >= expires_at:
                del self._entries[username]
                return None
            if not hmac.compare_digest(mac, self._mac(username, password)):
                # Wrong password: miss, but keep the valid entry in place so
                # probing cannot evict a legitimate client's cache.
                return None
            return user_id, auth_method

    def put(self, username, password, user_id, auth_method):
        if not self.enabled:
            return
        now = time.monotonic()
        with self._lock:
            if username not in self._entries and len(self._entries) >= self._max:
                expired = [u for u, e in self._entries.items() if e[3] <= now]
                for u in expired:
                    del self._entries[u]
                if len(self._entries) >= self._max:
                    oldest = min(self._entries, key=lambda u: self._entries[u][3])
                    del self._entries[oldest]
            self._entries[username] = (
                self._mac(username, password), user_id, auth_method, now + self._ttl,
            )

    def clear(self):
        with self._lock:
            self._entries.clear()


def authenticate_basic(username, password):
    """Authenticate Basic Auth credentials through the credential cache.

    Same semantics as authenticate() — local first, then LDAP — but a recent
    successful verification of the same credentials skips the expensive part
    (LDAP bind / password hash). The User row is still fetched fresh, so a
    cache hit never resurrects a deactivated, renamed, or deleted account.
    """
    if not username or not password:
        _burn_hash()
        return AuthResult(None, REASON_INVALID, "local")

    cache = getattr(current_app, "basic_auth_cache", None)
    if cache is not None:
        hit = cache.get(username, password)
        if hit is not None:
            user_id, auth_method = hit
            user = db.session.get(User, user_id)
            if user is not None and user.username == username and user.is_active:
                return AuthResult(user, None, auth_method)
            # Stale entry — fall through to a full authentication.

    result = authenticate(username, password)
    if result.ok and cache is not None:
        cache.put(username, password, result.user.id, result.auth_method)
    return result
