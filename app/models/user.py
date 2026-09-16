from datetime import datetime, timezone

from flask import g
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from ..extensions import db, login_manager
from ..serialization import iso

# Sentinel stored in password_hash for externally-authenticated (LDAP) users.
# Never a valid werkzeug hash, and check_password() short-circuits on it.
UNUSABLE_PASSWORD = "!"


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="csr_requester")
    is_active_user = db.Column(db.Boolean, nullable=False, default=True)
    auth_source = db.Column(db.String(10), nullable=False, default="local")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # D1: brute-force lockout for local accounts.
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    # Force a password change on next login (set for the bootstrap admin created
    # from ADMIN_PASSWORD, so the seed credential can't become permanent).
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    # F13: TOTP second factor. The secret is Fernet-wrapped under
    # MASTER_PASSPHRASE (registered in passphrase_service); recovery codes are
    # werkzeug hashes, each usable once; totp_last_step blocks code replay.
    totp_secret_enc = db.Column(db.LargeBinary, nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    totp_confirmed_at = db.Column(db.DateTime, nullable=True)
    totp_last_step = db.Column(db.Integer, nullable=True)
    recovery_codes_json = db.Column(db.Text, nullable=True)
    # G6-4/G6-5: bumped on password change, admin reset and any 2FA change;
    # a session carrying an older value is no longer valid.
    session_version = db.Column(db.Integer, nullable=False, default=1)

    @property
    def is_active(self):
        return self.is_active_user

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_csr_requester(self):
        return self.role == "csr_requester"

    @property
    def is_ldap_user(self):
        return self.auth_source == "ldap"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def set_unusable_password(self):
        """Mark the account as externally authenticated (no local password)."""
        self.password_hash = UNUSABLE_PASSWORD

    def has_usable_password(self):
        return self.password_hash != UNUSABLE_PASSWORD

    def check_password(self, password):
        if not self.has_usable_password():
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def recovery_codes(self):
        import json
        try:
            return list(json.loads(self.recovery_codes_json or "[]"))
        except ValueError:
            return []

    def to_dict(self):
        # Never expose password_hash, the TOTP secret or the recovery codes.
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active_user,
            "auth_source": self.auth_source,
            "must_change_password": self.must_change_password,
            "totp_enabled": self.totp_enabled,
            "created_at": iso(self.created_at),
        }

    def __repr__(self):
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id):
    """Session login. G6-4: a session minted before the user's
    `session_version` was bumped (password change, admin reset, 2FA change)
    is refused, which logs that session out everywhere."""
    from flask import session
    user = db.session.get(User, int(user_id))
    if user is None:
        return None
    stamped = session.get("sv")
    if stamped is not None and stamped != user.session_version:
        return None
    return user


@login_manager.request_loader
def load_user_from_request(request):
    """Load user from Basic Auth header (set by before_request handler)."""
    return getattr(g, "basic_auth_user", None)
