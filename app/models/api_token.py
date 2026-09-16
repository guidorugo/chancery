"""Scoped API tokens (F12, 2.26.0).

A bearer credential for programmatic access that is *not* the user's password:
`Authorization: Bearer chy_api_<token_id>_<secret>`. A token belongs to a user,
carries a subset of scopes (`read`, `issue`, `revoke`, `admin`), a required
expiry, and can be revoked; it never grants more than its owner's role. The
secret is stored only as a SHA-256 hash and shown once at creation.

The `chy_api_` prefix keeps API tokens distinguishable from the Prometheus
`cmt_` metrics tokens: each endpoint refuses the other kind.
"""
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone

from ..extensions import db
from ..serialization import iso, days_until

TOKEN_PREFIX = "chy_api_"
SCOPES = ("read", "issue", "revoke", "admin")
SCOPE_LABELS = {
    "read": "Read — list and view everything the account may see",
    "issue": "Issue — create CSRs, sign CSRs, create and renew certificates",
    "revoke": "Revoke — revoke certificates and CAs, regenerate CRLs",
    "admin": "Admin — everything else the account's role allows (CAs, users, settings)",
}


def _now_naive_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ApiToken(db.Model):
    __tablename__ = "api_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    token_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    token_hash = db.Column(db.String(64), nullable=False)
    scopes_json = db.Column(db.Text, nullable=False, default='["read"]')
    expires_at = db.Column(db.DateTime, nullable=False)        # naive UTC
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    last_used_at = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, nullable=False, default=False)

    user = db.relationship("User", foreign_keys=[user_id], backref=db.backref("api_tokens", lazy="dynamic"))

    __table_args__ = (db.UniqueConstraint("user_id", "name", name="ux_api_tokens_user_name"),)

    # ---- secret handling -------------------------------------------------
    @staticmethod
    def hash_secret(secret):
        return hashlib.sha256(secret.encode()).hexdigest()

    @classmethod
    def generate(cls, user_id, name, scopes, expires_at, created_by=None):
        token_id = secrets.token_hex(8)
        secret = secrets.token_hex(32)
        row = cls(user_id=user_id, name=name, token_id=token_id, token_hash=cls.hash_secret(secret),
                  scopes_json=json.dumps(sorted(set(scopes))), expires_at=expires_at, created_by=created_by)
        return f"{TOKEN_PREFIX}{token_id}_{secret}", row

    @staticmethod
    def split(presented):
        if not presented or not presented.startswith(TOKEN_PREFIX):
            return None, None
        token_id, sep, secret = presented[len(TOKEN_PREFIX):].partition("_")
        if not sep or not token_id or not secret:
            return None, None
        return token_id, secret

    def matches(self, secret):
        return hmac.compare_digest(self.token_hash, self.hash_secret(secret))

    def is_valid(self, now=None):
        now = now or _now_naive_utc()
        return (not self.revoked) and self.expires_at is not None and self.expires_at > now

    # ---- scopes ------------------------------------------------------------
    @property
    def scopes(self):
        try:
            return list(json.loads(self.scopes_json or "[]"))
        except ValueError:
            return []

    def has_scope(self, scope):
        scopes = self.scopes
        return scope in scopes or "admin" in scopes

    # ---- display -----------------------------------------------------------
    @property
    def status(self):
        if self.revoked:
            return "revoked"
        if self.expires_at is not None and self.expires_at <= _now_naive_utc():
            return "expired"
        return "active"

    @property
    def days_until_expiry(self):
        return days_until(self.expires_at)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username if self.user else None,
            "name": self.name,
            "token_id": self.token_id,
            "scopes": self.scopes,
            "status": self.status,
            "expires_at": iso(self.expires_at),
            "days_until_expiry": self.days_until_expiry,
            "last_used_at": iso(self.last_used_at),
            "created_at": iso(self.created_at),
            "created_by": self.created_by,
        }

    def __repr__(self):
        return f"<ApiToken {self.name} user={self.user_id} {self.status}>"
