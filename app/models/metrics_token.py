"""Dedicated bearer token for the Prometheus ``/metrics`` endpoint (2.7.0).

A ``MetricsToken`` is deliberately **NOT** a ``User``: it carries no role, cannot
log in, and is accepted by nothing except the ``/metrics`` view (least privilege).
Each token has a required name and a required expiry, is individually revocable,
and its secret is stored only as a SHA-256 hash — the plaintext is shown once at
creation and never again.

Token string format: ``cmt_<token_id>_<secret>`` where both parts are hex, so the
first ``_`` after the (hex-only) ``token_id`` unambiguously separates the two. The
public ``token_id`` allows an O(1) indexed lookup without scanning every row; the
high-entropy ``secret`` is compared against the stored hash in constant time.
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from ..extensions import db
from ..serialization import iso, days_until, expiry_status as _expiry_status

TOKEN_PREFIX = "cmt_"


def _now_naive_utc():
    """Naive-UTC now, matching how the datetime columns are stored/compared."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class MetricsToken(db.Model):
    __tablename__ = "metrics_tokens"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    # Public, non-secret lookup id (indexed) so verify() is O(1), not a row scan.
    token_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    # SHA-256 hex of the high-entropy secret — never the secret itself.
    token_hash = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)  # required; naive-UTC
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    last_used_at = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, nullable=False, default=False)

    # ---- secret handling -------------------------------------------------
    @staticmethod
    def hash_secret(secret):
        return hashlib.sha256(secret.encode()).hexdigest()

    @classmethod
    def generate(cls, name, expires_at, created_by=None):
        """Build an unsaved token. Returns ``(plaintext, row)``; the plaintext is
        the only time the secret exists — persist ``row`` and show the plaintext
        to the operator once."""
        token_id = secrets.token_hex(8)    # 16 hex chars (public)
        secret = secrets.token_hex(32)     # 64 hex chars = 256-bit (secret)
        row = cls(
            name=name,
            token_id=token_id,
            token_hash=cls.hash_secret(secret),
            expires_at=expires_at,
            created_by=created_by,
        )
        return f"{TOKEN_PREFIX}{token_id}_{secret}", row

    @staticmethod
    def split(presented):
        """Parse ``cmt_<token_id>_<secret>`` → ``(token_id, secret)`` or
        ``(None, None)``. token_id is hex (no ``_``), so the first ``_`` after it
        is the separator regardless of the secret's contents."""
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

    # ---- display ---------------------------------------------------------
    @property
    def days_until_expiry(self):
        return days_until(self.expires_at)

    @property
    def expiry_status(self):
        return _expiry_status(self.expires_at)

    @property
    def status(self):
        if self.revoked:
            return "revoked"
        if self.expires_at is not None and self.expires_at <= _now_naive_utc():
            return "expired"
        return "active"

    def to_dict(self):
        # NEVER expose token_hash or the secret.
        return {
            "id": self.id,
            "name": self.name,
            "token_id": self.token_id,
            "status": self.status,
            "expires_at": iso(self.expires_at),
            "created_at": iso(self.created_at),
            "last_used_at": iso(self.last_used_at),
            "revoked": self.revoked,
        }

    def __repr__(self):
        return f"<MetricsToken {self.name} ({self.token_id})>"
