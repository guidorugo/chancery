from datetime import datetime, timezone

from ..extensions import db
from ..serialization import iso, json_or_none


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    target_type = db.Column(db.String(50), nullable=True)
    target_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    # F16 (3.3.0): hash chain. NULL until the scheduler's lease holder seals
    # the row (in id order); prev_hash is the previous row's entry_hash ("" for
    # the first row), entry_hash = SHA-256(prev_hash || canonical row JSON).
    prev_hash = db.Column(db.String(64), nullable=True)
    entry_hash = db.Column(db.String(64), nullable=True)

    @property
    def sealed(self):
        return bool(self.entry_hash)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": iso(self.timestamp),
            "user_id": self.user_id,
            "username": self.username,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "details": json_or_none(self.details),
            "ip_address": self.ip_address,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    def __repr__(self):
        return f"<AuditLog {self.action} by {self.username}>"
