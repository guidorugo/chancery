from datetime import datetime, timezone

from ..extensions import db
from ..serialization import iso, json_or_none, days_until, expiry_status as _expiry_status


class Certificate(db.Model):
    __tablename__ = "certificates"

    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    common_name = db.Column(db.String(200), nullable=False)
    subject_json = db.Column(db.Text, nullable=False)
    certificate_pem = db.Column(db.Text, nullable=False)
    private_key_enc = db.Column(db.LargeBinary, nullable=True)
    ca_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=False)
    key_type = db.Column(db.String(10), nullable=False)
    key_size = db.Column(db.Integer, nullable=False)
    not_before = db.Column(db.DateTime, nullable=False)
    not_after = db.Column(db.DateTime, nullable=False)
    san_json = db.Column(db.Text, nullable=True)
    key_usage_json = db.Column(db.Text, nullable=True)
    extended_key_usage_json = db.Column(db.Text, nullable=True)
    is_revoked = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revocation_reason = db.Column(db.String(50), nullable=True)
    requested_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    # Who actually issued it: the CSR's signer, or the admin who created it
    # directly. NULL on legacy rows until `flask certs backfill-issuers`.
    issued_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    requester = db.relationship("User", backref="certificates", foreign_keys=[requested_by])
    issuer_user = db.relationship("User", foreign_keys=[issued_by])

    @property
    def days_until_expiry(self):
        """Whole days until notAfter (negative if already expired), or None."""
        return days_until(self.not_after)

    @property
    def expiry_status(self):
        """valid | expiring_soon | expired | unknown, using CERT_EXPIRY_WARNING_DAYS."""
        warning = 30
        try:
            from flask import current_app
            warning = current_app.config.get("CERT_EXPIRY_WARNING_DAYS", 30)
        except RuntimeError:
            pass  # outside an app context — fall back to the default
        return _expiry_status(self.not_after, warning)

    def to_dict(self, detail=False):
        d = {
            "id": self.id,
            "serial_number": self.serial_number,
            "common_name": self.common_name,
            "ca_id": self.ca_id,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "not_before": iso(self.not_before),
            "not_after": iso(self.not_after),
            "days_until_expiry": self.days_until_expiry,
            "expiry_status": self.expiry_status,
            "is_revoked": self.is_revoked,
            "requested_by": self.requested_by,
            "issued_by": self.issued_by,
            "created_at": iso(self.created_at),
        }
        if detail:
            d.update({
                "subject": json_or_none(self.subject_json),
                "sans": json_or_none(self.san_json),
                "key_usage": json_or_none(self.key_usage_json),
                "extended_key_usage": json_or_none(self.extended_key_usage_json),
                "revoked_at": iso(self.revoked_at),
                "revocation_reason": self.revocation_reason,
                "certificate_pem": self.certificate_pem,
            })
        return d

    def __repr__(self):
        return f"<Certificate {self.common_name} ({self.serial_number})>"
