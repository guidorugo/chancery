"""Alternate certificates for a CA's key (F11, 2.25.0).

`certificate_authorities.certificate_pem` stays the *primary* certificate every
existing reader uses. This table holds the alternates for the same key:

- `previous` — a superseded primary after a re-issue (kept so relying parties
  that pinned it can still be served);
- `cross` — a cross-certificate for this CA's public key issued by another
  CA (`issuer_ca_id`, or NULL when the issuer is external — imported);
- `reissue` — a re-issued certificate waiting for dual-control approval; on
  approval it becomes the primary and the old primary becomes `previous`.

Chain building (`ca_service.chain_pems(ca, via=)`) can route through an
approved alternate so a leaf's fullchain can be exported via either trust path.
"""
from datetime import datetime, timezone

from ..extensions import db
from ..serialization import iso

KINDS = ("previous", "cross", "reissue")


class CaCertificate(db.Model):
    __tablename__ = "ca_certificates"

    id = db.Column(db.Integer, primary_key=True)
    ca_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=False, index=True)
    kind = db.Column(db.String(16), nullable=False)
    certificate_pem = db.Column(db.Text, nullable=False)
    issuer_ca_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=True)
    serial_number = db.Column(db.String(100), nullable=False)
    not_before = db.Column(db.DateTime, nullable=False)
    not_after = db.Column(db.DateTime, nullable=False)
    approval_status = db.Column(db.String(20), nullable=False, default="approved")  # approved / pending
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    approved_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    ca = db.relationship("CertificateAuthority", foreign_keys=[ca_id],
                         backref=db.backref("alternate_certificates", lazy="selectin", order_by="CaCertificate.id"))
    issuer = db.relationship("CertificateAuthority", foreign_keys=[issuer_ca_id])

    @property
    def is_usable(self):
        """Approved and, for a cross-certificate, issued by a CA that is not revoked."""
        if self.approval_status != "approved":
            return False
        if self.kind == "cross" and self.issuer is not None and self.issuer.is_revoked:
            return False
        return True

    def to_dict(self):
        return {
            "id": self.id,
            "ca_id": self.ca_id,
            "kind": self.kind,
            "issuer_ca_id": self.issuer_ca_id,
            "issuer_name": self.issuer.name if self.issuer is not None else None,
            "serial_number": self.serial_number,
            "not_before": iso(self.not_before),
            "not_after": iso(self.not_after),
            "approval_status": self.approval_status,
            "usable": self.is_usable,
            "created_at": iso(self.created_at),
        }

    def __repr__(self):
        return f"<CaCertificate {self.kind} ca={self.ca_id} serial={self.serial_number[:12]}>"
