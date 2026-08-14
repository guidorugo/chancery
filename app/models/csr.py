from datetime import datetime, timezone

from ..extensions import db
from ..serialization import iso, json_or_none


class CertificateSigningRequest(db.Model):
    __tablename__ = "certificate_signing_requests"

    id = db.Column(db.Integer, primary_key=True)
    common_name = db.Column(db.String(200), nullable=False)
    subject_json = db.Column(db.Text, nullable=False)
    csr_pem = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending/approved/rejected
    ca_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificates.id"), nullable=True)
    san_json = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    signed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    certificate = db.relationship("Certificate", backref="csr")
    creator = db.relationship("User", backref="csrs", foreign_keys=[created_by])
    signer = db.relationship("User", foreign_keys=[signed_by])

    def to_dict(self, detail=False):
        d = {
            "id": self.id,
            "common_name": self.common_name,
            "status": self.status,
            "ca_id": self.ca_id,
            "certificate_id": self.certificate_id,
            "created_by": self.created_by,
            "signed_by": self.signed_by,
            "created_at": iso(self.created_at),
        }
        if detail:
            d.update({
                "subject": json_or_none(self.subject_json),
                "sans": json_or_none(self.san_json),
                "csr_pem": self.csr_pem,
            })
        return d

    def __repr__(self):
        return f"<CSR {self.common_name} ({self.status})>"
