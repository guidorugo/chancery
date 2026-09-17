"""F14 (3.2.0): ACME server state — RFC 8555 accounts, orders, authorizations,
challenges, replay nonces and the admin-issued external-account-binding keys.

Every directory is per CA (`/acme/<ca_id>/directory`), so accounts, orders and
EAB keys carry `ca_id`. Datetimes are naive UTC like the rest of the schema.
"""
import json
from datetime import datetime, timezone

from ..extensions import db
from ..serialization import iso


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AcmeEabKey(db.Model):
    """External Account Binding MAC key (RFC 8555 §7.3.4): an admin issues
    `kid` + a MAC key; a client presents them once at newAccount. The MAC key is
    Fernet-wrapped under MASTER_PASSPHRASE (registered in passphrase_service)."""
    __tablename__ = "acme_eab_keys"

    id = db.Column(db.Integer, primary_key=True)
    ca_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=False, index=True)
    kid = db.Column(db.String(64), unique=True, nullable=False)
    hmac_key_enc = db.Column(db.LargeBinary, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow)
    used_at = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, nullable=False, default=False)

    ca = db.relationship("CertificateAuthority", backref=db.backref("acme_eab_keys", lazy="dynamic"))

    @property
    def status(self):
        if self.revoked:
            return "revoked"
        return "used" if self.used_at else "unused"

    def to_dict(self):
        return {"id": self.id, "ca_id": self.ca_id, "kid": self.kid, "name": self.name, "status": self.status,
                "created_at": iso(self.created_at), "used_at": iso(self.used_at)}


class AcmeAccount(db.Model):
    __tablename__ = "acme_accounts"
    __table_args__ = (db.UniqueConstraint("ca_id", "thumbprint", name="ux_acme_accounts_ca_thumbprint"),)

    id = db.Column(db.Integer, primary_key=True)
    ca_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=False, index=True)
    jwk_json = db.Column(db.Text, nullable=False)
    thumbprint = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="valid")   # valid | deactivated | revoked
    contact_json = db.Column(db.Text, nullable=True)
    eab_key_id = db.Column(db.Integer, db.ForeignKey("acme_eab_keys.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow)
    last_seen_at = db.Column(db.DateTime, nullable=True)

    ca = db.relationship("CertificateAuthority", backref=db.backref("acme_accounts", lazy="dynamic"))
    eab_key = db.relationship("AcmeEabKey", foreign_keys=[eab_key_id])

    @property
    def jwk(self):
        return json.loads(self.jwk_json)

    @property
    def contact(self):
        return json.loads(self.contact_json) if self.contact_json else []

    def to_dict(self):
        return {"id": self.id, "ca_id": self.ca_id, "status": self.status, "contact": self.contact,
                "thumbprint": self.thumbprint, "eab_kid": self.eab_key.kid if self.eab_key else None,
                "created_at": iso(self.created_at), "last_seen_at": iso(self.last_seen_at)}


class AcmeOrder(db.Model):
    __tablename__ = "acme_orders"

    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey("acme_accounts.id"), nullable=False, index=True)
    ca_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="pending")   # pending|ready|processing|valid|invalid
    identifiers_json = db.Column(db.Text, nullable=False)
    expires = db.Column(db.DateTime, nullable=False)
    csr_pem = db.Column(db.Text, nullable=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificates.id"), nullable=True)
    error_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow)
    finalized_at = db.Column(db.DateTime, nullable=True)

    account = db.relationship("AcmeAccount", backref=db.backref("orders", lazy="dynamic"))
    certificate = db.relationship("Certificate", foreign_keys=[certificate_id])
    authorizations = db.relationship("AcmeAuthorization", backref="order", lazy="selectin",
                                     order_by="AcmeAuthorization.id")

    @property
    def identifiers(self):
        return json.loads(self.identifiers_json)

    @property
    def error(self):
        return json.loads(self.error_json) if self.error_json else None


class AcmeAuthorization(db.Model):
    __tablename__ = "acme_authorizations"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("acme_orders.id"), nullable=False, index=True)
    account_id = db.Column(db.Integer, db.ForeignKey("acme_accounts.id"), nullable=False, index=True)
    ca_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=False)
    identifier_type = db.Column(db.String(10), nullable=False, default="dns")
    identifier_value = db.Column(db.String(253), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")   # pending|valid|invalid|expired|deactivated
    expires = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)

    challenges = db.relationship("AcmeChallenge", backref="authorization", lazy="selectin",
                                 order_by="AcmeChallenge.id")


class AcmeChallenge(db.Model):
    __tablename__ = "acme_challenges"

    id = db.Column(db.Integer, primary_key=True)
    authorization_id = db.Column(db.Integer, db.ForeignKey("acme_authorizations.id"), nullable=False, index=True)
    type = db.Column(db.String(20), nullable=False, default="http-01")
    token = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="pending")   # pending|processing|valid|invalid
    validated_at = db.Column(db.DateTime, nullable=True)
    error_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow)

    @property
    def error(self):
        return json.loads(self.error_json) if self.error_json else None


class AcmeNonce(db.Model):
    """Single-use replay nonces (RFC 8555 §6.5); pruned by the scheduler."""
    __tablename__ = "acme_nonces"

    value = db.Column(db.String(64), primary_key=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
