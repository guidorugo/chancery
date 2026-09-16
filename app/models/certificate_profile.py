"""Certificate profiles (F1, 2.13.0): stored, server-enforced issuance policy.

A profile fixes the Key Usage / Extended Key Usage of the certificates issued
under it and can bound validity, key type/size and SAN types. The built-in
profiles reproduce the presets the create/sign forms used to hold as
JavaScript, plus `custom`, which carries no restriction beyond the global
policy (`MIN_RSA_KEY_SIZE`, `MAX_CERT_VALIDITY_DAYS`, ...) and keeps legacy
behaviour for requests that name no profile.
"""
import json
from datetime import datetime, timezone

from ..extensions import db
from ..serialization import iso


def _load(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class CertificateProfile(db.Model):
    __tablename__ = "certificate_profiles"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)     # stable API/CLI handle
    name = db.Column(db.String(100), unique=True, nullable=False)   # display name
    description = db.Column(db.String(500), nullable=False, default="")
    is_builtin = db.Column(db.Boolean, nullable=False, default=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    # Extensions stamped on issued certificates (None = caller's choice / service default)
    key_usage_json = db.Column(db.Text, nullable=True)
    extended_key_usage_json = db.Column(db.Text, nullable=True)
    include_ocsp_aia = db.Column(db.Boolean, nullable=False, default=True)
    # F3: policies stamped on certificates issued under this profile (None = inherit the CA's).
    certificate_policies_json = db.Column(db.Text, nullable=True)

    # Bounds (None / empty = unrestricted, global policy still applies)
    default_validity_days = db.Column(db.Integer, nullable=False, default=365)
    max_validity_days = db.Column(db.Integer, nullable=True)
    allowed_key_types_json = db.Column(db.Text, nullable=True)
    min_rsa_bits = db.Column(db.Integer, nullable=True)
    max_rsa_bits = db.Column(db.Integer, nullable=True)
    allowed_ec_sizes_json = db.Column(db.Text, nullable=True)
    allowed_san_types_json = db.Column(db.Text, nullable=True)
    require_san = db.Column(db.Boolean, nullable=False, default=False)
    cn_in_san = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # -- decoded views ---------------------------------------------------------
    @property
    def is_custom(self):
        return self.key == "custom"

    @property
    def key_usage(self):
        return _load(self.key_usage_json, None)

    @property
    def extended_key_usage(self):
        return _load(self.extended_key_usage_json, None)

    @property
    def certificate_policies(self):
        return _load(self.certificate_policies_json, None)

    @property
    def allowed_key_types(self):
        return _load(self.allowed_key_types_json, None)

    @property
    def allowed_ec_sizes(self):
        return _load(self.allowed_ec_sizes_json, None)

    @property
    def allowed_san_types(self):
        return _load(self.allowed_san_types_json, None)

    def to_dict(self):
        return {
            "id": self.id,
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "is_builtin": self.is_builtin,
            "is_custom": self.is_custom,
            "enabled": self.enabled,
            "key_usage": self.key_usage,
            "extended_key_usage": self.extended_key_usage,
            "include_ocsp_aia": self.include_ocsp_aia,
            "certificate_policies": self.certificate_policies,
            "default_validity_days": self.default_validity_days,
            "max_validity_days": self.max_validity_days,
            "allowed_key_types": self.allowed_key_types,
            "min_rsa_bits": self.min_rsa_bits,
            "max_rsa_bits": self.max_rsa_bits,
            "allowed_ec_sizes": self.allowed_ec_sizes,
            "allowed_san_types": self.allowed_san_types,
            "require_san": self.require_san,
            "cn_in_san": self.cn_in_san,
            "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at),
        }

    def __repr__(self):
        return f"<CertificateProfile {self.key}>"
