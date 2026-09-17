import json
from datetime import datetime, timezone

from ..extensions import db
from ..serialization import iso, days_until, expiry_status as _expiry_status


class CertificateAuthority(db.Model):
    __tablename__ = "certificate_authorities"
    # 2.27.1: a name is unique among CAs that are NOT revoked, so a revoked
    # CA's name can be reused. Fresh databases get this partial unique index
    # from create_all(); an upgraded database has the original table-level
    # UNIQUE(name) removed by _migrate_schema (SQLite table rebuild).
    __table_args__ = (
        db.Index("ux_certificate_authorities_name_active", "name", unique=True,
                 sqlite_where=db.text("is_revoked IS NOT 1"),
                 postgresql_where=db.text("is_revoked IS NOT TRUE")),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    common_name = db.Column(db.String(200), nullable=False)
    serial_number = db.Column(db.String(100), nullable=False, unique=True)  # G9-1
    certificate_pem = db.Column(db.Text, nullable=False)
    private_key_enc = db.Column(db.LargeBinary, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=True)
    is_root = db.Column(db.Boolean, default=True)
    key_type = db.Column(db.String(10), nullable=False)  # RSA or EC
    key_size = db.Column(db.Integer, nullable=False)
    not_before = db.Column(db.DateTime, nullable=False)
    not_after = db.Column(db.DateTime, nullable=False)
    path_length = db.Column(db.Integer, nullable=True)
    crl_number = db.Column(db.Integer, default=0)
    crl_pem = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_revoked = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revocation_reason = db.Column(db.String(50), nullable=True)
    # A1 key-backend: where this CA's signing key lives. "software" (default)
    # = Fernet-encrypted in private_key_enc; "softhsm" = inside a PKCS#11 token
    # (private_key_enc is the empty-bytes sentinel, key material never in memory).
    key_backend = db.Column(db.String(20), nullable=False, default="software")
    key_label = db.Column(db.String(200), nullable=True)
    # Dual control (2.10.0): a CA created while the mode is active starts
    # "pending" and cannot sign anything until a different admin approves it.
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    approval_status = db.Column(db.String(20), nullable=False, default="approved")  # approved/pending
    approved_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    # F1: JSON list of certificate_profiles.id this CA may issue under; NULL = any.
    allowed_profiles_json = db.Column(db.Text, nullable=True)
    expiry_notified_at = db.Column(db.DateTime, nullable=True)  # F10, same rule as Certificate
    # F2: {"permitted": [...], "excluded": [...]} in DNS:/IP:/EMAIL:/URI: spelling; NULL = unconstrained.
    name_constraints_json = db.Column(db.Text, nullable=True)
    # F3: [{"oid": ..., "cps_uri": ...|null}] stamped on this CA's certificate and inherited by its leaves.
    certificate_policies_json = db.Column(db.Text, nullable=True)
    # F7: delegated OCSP responder — short-lived cert issued by this CA and its
    # Fernet-wrapped key (always software, registered in passphrase_service).
    ocsp_responder_cert_pem = db.Column(db.Text, nullable=True)
    ocsp_responder_key_enc = db.Column(db.LargeBinary, nullable=True)
    # F14 (3.2.0): per-CA ACME directory settings. Enabling ACME is the approved
    # act under dual control; orders afterwards are automated issuance.
    acme_enabled = db.Column(db.Boolean, nullable=False, default=False)
    acme_profile_id = db.Column(db.Integer, db.ForeignKey("certificate_profiles.id"), nullable=True)
    acme_require_eab = db.Column(db.Boolean, nullable=False, default=True)

    parent = db.relationship("CertificateAuthority", remote_side=[id], backref="children")
    certificates = db.relationship("Certificate", backref="ca", lazy="dynamic")
    csrs = db.relationship("CertificateSigningRequest", backref="ca", lazy="dynamic")
    creator = db.relationship("User", foreign_keys=[created_by])
    acme_profile = db.relationship("CertificateProfile", foreign_keys=[acme_profile_id])
    approver = db.relationship("User", foreign_keys=[approved_by])

    @property
    def has_private_key(self):
        """False for CAs imported certificate-only (empty-bytes sentinel).

        Retained for templates/audit that mean "software key material is
        stored". For "can this CA sign?" use `has_signing_key`, which is also
        true for HSM-backed CAs that hold no bytes here.
        """
        return bool(self.private_key_enc)

    @property
    def has_signing_key(self):
        """True if this CA can sign (leaf certs, CRLs, OCSP, sub-CAs).

        Software CAs hold encrypted bytes; HSM CAs hold the key in the token
        (no bytes here). False only for certificate-only imports.
        """
        return self.key_backend == "softhsm" or bool(self.private_key_enc)

    @property
    def is_exportable(self):
        """True only when the private key can be handed out (software + stored).
        HSM keys are non-extractable, so key/PKCS#12 export is refused."""
        return self.key_backend != "softhsm" and bool(self.private_key_enc)

    @property
    def allowed_profile_ids(self):
        """List of allowed profile ids, or None when unrestricted (F1)."""
        if not self.allowed_profiles_json:
            return None
        try:
            import json
            ids = json.loads(self.allowed_profiles_json)
            return [int(i) for i in ids] if isinstance(ids, list) else None
        except (TypeError, ValueError):
            return None

    def set_allowed_profile_ids(self, ids):
        import json
        self.allowed_profiles_json = json.dumps(sorted({int(i) for i in ids})) if ids else None

    @property
    def is_pending_approval(self):
        """True while a dual-control-created CA awaits a second admin."""
        return self.approval_status == "pending"

    @classmethod
    def signing_capable(cls):
        """Query for CAs that can sign: not revoked, approved (dual control),
        and holding a usable key (software bytes present, or key in an HSM
        token)."""
        return cls.query.filter_by(is_revoked=False).filter(
            cls.approval_status == "approved",
            db.or_(cls.key_backend == "softhsm", cls.private_key_enc != b""),
        )

    @property
    def name_constraints(self):
        """Stored name constraints (F2) as a dict, or None."""
        if not self.name_constraints_json:
            return None
        try:
            return json.loads(self.name_constraints_json)
        except ValueError:
            return None

    def set_name_constraints(self, constraints):
        self.name_constraints_json = json.dumps(constraints) if constraints else None

    @property
    def certificate_policies(self):
        """Stored certificate policies (F3) as a list, or None."""
        if not self.certificate_policies_json:
            return None
        try:
            return json.loads(self.certificate_policies_json)
        except ValueError:
            return None

    def set_certificate_policies(self, policies):
        self.certificate_policies_json = json.dumps(policies) if policies else None

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
            "name": self.name,
            "common_name": self.common_name,
            "serial_number": self.serial_number,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "key_backend": self.key_backend,
            "is_root": self.is_root,
            "parent_id": self.parent_id,
            "not_before": iso(self.not_before),
            "not_after": iso(self.not_after),
            "days_until_expiry": self.days_until_expiry,
            "expiry_status": self.expiry_status,
            "expiry_notified_at": iso(self.expiry_notified_at),
            "is_revoked": self.is_revoked,
            "has_private_key": self.has_private_key,
            "has_signing_key": self.has_signing_key,
            "is_exportable": self.is_exportable,
            "approval_status": self.approval_status,
            "created_by": self.created_by,
            "allowed_profiles": self.allowed_profile_ids,
            "name_constraints": self.name_constraints,
            "certificate_policies": self.certificate_policies,
            "acme": {"enabled": bool(self.acme_enabled), "require_eab": bool(self.acme_require_eab),
                     "profile": self.acme_profile.key if self.acme_profile else None},
            "created_at": iso(self.created_at),
        }
        if detail:
            from ..services import ocsp_service
            d["ocsp_responder"] = ocsp_service.responder_status(self)
            d["alternate_certificates"] = [a.to_dict() for a in self.alternate_certificates]  # F11
            d.update({
                "path_length": self.path_length,
                "crl_number": self.crl_number,
                "revoked_at": iso(self.revoked_at),
                "revocation_reason": self.revocation_reason,
                "approved_by": self.approved_by,
                "approved_at": iso(self.approved_at),
                "certificate_pem": self.certificate_pem,
            })
        return d

    def __repr__(self):
        return f"<CA {self.name}>"
