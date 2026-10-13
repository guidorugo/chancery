"""Component schemas of the OpenAPI document (F22, 3.8.0).

Every object schema mirrors a serializer (`to_dict`) or a route's literal JSON
payload and is closed with ``additionalProperties: false``: a field added to a
serializer later fails ``tests/test_openapi.py`` until it is documented here, so
every new exposure shows up as a schema diff in review.

JSON Schema 2020-12 (the OpenAPI 3.1 default dialect). Nothing in this module
may depend on the database or the request — see the static-document rule in
``builder.py``.
"""

ISO_DATETIME = {"type": "string", "format": "date-time",
                "description": "ISO 8601 timestamp (UTC)."}
NULLABLE_DATETIME = {"type": ["string", "null"], "format": "date-time",
                     "description": "ISO 8601 timestamp (UTC), or null."}
EXPIRY_STATUS = {"type": "string", "enum": ["valid", "expiring_soon", "expired", "unknown"],
                 "description": "`expiring_soon` within `CERT_EXPIRY_WARNING_DAYS` of notAfter."}


def _int(description=None, nullable=False):
    s = {"type": ["integer", "null"] if nullable else "integer"}
    if description:
        s["description"] = description
    return s


def _str(description=None, nullable=False, **extra):
    s = {"type": ["string", "null"] if nullable else "string"}
    if description:
        s["description"] = description
    s.update(extra)
    return s


def _bool(description=None):
    s = {"type": "boolean"}
    if description:
        s["description"] = description
    return s


def _ref(name):
    return {"$ref": f"#/components/schemas/{name}"}


def _array(items, description=None, nullable=False):
    s = {"type": ["array", "null"] if nullable else "array", "items": items}
    if description:
        s["description"] = description
    return s


def _obj(properties, required=None, description=None, **extra):
    s = {"type": "object", "properties": properties,
         "required": list(required) if required is not None else list(properties),
         "additionalProperties": False}
    if description:
        s["description"] = description
    s.update(extra)
    return s


def _extend(base, extra_properties, extra_required=(), description=None):
    """A copy of an object schema with additional properties (kept closed)."""
    props = dict(base["properties"])
    props.update(extra_properties)
    required = list(base["required"]) + list(extra_required)
    return _obj(props, required, description or base.get("description"))


def _nullable_ref(name):
    return {"oneOf": [_ref(name), {"type": "null"}]}


def _page(item_name, description):
    return _obj({
        "items": _array(_ref(item_name)),
        "page": _int("Current page (1-based)."),
        "per_page": _int("Rows per page (1–500)."),
        "total": _int("Matching rows."),
        "pages": _int("Total pages (at least 1)."),
    }, description=description)


# --- shared building blocks -------------------------------------------------------

ERROR = _obj({"error": _str("Human-readable reason.")},
             description="Error body of every JSON 4xx/5xx response.")

SUBJECT = {"type": ["object", "null"],
           "description": "Subject DN attributes that were set (CN, O, OU, C, ST, L).",
           "additionalProperties": {"type": "string"}}

KEY_USAGE = {"type": ["object", "null"],
             "description": "Key Usage bits (digital_signature, key_encipherment, content_commitment, "
                            "data_encipherment, key_agreement).",
             "additionalProperties": {"type": "boolean"}}

CERTIFICATE_POLICY = _obj({
    "oid": _str("Policy OID, dotted decimal."),
    "cps_uri": _str("CPS URL qualifier, or null.", nullable=True),
}, description="One Certificate Policies entry.")

NAME_CONSTRAINTS = _obj({
    "permitted": _array({"type": "string"}, "Permitted subtrees in SAN spelling (`DNS:`, `IP:<cidr>`, `EMAIL:`, `URI:`)."),
    "excluded": _array({"type": "string"}, "Excluded subtrees in SAN spelling."),
}, description="RFC 5280 Name Constraints carried by the CA certificate.")

ACME_SETTINGS = _obj({
    "enabled": _bool("ACME directory served for this CA (also needs `ACME_ENABLED`)."),
    "require_eab": _bool("New accounts need an admin-issued external account binding key."),
    "allow_wildcards": _bool("Wildcard identifiers accepted (dns-01 only)."),
    "profile": _str("Issuance profile key, or null for `custom`.", nullable=True),
}, description="Per-CA ACME settings.")

OCSP_RESPONDER_STATUS = _obj({
    "serial_number": _str("Responder certificate serial (hex)."),
    "not_before": ISO_DATETIME,
    "not_after": ISO_DATETIME,
    "days_left": _int("Whole days until the responder certificate expires."),
    "valid": _bool("Issued by the current CA certificate and within its validity."),
    "key_type": _str("Responder key algorithm (RSA, EC, ED25519, ED448)."),
}, description="Delegated OCSP responder certificate (`OCSP_DELEGATED_RESPONDER`).")

CA_CERTIFICATE = _obj({
    "id": _int(),
    "ca_id": _int("The CA whose key this certificate certifies."),
    "kind": _str("`previous` (superseded primary), `cross` (cross-certificate) or `reissue` (pending re-issue).",
                 enum=["previous", "cross", "reissue"]),
    "issuer_ca_id": _int("Issuing CA, or null when issued outside Chancery.", nullable=True),
    "issuer_name": _str("Issuing CA name, or null.", nullable=True),
    "serial_number": _str("Serial number (hex)."),
    "not_before": ISO_DATETIME,
    "not_after": ISO_DATETIME,
    "approval_status": _str("`approved` or `pending` (dual control).", enum=["approved", "pending"]),
    "usable": _bool("Approved and, for a cross-certificate, its issuer is not revoked."),
    "created_at": NULLABLE_DATETIME,
}, description="An alternate certificate for a CA's key (F11).")

# --- certificate authorities ---------------------------------------------------

CERTIFICATE_AUTHORITY = _obj({
    "id": _int(),
    "name": _str("Display name, unique among non-revoked CAs."),
    "common_name": _str("Subject Common Name."),
    "serial_number": _str("Serial number (hex)."),
    "key_type": _str("RSA, EC, ED25519 or ED448."),
    "key_size": _int("Key size in bits (256 for Ed25519, 456 for Ed448)."),
    "key_backend": _str("`software` (Fernet-encrypted key) or `softhsm` (PKCS#11 token).",
                        enum=["software", "softhsm"]),
    "is_root": _bool(),
    "parent_id": _int("Parent CA, or null for a root / an unlinked import.", nullable=True),
    "not_before": ISO_DATETIME,
    "not_after": ISO_DATETIME,
    "days_until_expiry": _int(nullable=True),
    "expiry_status": EXPIRY_STATUS,
    "expiry_notified_at": NULLABLE_DATETIME,
    "is_revoked": _bool(),
    "has_private_key": _bool("False for a certificate-only import."),
    "has_signing_key": _bool("Can sign (software or HSM key present)."),
    "is_exportable": _bool("Private key can be exported (software backend only)."),
    "approval_status": _str("`approved`, or `pending` under dual control.", enum=["approved", "pending"]),
    "created_by": _int("User id of the creator, or null.", nullable=True),
    "allowed_profiles": _array(_int(), "Allowed profile ids, or null when any profile may be used.", nullable=True),
    "name_constraints": _nullable_ref("NameConstraints"),
    "certificate_policies": _array(_ref("CertificatePolicy"), "Policies declared by the CA, or null.", nullable=True),
    "acme": _ref("AcmeSettings"),
    "created_at": NULLABLE_DATETIME,
}, description="A Certificate Authority (list form).")

CERTIFICATE_AUTHORITY_DETAIL = _extend(CERTIFICATE_AUTHORITY, {
    "ocsp_responder": {"oneOf": [_ref("OcspResponderStatus"), {"type": "null"}],
                       "description": "Delegated responder certificate, or null when none is held."},
    "alternate_certificates": _array(_ref("CaCertificate"), "Previous primaries, cross-certificates and pending re-issues."),
    "path_length": _int("BasicConstraints pathLenConstraint, or null.", nullable=True),
    "crl_number": _int("Number of the current CRL, or null.", nullable=True),
    "revoked_at": NULLABLE_DATETIME,
    "revocation_reason": _str(nullable=True),
    "approved_by": _int(nullable=True),
    "approved_at": NULLABLE_DATETIME,
    "certificate_pem": _str("The CA certificate (PEM)."),
}, description="A Certificate Authority with its certificate and revocation details.")

WARNING = _str("Present when the state change succeeded but the follow-up CRL refresh failed.")

CERTIFICATE_AUTHORITY_RESULT = _extend(CERTIFICATE_AUTHORITY_DETAIL, {"warning": WARNING}, (),
                                       "The CA after a state change; `warning` only when the CRL refresh failed.")

# --- certificates --------------------------------------------------------------

CERTIFICATE = _obj({
    "id": _int(),
    "serial_number": _str("Serial number (hex)."),
    "common_name": _str(),
    "ca_id": _int("Issuing CA."),
    "key_type": _str("RSA, EC, ED25519 or ED448."),
    "key_size": _int(),
    "not_before": ISO_DATETIME,
    "not_after": ISO_DATETIME,
    "days_until_expiry": _int(nullable=True),
    "expiry_status": EXPIRY_STATUS,
    "expiry_notified_at": NULLABLE_DATETIME,
    "is_revoked": _bool(),
    "requested_by": _int("User id of the CSR's requester, or null.", nullable=True),
    "issued_by": _int("User id of the admin who issued it, or null.", nullable=True),
    "profile_id": _int(nullable=True),
    "profile": _str("Profile key, or null.", nullable=True),
    "renewed_from_id": _int("Predecessor certificate (renewal lineage), or null.", nullable=True),
    "superseded_by_id": _int("Successor certificate, or null.", nullable=True),
    "issuance_source": _str("`manual` (UI/API) or `acme`.", enum=["manual", "acme"]),
    "created_at": NULLABLE_DATETIME,
}, description="A certificate (list form).")

CERTIFICATE_DETAIL = _extend(CERTIFICATE, {
    "subject": SUBJECT,
    "sans": _array({"type": "string"}, "Subject Alternative Names in `TYPE:value` form, or null.", nullable=True),
    "key_usage": KEY_USAGE,
    "extended_key_usage": _array({"type": "string"}, "Extended Key Usage names, or null.", nullable=True),
    "revoked_at": NULLABLE_DATETIME,
    "revocation_reason": _str(nullable=True),
    "certificate_policies": _array(_ref("CertificatePolicy"), "Policies stamped on the certificate, or null.", nullable=True),
    "certificate_pem": _str("The certificate (PEM)."),
}, description="A certificate with subject, SANs, usages and PEM.")

CERTIFICATE_RESULT = _extend(CERTIFICATE_DETAIL, {"warning": WARNING}, (),
                             "The certificate after revocation; `warning` only when the CRL refresh failed.")

CERTIFICATE_RENEWED = _extend(CERTIFICATE_DETAIL, {
    "old_id": _int("The certificate that was renewed."),
    "warning": WARNING,
}, ("old_id",), "The successor certificate plus the id of its predecessor.")

# --- signing requests ------------------------------------------------------------

CSR = _obj({
    "id": _int(),
    "common_name": _str(),
    "status": _str("`pending`, `signing` (claimed by a sign request), `approved` or `rejected`.",
                   enum=["pending", "signing", "approved", "rejected"]),
    "ca_id": _int("CA that signed it, or null while pending.", nullable=True),
    "certificate_id": _int("Issued certificate, or null.", nullable=True),
    "created_by": _int("Requester's user id.", nullable=True),
    "signed_by": _int("Signer's user id, or null.", nullable=True),
    "profile_id": _int(nullable=True),
    "profile": _str("Requested profile key, or null.", nullable=True),
    "created_at": NULLABLE_DATETIME,
}, description="A certificate signing request (list form).")

CSR_DETAIL = _extend(CSR, {
    "subject": SUBJECT,
    "sans": _array({"type": "string"}, "Requested SANs in `TYPE:value` form, or null.", nullable=True),
    "csr_pem": _str("The CSR (PEM)."),
}, description="A certificate signing request with subject, SANs and PEM.")

CSR_CREATED = _extend(CSR_DETAIL, {
    "private_key_pem": _str("The generated private key (PEM, PKCS#8, unencrypted) — returned once and never "
                            "stored. Absent when a CSR was uploaded.", nullable=True),
}, (), "A new CSR; `private_key_pem` is present only for a generated key.")

# --- users, tokens, profiles, audit ---------------------------------------------

USER = _obj({
    "id": _int(),
    "username": _str(),
    "role": _str(enum=["admin", "csr_requester"]),
    "is_active": _bool(),
    "auth_source": _str("`local` or `ldap`."),
    "must_change_password": _bool(),
    "totp_enabled": _bool(),
    "approval_status": _str("`approved`, or `pending` under dual control (F19).", enum=["approved", "pending"]),
    "pending_role": _str("Role awaiting approval, or null.", nullable=True),
    "created_by": _int(nullable=True),
    "created_at": NULLABLE_DATETIME,
}, description="A user account. Password hashes, TOTP secrets and recovery codes are never exposed.")

API_TOKEN = _obj({
    "id": _int(),
    "user_id": _int(),
    "username": _str("Owner's username.", nullable=True),
    "name": _str("Unique per owner."),
    "token_id": _str("Public token id (the middle part of `chy_api_<id>_<secret>`)."),
    "scopes": _array({"type": "string", "enum": ["read", "issue", "revoke", "admin"]}),
    "status": _str(enum=["active", "expired", "revoked"]),
    "expires_at": NULLABLE_DATETIME,
    "days_until_expiry": _int(nullable=True),
    "last_used_at": NULLABLE_DATETIME,
    "created_at": NULLABLE_DATETIME,
    "created_by": _int(nullable=True),
}, description="A scoped API token (the secret is never included).")

API_TOKEN_CREATED = _extend(API_TOKEN, {
    "token": _str("The bearer secret `chy_api_<id>_<secret>` — shown once, never retrievable again."),
}, ("token",), "A freshly created token including its one-time secret.")

CERTIFICATE_PROFILE = _obj({
    "id": _int(),
    "key": _str("Stable key used in `profile=` fields (e.g. `web_server`, `custom`)."),
    "name": _str(),
    "description": _str(nullable=True),
    "is_builtin": _bool(),
    "is_custom": _bool("The unrestricted profile."),
    "enabled": _bool(),
    "key_usage": KEY_USAGE,
    "extended_key_usage": _array({"type": "string"}, nullable=True),
    "include_ocsp_aia": _bool(),
    "certificate_policies": _array(_ref("CertificatePolicy"), "Profile-level policies, or null to inherit the CA's.", nullable=True),
    "default_validity_days": _int(),
    "max_validity_days": _int(nullable=True),
    "allowed_key_types": _array({"type": "string"}, nullable=True),
    "min_rsa_bits": _int(nullable=True),
    "max_rsa_bits": _int(nullable=True),
    "allowed_ec_sizes": _array(_int(), nullable=True),
    "allowed_san_types": _array({"type": "string"}, nullable=True),
    "require_san": _bool(),
    "cn_in_san": _bool(),
    "created_at": NULLABLE_DATETIME,
    "updated_at": NULLABLE_DATETIME,
}, description="A server-enforced issuance profile (F1).")

AUDIT_ENTRY = _obj({
    "id": _int(),
    "timestamp": NULLABLE_DATETIME,
    "user_id": _int(nullable=True),
    "username": _str("Actor: a user, or `scheduler` / `cli` / `system` / `acme`.", nullable=True),
    "action": _str(),
    "target_type": _str(nullable=True),
    "target_id": _int(nullable=True),
    "details": {"type": ["object", "null"], "description": "Action-specific details."},
    "ip_address": _str(nullable=True),
    "prev_hash": _str("Hash chain link (F16); null while unsealed.", nullable=True),
    "entry_hash": _str("This row's hash; null while unsealed.", nullable=True),
}, description="One audit-log row.")

AUDIT_INTEGRITY = _obj({
    "head_id": _int("Last sealed row id, or null.", nullable=True),
    "head_hash": _str(nullable=True),
    "unsealed": _int("Rows not yet sealed by the scheduler."),
    "total": _int(),
    "last_anchor": _nullable_ref("AuditEntry"),
    "last_checkpoint": _nullable_ref("AuditEntry"),
    "retention_days": _int("`AUDIT_RETENTION_DAYS` (0 = keep everything)."),
}, description="Hash-chain summary (F16).")

AUDIT_LOG_PAGE = _obj({
    "items": _array(_ref("AuditEntry")),
    "page": _int(),
    "per_page": _int(),
    "total": _int(),
    "pages": _int(),
    "filters": {"type": "object", "additionalProperties": {"type": "string"},
                "description": "The filters that were applied."},
    "integrity": _ref("AuditIntegrity"),
}, description="A page of audit rows, newest first.")

ACME_EAB_KEY = _obj({
    "id": _int(),
    "ca_id": _int(),
    "kid": _str("Key identifier the ACME client presents."),
    "name": _str(nullable=True),
    "status": _str("`unused`, `used` or `revoked`."),
    "created_at": NULLABLE_DATETIME,
    "used_at": NULLABLE_DATETIME,
}, description="An external account binding key (F14).")

ACME_EAB_KEY_CREATED = _extend(ACME_EAB_KEY, {
    "hmac_key": _str("The base64url MAC key — shown once."),
}, ("hmac_key",), "A new EAB key including its one-time MAC key.")

# --- small payloads ---------------------------------------------------------------

DELETED = _obj({"deleted": _int("Id of the removed row.")})

DETECT_PARENT_RESULT = _obj({
    "is_self_signed": {"type": ["boolean", "null"], "description": "Null when no PEM was given."},
    "parent_id": _int("Known CA that issued the certificate, or null.", nullable=True),
})

OCSP_RESPONDER_ROTATED = _obj({
    "ca_id": _int(),
    "ocsp_responder": _ref("OcspResponderStatus"),
})

HEALTH = _obj({
    "status": _str(enum=["ok", "unhealthy"]),
    "checks": _obj({"database": _str(enum=["ok", "error"])}),
}, description="Liveness probe result; deliberately carries no version or detail.")

ACME_DIRECTORY = _obj({
    "newNonce": _str(format="uri"),
    "newAccount": _str(format="uri"),
    "newOrder": _str(format="uri"),
    "revokeCert": _str(format="uri"),
    "keyChange": _str(format="uri"),
    "meta": _obj({
        "externalAccountRequired": _bool(),
        "website": _str(format="uri"),
    }),
}, description="RFC 8555 §7.1.1 directory object.")

DASHBOARD_ADMIN = _obj({
    "stats": _obj({
        "ca_count": _int("Non-revoked CAs."),
        "cert_count": _int(),
        "cert_active": _int(),
        "cert_revoked": _int(),
        "cert_expiring_soon": _int(),
        "cert_expired": _int(),
        "csr_pending": _int(),
        "csr_total": _int(),
    }),
    "recent_cas": _array(_ref("CertificateAuthority")),
    "recent_certs": _array(_ref("Certificate")),
}, description="Dashboard for an administrator (at most 10 recent rows each).")

DASHBOARD_REQUESTER = _obj({
    "stats": _obj({
        "csr_pending": _int(),
        "csr_approved": _int(),
        "csr_total": _int(),
    }),
    "recent_csrs": _array(_ref("Csr")),
}, description="Dashboard for a requester (own CSRs only).")

OPENAPI_DOCUMENT = {"type": "object", "description": "This OpenAPI 3.1 document.",
                    "required": ["openapi", "info", "paths"]}

SCHEMAS = {
    "Error": ERROR,
    "CertificatePolicy": CERTIFICATE_POLICY,
    "NameConstraints": NAME_CONSTRAINTS,
    "AcmeSettings": ACME_SETTINGS,
    "OcspResponderStatus": OCSP_RESPONDER_STATUS,
    "CaCertificate": CA_CERTIFICATE,
    "CertificateAuthority": CERTIFICATE_AUTHORITY,
    "CertificateAuthorityDetail": CERTIFICATE_AUTHORITY_DETAIL,
    "CertificateAuthorityResult": CERTIFICATE_AUTHORITY_RESULT,
    "CertificateAuthorityPage": _page("CertificateAuthority", "A page of CAs."),
    "Certificate": CERTIFICATE,
    "CertificateDetail": CERTIFICATE_DETAIL,
    "CertificateResult": CERTIFICATE_RESULT,
    "CertificateRenewed": CERTIFICATE_RENEWED,
    "CertificatePage": _page("Certificate", "A page of certificates."),
    "Csr": CSR,
    "CsrDetail": CSR_DETAIL,
    "CsrCreated": CSR_CREATED,
    "CsrPage": _page("Csr", "A page of signing requests."),
    "User": USER,
    "ApiToken": API_TOKEN,
    "ApiTokenCreated": API_TOKEN_CREATED,
    "CertificateProfile": CERTIFICATE_PROFILE,
    "AuditEntry": AUDIT_ENTRY,
    "AuditIntegrity": AUDIT_INTEGRITY,
    "AuditLogPage": AUDIT_LOG_PAGE,
    "AcmeEabKey": ACME_EAB_KEY,
    "AcmeEabKeyCreated": ACME_EAB_KEY_CREATED,
    "Deleted": DELETED,
    "DetectParentResult": DETECT_PARENT_RESULT,
    "OcspResponderRotated": OCSP_RESPONDER_ROTATED,
    "Health": HEALTH,
    "AcmeDirectory": ACME_DIRECTORY,
    "DashboardAdmin": DASHBOARD_ADMIN,
    "DashboardRequester": DASHBOARD_REQUESTER,
    "OpenApiDocument": OPENAPI_DOCUMENT,
}

# Serializer ↔ schema pairs the tests validate against live objects:
# (schema name, model attribute path, to_dict kwargs).
SERIALIZER_SCHEMAS = {
    "CertificateAuthority": ("ca", {}),
    "CertificateAuthorityDetail": ("ca", {"detail": True}),
    "Certificate": ("certificate", {}),
    "CertificateDetail": ("certificate", {"detail": True}),
    "Csr": ("csr", {}),
    "CsrDetail": ("csr", {"detail": True}),
    "User": ("user", {}),
    "ApiToken": ("api_token", {}),
    "CertificateProfile": ("profile", {}),
    "AuditEntry": ("audit", {}),
    "CaCertificate": ("ca_certificate", {}),
    "AcmeEabKey": ("eab_key", {}),
}
