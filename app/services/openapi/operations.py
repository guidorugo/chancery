"""Per-endpoint metadata of the OpenAPI document (F22, 3.8.0).

``OPERATIONS`` describes every ``endpoint:METHOD`` pair of the JSON API (and the
public / binary endpoints); ``EXCLUDED`` names the pairs that are deliberately
not part of the document, each with its reason. ``tests/test_openapi.py``
asserts that every rule of ``app.url_map`` is in exactly one of the two, that the
``role`` matches the view's decorator, that every documented field / query name
is a literal in the route module, and that every form field the view reads is
documented (``UNDOCUMENTED_FIELDS`` lists the agreed exceptions).

Static-document rule: nothing here may come from the database, the request or a
secret. Config-derived limits are expressed with ``Cfg`` and resolved by the
builder from ``current_app.config`` (non-secret policy numbers only).
"""

FORM = "application/x-www-form-urlencoded"
MULTIPART = "multipart/form-data"

KEY_TYPES = ("RSA", "EC", "ED25519", "ED448")
REVOCATION_REASONS = ("unspecified", "key_compromise", "ca_compromise", "affiliation_changed",
                      "superseded", "cessation_of_operation", "certificate_hold",
                      "privilege_withdrawn", "aa_compromise")


class Cfg:
    """A non-secret numeric limit read from the app config at build time."""

    def __init__(self, key, default):
        self.key = key
        self.default = default

    def __repr__(self):
        return f"Cfg({self.key!r})"


# --- field / parameter constructors ----------------------------------------------

def field(name, description, *, type="string", required=False, enum=None, default=None,
          format=None, minimum=None, maximum=None, items=None, literal=True):
    """One request-body field. ``literal=False`` marks a name the route builds
    dynamically (f-string), which the literal gate therefore skips."""
    return {"name": name, "description": description, "type": type, "required": required,
            "enum": list(enum) if enum else None, "default": default, "format": format,
            "minimum": minimum, "maximum": maximum, "items": items, "literal": literal}


def int_field(name, description, **kw):
    return field(name, description, type="integer", **kw)


def on_flag(name, description, **kw):
    return field(name, description + " Checkbox: send `on` to set it; omit to leave it off.",
                 enum=("on",), **kw)


def truthy_flag(name, description, **kw):
    return field(name, description + " Send `on`, `1`, `true` or `yes` to set it; omit to leave it off.",
                 enum=("on", "1", "true", "yes"), **kw)


def presence_flag(name, description, **kw):
    return field(name, description + " Presence counts (any value). When none of the fields of this "
                 "group is sent, the profile or the service defaults apply.", **kw)


def file_field(name, description, **kw):
    return field(name, description, format="binary", **kw)


def secret_field(name, description, **kw):
    return field(name, description + " Write-only: never echoed back.", format="password", **kw)


def query(name, description, *, type="string", enum=None, default=None, minimum=None,
          maximum=None, literal=True):
    return {"name": name, "description": description, "type": type, "enum": list(enum) if enum else None,
            "default": default, "minimum": minimum, "maximum": maximum, "literal": literal}


# --- shared field groups -----------------------------------------------------------

SUBJECT_FIELDS = [
    field("cn", "Subject Common Name.", required=True),
    field("org", "Organization (O)."),
    field("ou", "Organizational Unit (OU)."),
    field("country", "Country (C), two letters."),
    field("state", "State or province (ST)."),
    field("locality", "Locality (L)."),
]

KEY_TYPE_FIELD = field("key_type", "Key algorithm. Ed25519/Ed448 are refused by browsers and Windows "
                       "Schannel for TLS server certificates.", enum=KEY_TYPES, default="RSA")
KEY_SIZE_FIELD = int_field("key_size", "Key size in bits: RSA within `MIN_RSA_KEY_SIZE`–`MAX_RSA_KEY_SIZE` "
                           "(see `info.x-chancery-limits`), EC 256/384/521; ignored for Ed25519/Ed448.",
                           default=2048)
SAN_FIELD = field("san", "Subject Alternative Names, one per line: a bare hostname or `DNS:`, `IP:` "
                  "(v4/v6), `EMAIL:`, `URI:`, `UPN:` entries. Any other prefix is a 400.")
PROFILE_FIELD = field("profile", "Certificate profile key, id or name (`GET /users/profiles`). Omitted = the "
                      "unrestricted `custom` profile unless `PROFILES_REQUIRE_SELECTION` is on. A named "
                      "profile fixes Key Usage / EKU and the posted `ku_*`/`eku_*` fields are ignored.")
CRL_DP_FIELD = field("crl_dp_url", "CRL Distribution Point URL to stamp into the certificate. Blank = the "
                     "default `/public/crl/<ca_id>.crl` URL of this server (a loopback host is refused).",
                     format="uri")
LEAF_VALIDITY_FIELD = int_field("validity_days", "Validity in days; clamped to the issuing CA's expiry and the "
                                "profile's `max_validity_days`.", default=365, minimum=1,
                                maximum=Cfg("MAX_CERT_VALIDITY_DAYS", 1825))

KU_FIELDS = [presence_flag(f"ku_{n}", f"Key Usage bit *{n}*.") for n in
             ("digital_signature", "key_encipherment", "content_commitment", "data_encipherment", "key_agreement")]
EKU_FIELDS = [presence_flag(f"eku_{n}", f"Extended Key Usage *{n}*.") for n in
              ("serverAuth", "clientAuth", "codeSigning", "emailProtection", "timeStamping", "ocspSigning")]

REASON_FIELD = field("reason", "RFC 5280 revocation reason.", enum=REVOCATION_REASONS, default="unspecified")

PROFILE_RESTRICTION_FIELDS = [
    on_flag("restrict_profiles", "Restrict this CA to the listed profiles (otherwise any profile may be used)."),
    field("allowed_profiles", "Allowed profile keys or ids; repeat the field for each. Required when "
          "`restrict_profiles` is on.", type="array", items="string"),
]

PROFILE_FORM_FIELDS = [
    field("name", "Display name (unique).", required=True),
    field("description", "Free text."),
    on_flag("enabled", "Profile may be chosen for issuance."),
    on_flag("include_ocsp_aia", "Stamp the OCSP Authority Information Access extension."),
    int_field("default_validity_days", "Validity proposed by the forms.", default=365, minimum=1),
    int_field("max_validity_days", "Hard cap on validity (blank = the deployment cap)."),
    int_field("min_rsa_bits", "Smallest RSA key accepted (blank = `MIN_RSA_KEY_SIZE`)."),
    int_field("max_rsa_bits", "Largest RSA key accepted (blank = `MAX_RSA_KEY_SIZE`)."),
    on_flag("require_san", "Refuse a certificate without any SAN."),
    on_flag("cn_in_san", "Require the Common Name to appear among the SANs."),
    field("certificate_policies", "Certificate Policies, one `OID [CPS URL]` per line; blank inherits the CA's."),
] + [on_flag(f"ku_{n}", f"Key Usage bit *{n}* (ignored for the built-in `custom` profile).", literal=False) for n in
     ("digital_signature", "key_encipherment", "content_commitment", "data_encipherment", "key_agreement")] + [
    on_flag(f"eku_{n}", f"Extended Key Usage *{n}* (ignored for `custom`).", literal=False) for n in
    ("serverAuth", "clientAuth", "codeSigning", "emailProtection", "timeStamping", "ocspSigning")] + [
    on_flag(f"kt_{t}", f"Allow {t} keys (no `kt_*` field = any algorithm).", literal=False) for t in KEY_TYPES] + [
    on_flag(f"ec_{s}", f"Allow P-{s} EC keys (no `ec_*` field = any curve).", literal=False) for s in (256, 384, 521)] + [
    on_flag(f"san_{t}", f"Allow `{t.upper()}:` SANs (no `san_*` field = any type).", literal=False) for t in
    ("dns", "ip", "email", "uri", "upn")]

PAGING = [
    query("page", "Page number (1-based). Sending `page` or `per_page` switches the JSON response from a "
          "bare array to the `{items, page, per_page, total, pages}` envelope.", type="integer", minimum=1,
          default=1, literal=False),
    query("per_page", "Rows per page (1–500).", type="integer", minimum=1, maximum=500, default=50, literal=False),
]
Q_PARAM = query("q", "Case-insensitive substring search.")
CA_ID_PARAM = query("ca_id", "Only rows of this issuing CA.", type="integer")
PROFILE_PARAM = query("profile", "Only rows issued under this profile (key or id).")

AUDIT_FILTERS = [
    query("from", "First day to include, `YYYY-MM-DD`."),
    query("to", "Last day to include (inclusive), `YYYY-MM-DD`."),
    query("action", "Exact action name, or a prefix ending in `*` (e.g. `login*`)."),
    query("user", "Username substring."),
    query("target_type", "Exact target type (`ca`, `certificate`, `csr`, `user`, …)."),
    query("target_id", "Exact target id.", type="integer"),
    query("q", "Substring of the JSON details."),
]

# --- response shortcuts ---------------------------------------------------------------

PEM = {"type": "string", "description": "PEM text."}
BINARY = {"type": "string", "format": "binary"}

# Shared component responses: name -> (description, schema name or None[, media type]).
COMPONENT_RESPONSES = {
    "BadRequest": ("Invalid input or a policy refusal; `error` says which.", "Error"),
    "Unauthorized": ("No credential, or the credential was refused.", "Error"),
    "Forbidden": ("Refused by role, token scope, ownership or a dual-control rule.", "Error"),
    "NotFound": ("No such resource.", "Error"),
    "Conflict": ("The resource is not in a state that allows this action.", "Error"),
    "ServerError": ("Unexpected failure; the detail is in the server log only.", "Error"),
    "HtmlRedirect": ("Browser-style redirect carrying a flash message — this endpoint has no JSON error body "
                     "(resource not found, no permission, or an invalid export password).", None),
    "PlainNotFound": ("Unknown CA (plain text; no JSON body on the public endpoints).", None, "text/html"),
}


def _list_200(item, page):
    return ("The matching rows: a bare array, or the page envelope when `page`/`per_page` is given.",
            {"oneOf": [{"type": "array", "items": {"$ref": f"#/components/schemas/{item}"}},
                       {"$ref": f"#/components/schemas/{page}"}]})


# --- operation constructor -------------------------------------------------------------

def op(key, *, tag, role, summary, description="", query=(), body=None, body_type=FORM,
       responses, key_material=False, security=None, role_responses=None):
    """One documented ``endpoint:METHOD``.

    role: ``admin`` (``@admin_required``), ``any`` (``@login_required``; ownership
    rules in the description) or ``public`` (no login). The token scope is not
    declared here — the builder derives it from ``api_token_service.required_scope``
    so it can never drift from enforcement.
    """
    assert role in ("admin", "any", "public"), key
    return {"key": key, "tag": tag, "role": role, "summary": summary, "description": description,
            "query": list(query), "body": list(body) if body else None, "body_type": body_type,
            "responses": dict(responses), "key_material": key_material, "security": security,
            # Optional per-document overrides, e.g. {"requester": {...}} when the
            # shape a requester gets differs from the administrator's.
            "role_responses": dict(role_responses or {})}


KEY_MATERIAL_NOTE = ("\n\n**Returns private-key material.** Swagger UI shows the response body on screen; "
                     "prefer `curl` unless that is intended. Audited.")

DUAL_CONTROL_NOTE = ("\n\nUnder dual control (`DUAL_CONTROL_ENABLED`, once the instance is multi-user) the "
                     "creator of a request cannot also approve it; the bootstrap admin account is exempt.")

TAGS = [
    ("Certificate Authorities", "Create, import, approve, export and revoke CAs; CRLs; alternate certificates; ACME settings."),
    ("Certificates", "Issue, renew, revoke and download certificates."),
    ("Signing Requests", "Create or upload CSRs and have an administrator sign or reject them."),
    ("Certificate Profiles", "Server-enforced issuance policies."),
    ("Users", "Accounts and dual-control approvals (browser-only form actions are listed in the README)."),
    ("API Tokens", "Scoped bearer credentials for automation."),
    ("Audit Log", "The hash-chained audit trail."),
    ("Dashboard", "Role-dependent counters and recent objects."),
    ("Public", "Unauthenticated endpoints for relying parties: CA certificates, CRLs, OCSP."),
    ("ACME", "RFC 8555 entry points; the JWS-authenticated protocol endpoints are spoken by ACME clients."),
    ("Monitoring", "Liveness and metrics."),
    ("API Documentation", "This document."),
]

# --- the registry ----------------------------------------------------------------------------

OPERATIONS = {}


def _add(*ops):
    for o in ops:
        assert o["key"] not in OPERATIONS, o["key"]
        OPERATIONS[o["key"]] = o


# Certificate Authorities ------------------------------------------------------------------
_add(
    op("ca.list_cas:GET", tag="Certificate Authorities", role="admin", summary="List CAs",
       description="Every CA, newest first, filtered by the query parameters.",
       query=[Q_PARAM,
              query("status", "Lifecycle filter.", enum=("active", "revoked", "expired", "pending", "cert-only")),
              query("type", "Root or intermediate.", enum=("root", "intermediate")),
              query("backend", "Key protection.", enum=("software", "softhsm")), *PAGING],
       responses={200: _list_200("CertificateAuthority", "CertificateAuthorityPage"), 400: "BadRequest"}),

    op("ca.create:POST", tag="Certificate Authorities", role="admin", summary="Create or import a CA",
       description="`mode=generate` creates a root (`ca_type=root`) or an intermediate (`ca_type=intermediate` "
                   "+ `parent_id`) with a new key in the software or HSM backend. `mode=upload` imports an "
                   "existing CA from PEM (certificate + key, an encrypted key with `key_passphrase`, or "
                   "certificate-only with `cert_only`) or from a PKCS#12 file; a chain bundle also imports the "
                   "parents certificate-only. Files are capped at 64 KB. Under dual control a new keyed CA starts "
                   "`pending` and cannot sign until another admin approves it." + DUAL_CONTROL_NOTE,
       body_type=MULTIPART,
       body=[field("mode", "Generate a new CA or import one.", enum=("generate", "upload"), default="generate"),
             field("name", "Display name, unique among non-revoked CAs.", required=True),
             *PROFILE_RESTRICTION_FIELDS,
             # generate
             *[dict(f, required=False) for f in SUBJECT_FIELDS],
             field("ca_type", "generate: root or intermediate.", enum=("root", "intermediate"), default="root"),
             int_field("parent_id", "generate: id of the signing parent (required for an intermediate; must be "
                       "approved, unrevoked and hold a signing key)."),
             KEY_TYPE_FIELD, KEY_SIZE_FIELD,
             field("key_backend", "generate: where the key lives.", enum=("software", "softhsm"), default="software"),
             int_field("validity_days", "generate: validity in days, capped by `MAX_CA_VALIDITY_DAYS` (root) / "
                       "`MAX_INTERMEDIATE_VALIDITY_DAYS` (intermediate) and the parent's expiry.", default=3650,
                       minimum=1, maximum=Cfg("MAX_CA_VALIDITY_DAYS", 7300)),
             int_field("path_length", "generate: BasicConstraints pathLenConstraint (blank = none).", minimum=0),
             field("nc_permitted", "generate: Name Constraints permitted subtrees, one `DNS:`/`IP:<cidr>`/`EMAIL:`/`URI:` entry per line."),
             field("nc_excluded", "generate: Name Constraints excluded subtrees, same syntax."),
             field("certificate_policies", "generate: Certificate Policies, one `OID [CPS URL]` per line."),
             # upload
             field("import_format", "upload: input format.", enum=("pem", "pkcs12"), default="pem"),
             int_field("upload_parent_id", "upload: link the imported CA under this parent (must have issued it)."),
             field("cert_pem", "upload/pem: certificate PEM (or a full chain) — alternative to `cert_file`."),
             file_field("cert_file", "upload/pem: certificate file (PEM), preferred over `cert_pem`."),
             field("key_pem", "upload/pem: private key PEM — alternative to `key_file`."),
             file_field("key_file", "upload/pem: private key file (PEM)."),
             secret_field("key_passphrase", "upload/pem: passphrase of an encrypted private key."),
             on_flag("cert_only", "upload/pem: import the certificate without a key (offline root)."),
             file_field("p12_file", "upload/pkcs12: the .p12/.pfx bundle."),
             secret_field("p12_password", "upload/pkcs12: bundle password.")],
       responses={201: ("The new CA.", "CertificateAuthorityDetail"), 400: "BadRequest",
                  409: ("A CA with this name or serial was created concurrently.", "Error"), 500: "ServerError"}),

    op("ca.detect_parent:POST", tag="Certificate Authorities", role="admin", summary="Detect the parent of a certificate",
       description="Helper of the import form: tells whether a PEM is self-signed and which known CA issued it.",
       body=[field("cert_pem", "Certificate PEM to inspect (blank → both fields null).")],
       responses={200: ("Detection result.", "DetectParentResult")}),

    op("ca.detail:GET", tag="Certificate Authorities", role="admin", summary="Get a CA",
       description="Full record including the certificate PEM, alternates and the OCSP responder status.",
       responses={200: ("The CA.", "CertificateAuthorityDetail"), 404: "NotFound"}),

    op("ca.rotate_ocsp_responder:POST", tag="Certificate Authorities", role="admin", summary="Rotate the OCSP responder certificate",
       description="Issues a new delegated OCSP responder certificate now (F7). Refused for an expired CA or "
                   "while `OCSP_DELEGATED_RESPONDER` is off.",
       responses={200: ("The new responder status.", "OcspResponderRotated"), 400: "BadRequest", 404: "NotFound",
                  500: "ServerError"}),

    op("ca.set_profiles:POST", tag="Certificate Authorities", role="admin", summary="Set the CA's profile allow-list",
       description="Restrict issuance from this CA to a set of profiles, or lift the restriction.",
       body=PROFILE_RESTRICTION_FIELDS,
       responses={200: ("The updated CA.", "CertificateAuthorityDetail"), 400: "BadRequest", 404: "NotFound"}),

    op("ca.approve:POST", tag="Certificate Authorities", role="admin", summary="Approve a pending CA",
       description="Dual control: a different admin than the creator (cool-down applies) approves a pending CA, "
                   "which then publishes its initial CRL and may sign." + DUAL_CONTROL_NOTE,
       responses={200: ("The approved CA.", "CertificateAuthorityDetail"), 403: "Forbidden", 404: "NotFound",
                  409: ("The CA is not awaiting approval.", "Error")}),

    op("ca.download:GET", tag="Certificate Authorities", role="admin", summary="Download the CA certificate or chain",
       description="`format=pem` is the CA certificate, `format=chain` the certificate followed by its issuers up "
                   "to the root (`via=<alt_id>` routes the chain through an alternate certificate). Private-key "
                   "formats are POST-only.",
       query=[query("format", "What to download.", enum=("pem", "chain"), default="pem"),
              query("via", "Alternate CA certificate id to build the chain through.", type="integer")],
       responses={200: ("PEM text.", {"application/x-pem-file": PEM}), 302: "HtmlRedirect"}),

    op("ca.download:POST", tag="Certificate Authorities", role="admin", summary="Export the CA private key or PKCS#12 bundle (returns private-key material)",
       description="`format=key` returns the unencrypted private key (PEM, PKCS#8); `format=pkcs12` a bundle of "
                   "certificate, key and parent chain protected with `password`. Refused for certificate-only and "
                   "HSM-backed CAs (the key is not exportable). `pem`/`chain` also work over POST." + KEY_MATERIAL_NOTE,
       body=[field("format", "What to export.", enum=("key", "pkcs12", "pem", "chain"), default="pem"),
             secret_field("password", "pkcs12: export password (required, non-empty)."),
             int_field("via", "chain: alternate CA certificate id to build the chain through.")],
       responses={200: ("Key PEM or PKCS#12 bytes.", {"application/x-pem-file": PEM, "application/x-pkcs12": BINARY}),
                  302: "HtmlRedirect"},
       key_material=True),

    op("ca.revoke:POST", tag="Certificate Authorities", role="admin", summary="Revoke a CA",
       description="Revokes the CA, every certificate it issued and every sub-CA, publishes a final CRL (valid until "
                   "the CA's own notAfter) and refreshes the parent's CRL. Also the way to discard an unwanted pending CA.",
       body=[REASON_FIELD],
       responses={200: ("The revoked CA.", "CertificateAuthorityResult"), 400: "BadRequest", 404: "NotFound",
                  409: ("Already revoked.", "Error"), 500: "ServerError"}),

    op("ca.generate_crl:POST", tag="Certificate Authorities", role="admin", summary="Generate a new CRL",
       description="Signs a fresh CRL now (the scheduler does this automatically before `nextUpdate`).",
       responses={200: ("The CA with the new `crl_number`.", "CertificateAuthorityDetail"), 400: "BadRequest",
                  404: "NotFound", 500: "ServerError"}),

    op("ca.reissue:POST", tag="Certificate Authorities", role="admin", summary="Re-issue the CA certificate for the same key",
       description="New serial and validity, identical subject, key and extensions, so every certificate the CA "
                   "issued keeps validating. The old primary is kept as a `previous` alternate. Under dual control "
                   "the new certificate is stored as a pending `reissue` alternate instead." + DUAL_CONTROL_NOTE,
       body=[int_field("validity_days", "Validity of the new certificate (blank = the original window), clamped to "
                       "the parent's expiry and the CA caps.", minimum=1)],
       responses={201: ("The CA with the promoted certificate, or the pending alternate under dual control.",
                        {"oneOf": [{"$ref": "#/components/schemas/CertificateAuthorityResult"},
                                   {"$ref": "#/components/schemas/CaCertificate"}]}),
                  400: "BadRequest", 404: "NotFound", 500: "ServerError"}),

    op("ca.cross_sign:POST", tag="Certificate Authorities", role="admin", summary="Cross-sign the CA with another CA",
       description="A cross-certificate for this CA's key issued by `issuer_ca_id`, so relying parties that trust "
                   "the other hierarchy can validate this one. Refuses self, descendants, unusable issuers and a "
                   "subject outside the issuer's Name Constraints." + DUAL_CONTROL_NOTE,
       body=[int_field("issuer_ca_id", "The issuing CA (approved, unrevoked, with a signing key).", required=True),
             int_field("validity_days", "Validity (blank = the issuer's remaining validity).", minimum=1)],
       responses={201: ("The cross-certificate (pending under dual control).", "CaCertificate"),
                  400: "BadRequest", 404: "NotFound", 500: "ServerError"}),

    op("ca.import_alternate:POST", tag="Certificate Authorities", role="admin", summary="Import an externally issued cross-certificate",
       description="Attaches a certificate for this CA's key issued outside Chancery; the public key must match.",
       body=[field("cert_pem", "The cross-certificate (PEM).", required=True)],
       responses={201: ("The imported alternate.", "CaCertificate"), 400: "BadRequest", 404: "NotFound"}),

    op("ca.approve_alternate:POST", tag="Certificate Authorities", role="admin", summary="Approve a pending alternate certificate",
       description="Approving a pending `reissue` promotes it to the primary certificate (and refreshes the CRL); "
                   "approving a `cross` makes it usable." + DUAL_CONTROL_NOTE,
       responses={200: ("The CA (re-issue) or the approved alternate (cross-certificate).",
                        {"oneOf": [{"$ref": "#/components/schemas/CertificateAuthorityResult"},
                                   {"$ref": "#/components/schemas/CaCertificate"}]}),
                  400: "BadRequest", 403: "Forbidden", 404: "NotFound",
                  409: ("The alternate is not awaiting approval.", "Error")}),

    op("ca.delete_alternate:POST", tag="Certificate Authorities", role="admin", summary="Remove an alternate certificate",
       description="Deletes a previous, cross or pending alternate certificate. Audited.",
       responses={200: ("Removed.", "Deleted"), 404: "NotFound"}),

    op("ca.set_acme:POST", tag="Certificate Authorities", role="admin", summary="Update the CA's ACME settings",
       description="Switch the per-CA ACME directory on or off, choose the issuance profile and whether accounts "
                   "need an external account binding key or may request wildcards. The server also needs "
                   "`ACME_ENABLED`. Under dual control the CA's creator cannot switch ACME on." + DUAL_CONTROL_NOTE,
       body=[truthy_flag("acme_enabled", "Serve an ACME directory for this CA."),
             field("acme_profile", "Issuance profile key (`custom` or blank = unrestricted)."),
             truthy_flag("acme_require_eab", "Require an EAB key for new accounts."),
             truthy_flag("acme_allow_wildcards", "Accept wildcard identifiers (dns-01 only).")],
       responses={200: ("The updated CA.", "CertificateAuthorityDetail"), 400: "BadRequest", 403: "Forbidden",
                  404: "NotFound"}),

    op("ca.create_acme_eab:POST", tag="Certificate Authorities", role="admin", summary="Issue an ACME external account binding key",
       description="Creates a one-time EAB key for a client to bind its account; the MAC key is returned once.",
       body=[field("name", "Optional label.")],
       responses={201: ("The new key with its one-time MAC secret.", "AcmeEabKeyCreated"), 404: "NotFound"}),

    op("ca.revoke_acme_eab:POST", tag="Certificate Authorities", role="admin", summary="Revoke an ACME EAB key",
       description="An unused key can no longer bind an account. Idempotent.",
       responses={200: ("The key.", "AcmeEabKey"), 404: "NotFound"}),
)

# Certificates --------------------------------------------------------------------------------
_add(
    op("certificates.list_certs:GET", tag="Certificates", role="any", summary="List certificates",
       description="Administrators see every certificate; a requester sees those issued from their own CSRs.",
       query=[Q_PARAM, query("status", "Lifecycle filter.", enum=("active", "revoked", "expiring", "expired")),
              CA_ID_PARAM, PROFILE_PARAM, *PAGING],
       responses={200: _list_200("Certificate", "CertificatePage"), 400: "BadRequest"}),

    op("certificates.create:POST", tag="Certificates", role="admin", summary="Issue a certificate",
       description="Generates a key pair and issues a certificate from `ca_id`; the private key is escrowed "
                   "(encrypted) and downloadable with `POST /certificates/{cert_id}/download-key`. Disabled while "
                   "dual control is active (use the CSR flow; the bootstrap admin is exempt).",
       body=[*SUBJECT_FIELDS, int_field("ca_id", "Issuing CA.", required=True), KEY_TYPE_FIELD, KEY_SIZE_FIELD,
             LEAF_VALIDITY_FIELD, SAN_FIELD, PROFILE_FIELD, CRL_DP_FIELD, *KU_FIELDS, *EKU_FIELDS],
       responses={201: ("The new certificate.", "CertificateDetail"), 400: "BadRequest", 403: "Forbidden",
                  404: "NotFound", 500: "ServerError"}),

    op("certificates.detail:GET", tag="Certificates", role="any", summary="Get a certificate",
       description="A requester may only read certificates issued from their own CSRs.",
       responses={200: ("The certificate.", "CertificateDetail"), 403: "Forbidden", 404: "NotFound"}),

    op("certificates.revoke:POST", tag="Certificates", role="admin", summary="Revoke a certificate",
       description="Marks the certificate revoked and refreshes the issuing CA's CRL; OCSP answers `revoked` at once.",
       body=[REASON_FIELD],
       responses={200: ("The revoked certificate.", "CertificateResult"), 400: "BadRequest", 404: "NotFound",
                  409: ("Already revoked.", "Error"), 500: "ServerError"}),

    op("certificates.renew:POST", tag="Certificates", role="admin", summary="Renew a certificate",
       description="Issues a successor with the same subject, SANs, usages and profile (F9). Without `rekey` the "
                   "escrowed key is reused (a CSR-signed certificate keeps its owner's key); `rekey` needs an "
                   "escrowed key. A revoked certificate renews only with `rekey`; a certificate that already has a "
                   "renewal is a 409 unless `force`. Dual control treats a CSR-lineage renewal as signing and an "
                   "escrowed-key renewal as direct creation.",
       body=[int_field("validity_days", "Validity in days (blank = the original window), clamped as at issuance.",
                       minimum=1, maximum=Cfg("MAX_CERT_VALIDITY_DAYS", 1825)),
             truthy_flag("rekey", "Generate a fresh key instead of reusing the escrowed one."),
             truthy_flag("revoke_old", "Revoke the old certificate as `superseded` in the same transaction."),
             truthy_flag("force", "Renew again although a renewal already exists."),
             CRL_DP_FIELD],
       responses={201: ("The successor (`old_id` names the predecessor).", "CertificateRenewed"),
                  400: "BadRequest", 403: "Forbidden", 404: "NotFound",
                  409: ("A renewal already exists; send `force` to issue another.", "Error"), 500: "ServerError"}),

    op("certificates.download:GET", tag="Certificates", role="any", summary="Download the certificate or its chain",
       description="`pem`/`der` are the certificate alone, `fullchain` = leaf → intermediates → root, `chain` = the "
                   "issuers only; `via=<alt_id>` routes a chain through a cross-signed CA certificate. Owners and "
                   "administrators only. Audited.",
       query=[query("format", "Encoding / bundle.", enum=("pem", "der", "fullchain", "chain"), default="pem"),
              query("via", "Alternate CA certificate id for `fullchain`/`chain`.", type="integer")],
       responses={200: ("Certificate bytes.", {"application/x-pem-file": PEM, "application/x-x509-ca-cert": BINARY}),
                  302: "HtmlRedirect", 400: "BadRequest",
                  404: ("Unknown alternate CA certificate (`via`).", "Error")}),

    op("certificates.download:POST", tag="Certificates", role="any", summary="Export a PKCS#12 bundle (returns private-key material)",
       description="`format=pkcs12` bundles certificate, escrowed private key and chain under `password`; only a "
                   "certificate with an escrowed key can be exported this way. The other formats also work over POST."
                   + KEY_MATERIAL_NOTE,
       body=[field("format", "Encoding / bundle.", enum=("pkcs12", "pem", "der", "fullchain", "chain"), default="pem"),
             secret_field("password", "pkcs12: export password."),
             int_field("via", "Alternate CA certificate id for `fullchain`/`chain`.")],
       responses={200: ("PKCS#12 or certificate bytes.", {"application/x-pkcs12": BINARY, "application/x-pem-file": PEM,
                                                            "application/x-x509-ca-cert": BINARY}),
                  302: "HtmlRedirect", 400: "BadRequest", 404: ("Unknown alternate CA certificate (`via`).", "Error")},
       key_material=True),

    op("certificates.download_key:POST", tag="Certificates", role="admin", summary="Download the escrowed private key (returns private-key material)",
       description="The unencrypted private key (PEM, PKCS#8) of a directly issued or renewed certificate. A "
                   "CSR-signed certificate has no escrowed key." + KEY_MATERIAL_NOTE,
       responses={200: ("Private key PEM.", {"application/x-pem-file": PEM}), 302: "HtmlRedirect"},
       key_material=True),
)

# Signing requests ------------------------------------------------------------------------------
_add(
    op("csr.list_csrs:GET", tag="Signing Requests", role="any", summary="List signing requests",
       description="Administrators see every CSR; a requester sees their own.",
       query=[Q_PARAM, query("status", "Lifecycle filter.", enum=("pending", "approved", "rejected")),
              CA_ID_PARAM, PROFILE_PARAM, *PAGING],
       responses={200: _list_200("Csr", "CsrPage"), 400: "BadRequest"}),

    op("csr.create:POST", tag="Signing Requests", role="any", summary="Create or upload a signing request",
       description="`mode=generate` builds a key pair and a CSR from the subject fields and returns the private "
                   "key **once** (it is never stored); `mode=upload` imports an existing CSR (`csr_pem`), so the "
                   "key stays with its owner. The requested `profile` is a hint the signer may change.",
       body=[field("mode", "Generate a key and CSR, or upload a CSR.", enum=("generate", "upload"), default="generate"),
             PROFILE_FIELD,
             field("csr_pem", "upload: the CSR (PEM). Weak or unsupported keys are refused."),
             *[dict(f, required=False) for f in SUBJECT_FIELDS], KEY_TYPE_FIELD, KEY_SIZE_FIELD, SAN_FIELD],
       responses={201: ("The new CSR (with `private_key_pem` when generated).", "CsrCreated"), 400: "BadRequest",
                  500: "ServerError"}),

    op("csr.detail:GET", tag="Signing Requests", role="any", summary="Get a signing request",
       description="A requester may only read their own CSRs.",
       responses={200: ("The CSR.", "CsrDetail"), 403: "Forbidden", 404: "NotFound"}),

    op("csr.sign:POST", tag="Signing Requests", role="admin", summary="Sign a signing request",
       description="Issues a certificate for a pending CSR from `ca_id` after proof-of-possession, key-strength, "
                   "Name-Constraints and profile checks; single-flight, so a concurrent second signer gets a 409. "
                   "Under dual control the CSR's creator cannot sign it." + DUAL_CONTROL_NOTE,
       body=[int_field("ca_id", "Issuing CA.", required=True), LEAF_VALIDITY_FIELD, PROFILE_FIELD, CRL_DP_FIELD,
             *KU_FIELDS, *EKU_FIELDS],
       responses={201: ("The issued certificate.", "CertificateDetail"), 400: "BadRequest", 403: "Forbidden",
                  404: "NotFound", 409: ("Already processed, or claimed by a concurrent request.", "Error"),
                  500: "ServerError"}),

    op("csr.reject:POST", tag="Signing Requests", role="admin", summary="Reject a signing request",
       description="Only a pending CSR can be rejected.",
       responses={200: ("The rejected CSR.", "CsrDetail"), 404: "NotFound", 409: ("Already processed.", "Error")}),
)

# Profiles, users, tokens, audit ----------------------------------------------------------------
_add(
    op("users.profiles:GET", tag="Certificate Profiles", role="admin", summary="List certificate profiles",
       description="All profiles, enabled or not.",
       responses={200: ("Profiles.", {"type": "array", "items": {"$ref": "#/components/schemas/CertificateProfile"}})}),

    op("users.profile_new:POST", tag="Certificate Profiles", role="admin", summary="Create a certificate profile",
       description="The key is derived from the name. Profile CRUD is configuration, not issuance: dual control does not gate it.",
       body=PROFILE_FORM_FIELDS,
       responses={201: ("The new profile.", "CertificateProfile"), 400: "BadRequest"}),

    op("users.profile_edit:POST", tag="Certificate Profiles", role="admin", summary="Update a certificate profile",
       description="Built-ins are editable; the `custom` profile keeps its unrestricted Key Usage / EKU.",
       body=PROFILE_FORM_FIELDS,
       responses={200: ("The updated profile.", "CertificateProfile"), 400: "BadRequest", 404: "NotFound"}),

    op("users.profile_toggle:POST", tag="Certificate Profiles", role="admin", summary="Enable or disable a profile",
       description="A disabled profile cannot be chosen for new issuance or renewal.",
       responses={200: ("The profile.", "CertificateProfile"), 404: "NotFound"}),

    op("users.profile_delete:POST", tag="Certificate Profiles", role="admin", summary="Delete a profile",
       description="Refused for built-ins and for profiles referenced by certificates, CSRs or CAs.",
       responses={200: ("Deleted.", "Deleted"), 404: "NotFound", 409: ("Built-in or still referenced.", "Error")}),

    op("users.list_users:GET", tag="Users", role="admin", summary="List users",
       description="Every account, newest first. Creating, editing, deactivating and password resets are "
                   "browser form actions (see the README) and are not part of this document.",
       responses={200: ("Users.", {"type": "array", "items": {"$ref": "#/components/schemas/User"}})}),

    op("users.approve_user:POST", tag="Users", role="admin", summary="Approve a pending account or promotion",
       description="Dual control for user management (F19): activates a pending account and/or applies a pending "
                   "promotion. The approver must differ from the admin who set it up; an account that admin created "
                   "or reset within `DUAL_CONTROL_COOLDOWN_HOURS` cannot approve either." + DUAL_CONTROL_NOTE,
       responses={200: ("The user.", "User"), 403: "Forbidden", 404: "NotFound",
                  409: ("Nothing is pending for this user.", "Error")}),

    op("users.reset_2fa:POST", tag="Users", role="admin", summary="Reset a user's second factor",
       description="Clears the TOTP secret and recovery codes (lost authenticator) and logs the user out everywhere; "
                   "under `REQUIRE_2FA` they must enrol again at the next login.",
       responses={200: ("The user.", "User"), 404: "NotFound", 409: ("Two-factor is not enabled for this user.", "Error")}),

    op("users.api_tokens:GET", tag="API Tokens", role="any", summary="List API tokens",
       description="Your own tokens; administrators see everyone's. Secrets are never included.",
       responses={200: ("Tokens.", {"type": "array", "items": {"$ref": "#/components/schemas/ApiToken"}})}),

    op("users.api_tokens:POST", tag="API Tokens", role="any", summary="Create an API token",
       description="A token never exceeds its owner's role; it must expire within `API_TOKEN_MAX_DAYS`. The "
                   "secret is returned once in `token`.",
       body=[field("name", "Label, unique per owner.", required=True),
             int_field("expires_in_days", "Lifetime in days.", default=30, minimum=1,
                       maximum=Cfg("API_TOKEN_MAX_DAYS", 365)),
             field("scopes", "Scopes; repeat the field for each (`read`, `issue`, `revoke`, `admin`). Alternative "
                   "to the `scope_*` checkbox fields.", type="array", items="string"),
             on_flag("scope_read", "Scope *read*: list and view what the account may see.", literal=False),
             on_flag("scope_issue", "Scope *issue*: create/sign CSRs, create and renew certificates.", literal=False),
             on_flag("scope_revoke", "Scope *revoke*: revoke certificates and CAs, regenerate CRLs.", literal=False),
             on_flag("scope_admin", "Scope *admin*: every other write.", literal=False)],
       responses={201: ("The token with its one-time secret.", "ApiTokenCreated"), 400: "BadRequest"}),

    op("users.revoke_api_token:POST", tag="API Tokens", role="any", summary="Revoke an API token",
       description="Your own token; administrators may revoke any. A revoked token is refused immediately.",
       responses={200: ("The token.", "ApiToken"), 404: "NotFound"}),

    op("users.audit_log:GET", tag="Audit Log", role="admin", summary="Query the audit log",
       description="Newest first, 50 per page by default, with the hash-chain integrity summary.",
       query=[*PAGING, *AUDIT_FILTERS],
       responses={200: ("A page of audit rows.", "AuditLogPage"), 400: "BadRequest"}),

    op("users.audit_log_export:GET", tag="Audit Log", role="admin", summary="Export the audit log",
       description="Streams the filtered rows, hashes included, as CSV, a JSON array or JSON lines. The export itself is audited.",
       query=[query("format", "Output format.", enum=("csv", "json", "jsonl"), default="csv"), *AUDIT_FILTERS],
       responses={200: ("The export.", {"text/csv": {"type": "string"},
                                        "application/json": {"type": "array", "items": {"$ref": "#/components/schemas/AuditEntry"}},
                                        "application/x-ndjson": {"type": "string"}}),
                  400: "BadRequest"}),
)

# Dashboard, public, ACME, monitoring, this document -----------------------------------------------
_add(
    op("dashboard.index:GET", tag="Dashboard", role="any", summary="Dashboard counters",
       description="Administrators get fleet-wide counters plus the ten most recent CAs and certificates; a "
                   "requester gets the counters of their own CSRs.",
       responses={200: ("Administrator dashboard.", "DashboardAdmin")},
       role_responses={"requester": {200: ("Requester dashboard (own CSRs).", "DashboardRequester")}}),

    op("public.download_ca_cert:GET", tag="Public", role="public", summary="CA certificate (PEM)",
       description="The CA's current certificate.",
       responses={200: ("PEM.", {"application/x-pem-file": PEM}), 404: "PlainNotFound"}),

    op("public.download_ca_alt_cert:GET", tag="Public", role="public", summary="Alternate CA certificate (PEM)",
       description="An approved alternate certificate for the CA's key — a previous primary or a cross-certificate.",
       responses={200: ("PEM.", {"application/x-pem-file": PEM}), 404: "PlainNotFound"}),

    op("public.download_crl_der:GET", tag="Public", role="public", summary="CRL (DER)",
       description="The current CRL, regenerated on the fly when it is past `nextUpdate` and the CA can still sign. "
                   "`Last-Modified`/`Expires`/`Cache-Control` follow the CRL window.",
       responses={200: ("DER CRL.", {"application/pkix-crl": BINARY}), 404: "PlainNotFound"}),

    op("public.download_crl_pem:GET", tag="Public", role="public", summary="CRL (PEM)",
       description="The same CRL as PEM text.",
       responses={200: ("PEM CRL.", {"application/x-pem-file": PEM}), 404: "PlainNotFound"}),

    op("public.ocsp_responder:POST", tag="Public", role="public", summary="OCSP responder (POST)",
       description="RFC 6960 responder: send a DER `OCSPRequest`, receive a signed `OCSPResponse`. An unparseable "
                   "request gets an OCSP-level `malformedRequest` at HTTP 200. Responses are cached per "
                   "(serial, status) for `OCSP_RESPONSE_CACHE_TTL_SECONDS`.",
       body_type="application/ocsp-request", body=[],
       responses={200: ("DER OCSPResponse.", {"application/ocsp-response": BINARY}), 404: "PlainNotFound"}),

    op("public.ocsp_responder_get:GET", tag="Public", role="public", summary="OCSP responder (GET)",
       description="RFC 6960 §A.1 GET form: the base64 DER request, URL-encoded, appended to the responder URL.",
       responses={200: ("DER OCSPResponse.", {"application/ocsp-response": BINARY}), 404: "PlainNotFound"}),

    op("acme.directory:GET", tag="ACME", role="public", summary="ACME directory",
       description="RFC 8555 §7.1.1 entry point of this CA's ACME service; point certbot, acme.sh, lego or Caddy at "
                   "it. 404 (`application/problem+json`) unless `ACME_ENABLED` is on and the CA has ACME switched on. "
                   "The JWS-authenticated endpoints it lists (`newAccount`, `newOrder`, orders, authorizations, "
                   "challenges, certificates, `revokeCert`, `keyChange`) follow RFC 8555 and are not repeated here.",
       responses={200: ("The directory.", "AcmeDirectory"),
                  404: ("ACME is off, or this CA has no directory.", {"application/problem+json": {"type": "object"}})}),

    op("acme.new_nonce:GET", tag="ACME", role="public", summary="ACME new nonce",
       description="Returns a fresh `Replay-Nonce` header (204 for GET, 200 for HEAD).",
       responses={204: ("No body; the nonce is in `Replay-Nonce`.", None),
                  404: ("ACME is off, or this CA has no directory.", {"application/problem+json": {"type": "object"}})}),

    op("health.health:GET", tag="Monitoring", role="public", summary="Liveness probe",
       description="A cheap database round-trip. No authentication, never rate-limited, exposes no version or detail.",
       responses={200: ("Healthy.", "Health"), 503: ("Unhealthy.", "Health")}),

    op("metrics.metrics:GET", tag="Monitoring", role="public", summary="Prometheus metrics",
       description="Opt-in (`METRICS_ENABLED`, otherwise 404). Requires a dedicated **metrics token** "
                   "(`flask metrics-token create`) as a bearer credential — user credentials and API tokens are "
                   "refused here. Per-CA series are keyed by opaque `ca_id` unless `METRICS_INCLUDE_CA_DETAILS`.",
       security=[{"metricsToken": []}],
       responses={200: ("Prometheus text exposition.", {"text/plain": {"type": "string"}}),
                  401: ("Missing or invalid metrics token.", {"text/plain": {"type": "string"}}),
                  404: ("Metrics are disabled.", {"text/plain": {"type": "string"}})}),

    op("apidocs.openapi_json:GET", tag="API Documentation", role="any", summary="This OpenAPI document",
       description="The document is filtered by your role: a requester does not see administrator-only operations.",
       responses={200: ("OpenAPI 3.1 document.", "OpenApiDocument")}),
)

# --- deliberately undocumented ------------------------------------------------------------------

_HTML_FORM = "HTML form page (GET renders the browser form; the POST of the same URL is documented)."
_BROWSER_FLOW = "Browser session flow (login, password change, 2FA); API clients authenticate per request with Basic Auth or a bearer token."
_FORM_ONLY = ("Browser-only admin console action: it answers with an HTML redirect or a re-rendered form and has "
              "no JSON contract (README: 'User-management writes remain form-based').")
_ACME_JWS = "RFC 8555 JWS-authenticated protocol endpoint, spoken by ACME clients; see GET /acme/{ca_id}/directory."

EXCLUDED = {
    "csr.create:GET": _HTML_FORM, "csr.sign:GET": _HTML_FORM,
    "ca.create:GET": _HTML_FORM, "ca.revoke:GET": _HTML_FORM,
    "certificates.create:GET": _HTML_FORM, "certificates.revoke:GET": _HTML_FORM, "certificates.renew:GET": _HTML_FORM,
    "users.create_user:GET": _HTML_FORM, "users.create_user:POST": _FORM_ONLY,
    "users.edit_user:GET": _HTML_FORM, "users.edit_user:POST": _FORM_ONLY,
    "users.toggle_active:POST": _FORM_ONLY,
    "users.reset_password:GET": _HTML_FORM, "users.reset_password:POST": _FORM_ONLY,
    "users.ldap_settings:GET": _HTML_FORM, "users.ldap_settings:POST": _FORM_ONLY + " Carries the directory bind password.",
    "users.ldap_settings_reset:POST": _FORM_ONLY,
    "users.webhook_settings:GET": _HTML_FORM, "users.webhook_settings:POST": _FORM_ONLY + " Carries the webhook secret.",
    "users.webhook_settings_reset:POST": _FORM_ONLY,
    "users.profile_new:GET": _HTML_FORM, "users.profile_edit:GET": _HTML_FORM,
    "auth.login:GET": _BROWSER_FLOW, "auth.login:POST": _BROWSER_FLOW,
    "auth.change_password:GET": _BROWSER_FLOW, "auth.change_password:POST": _BROWSER_FLOW,
    "auth.logout:POST": _BROWSER_FLOW,
    "auth.two_factor:GET": _BROWSER_FLOW, "auth.two_factor:POST": _BROWSER_FLOW,
    "auth.two_factor_setup:GET": _BROWSER_FLOW, "auth.two_factor_setup:POST": _BROWSER_FLOW,
    "auth.two_factor_disable:POST": _BROWSER_FLOW, "auth.two_factor_recovery_codes:POST": _BROWSER_FLOW,
    "acme.new_account:POST": _ACME_JWS, "acme.account:POST": _ACME_JWS, "acme.account_orders:POST": _ACME_JWS,
    "acme.new_order:POST": _ACME_JWS, "acme.order:POST": _ACME_JWS, "acme.finalize:POST": _ACME_JWS,
    "acme.authorization:POST": _ACME_JWS, "acme.challenge:POST": _ACME_JWS, "acme.certificate:POST": _ACME_JWS,
    "acme.revoke_cert:POST": _ACME_JWS, "acme.key_change:POST": _ACME_JWS,
    "apidocs.docs:GET": "The Swagger UI page itself (HTML).",
}

# Form/query names a documented view reads that are intentionally not documented
# for it: endpoint -> {name: reason}.
UNDOCUMENTED_FIELDS = {
    "ca.detail": {"_eab_kid": "HTML-only query flag of the CA page (ACME EAB flash helper); the JSON branch never reads it."},
}

# Path parameters: name -> description (every <converter:name> must be listed).
PATH_PARAMS = {
    "ca_id": "Certificate Authority id.",
    "cert_id": "Certificate id.",
    "csr_id": "Signing request id.",
    "user_id": "User id.",
    "alt_id": "Alternate CA certificate id.",
    "key_id": "ACME external account binding key id.",
    "profile_id": "Certificate profile id.",
    "token_id": "API token id.",
    "encoded": "The base64 DER `OCSPRequest`, URL-encoded (RFC 6960 §A.1).",
    # ACME protocol resources (excluded endpoints, listed for completeness)
    "account_id": "ACME account id.",
    "order_id": "ACME order id.",
    "authz_id": "ACME authorization id.",
    "challenge_id": "ACME challenge id.",
}
