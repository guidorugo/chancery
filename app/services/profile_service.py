"""Certificate profile resolution and enforcement (F1, 2.13.0).

`resolve()` turns the `profile` form/API field into a `CertificateProfile`
(the built-in `custom` when absent) and checks the CA's allow-list;
`enforce()` runs inside the certificate services, so the API path is bound by
the same policy as the forms. Built-ins are seeded at startup and kept
editable but not deletable.
"""
import json
import re

from flask import current_app
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models.certificate_profile import CertificateProfile
from . import san as san_module

KU_FIELDS = ("digital_signature", "key_encipherment", "content_commitment",
             "data_encipherment", "key_agreement")
EKU_NAMES = ("serverAuth", "clientAuth", "codeSigning", "emailProtection",
             "timeStamping", "ocspSigning")
SAN_TYPES = san_module.TYPES  # dns, ip, email, uri, upn (F4)
KEY_TYPES = ("RSA", "EC")
EC_SIZES = (256, 384, 521)


def _ku(*on):
    return {f: (f in on) for f in KU_FIELDS}


# The four presets the forms used to carry as JavaScript, byte-for-byte the
# same Key Usage / EKU, plus `custom` (no restrictions, legacy behaviour).
BUILTINS = (
    {"key": "web_server", "name": "Web Server",
     "description": "TLS server certificate (also usable for client auth).",
     "key_usage": _ku("digital_signature", "key_encipherment"),
     "extended_key_usage": ["serverAuth", "clientAuth"]},
    {"key": "client_auth", "name": "Client Auth",
     "description": "TLS client / mutual-TLS identity certificate.",
     "key_usage": _ku("digital_signature"),
     "extended_key_usage": ["clientAuth"]},
    {"key": "email", "name": "Email / S-MIME",
     "description": "S/MIME signing and encryption certificate.",
     "key_usage": _ku("digital_signature", "key_encipherment", "content_commitment"),
     "extended_key_usage": ["emailProtection"]},
    {"key": "code_signing", "name": "Code Signing",
     "description": "Code-signing certificate.",
     "key_usage": _ku("digital_signature"),
     "extended_key_usage": ["codeSigning"]},
    {"key": "custom", "name": "Custom",
     "description": "No profile restrictions: Key Usage and Extended Key Usage come from the "
                    "request (or the service defaults); only the global policy applies.",
     "key_usage": None, "extended_key_usage": None},
)


# --- seeding ----------------------------------------------------------------

def ensure_builtins():
    """Insert any missing built-in profile (idempotent, race-safe). Existing
    rows are never modified, so operator edits to a built-in survive."""
    created = []
    for spec in BUILTINS:
        if CertificateProfile.query.filter_by(key=spec["key"]).first():
            continue
        row = CertificateProfile(
            key=spec["key"], name=spec["name"], description=spec["description"],
            is_builtin=True, enabled=True,
            key_usage_json=json.dumps(spec["key_usage"]) if spec["key_usage"] else None,
            extended_key_usage_json=(json.dumps(spec["extended_key_usage"])
                                     if spec["extended_key_usage"] else None),
        )
        db.session.add(row)
        try:
            db.session.commit()
            created.append(spec["key"])
        except IntegrityError:
            db.session.rollback()  # another worker won the race
    return created


# --- lookup -----------------------------------------------------------------

def get_custom():
    return CertificateProfile.query.filter_by(key="custom").first()


def lookup(value):
    """Find a profile by id, key or name. None when not found."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        row = db.session.get(CertificateProfile, int(text))
        if row:
            return row
    return (CertificateProfile.query.filter_by(key=text).first()
            or CertificateProfile.query.filter_by(name=text).first())


def list_profiles(enabled_only=False):
    q = CertificateProfile.query
    if enabled_only:
        q = q.filter_by(enabled=True)
    return q.order_by(CertificateProfile.is_builtin.desc(), CertificateProfile.id.asc()).all()


def allowed_for_ca(ca, profile):
    """A CA with an allow-list (`allowed_profiles_json`) issues only under
    the listed profiles; None means every profile."""
    if ca is None:
        return True
    ids = ca.allowed_profile_ids
    return ids is None or profile.id in ids


def resolve(value, ca=None):
    """Profile for a create/sign request. Absent → `custom` unless
    PROFILES_REQUIRE_SELECTION. Raises ValueError for unknown, disabled or
    CA-disallowed profiles."""
    text = "" if value is None else str(value).strip()
    if not text:
        if current_app.config.get("PROFILES_REQUIRE_SELECTION", False):
            raise ValueError("A certificate profile is required (PROFILES_REQUIRE_SELECTION).")
        profile = get_custom()
        if profile is None:  # seeding failed / very first request on an empty DB
            ensure_builtins()
            profile = get_custom()
    else:
        profile = lookup(text)
        if profile is None:
            raise ValueError(f"Unknown certificate profile '{text}'.")
    if not profile.enabled:
        raise ValueError(f"Certificate profile '{profile.name}' is disabled.")
    if ca is not None and not allowed_for_ca(ca, profile):
        raise ValueError(f"Certificate profile '{profile.name}' is not allowed for CA '{ca.name}'.")
    return profile


# --- enforcement --------------------------------------------------------------

def san_type(entry):
    parsed = san_module.parse_entry(entry)
    return parsed[0] if parsed else None


def _san_value(entry):
    parsed = san_module.parse_entry(entry)
    return parsed[1] if parsed else ""


def enforce(profile, *, key_type, key_size, validity_days, san_list, common_name=None,
            key_usage=None, extended_key_usage=None):
    """Validate a request against `profile` and return the
    (key_usage, extended_key_usage, include_ocsp_aia) the certificate must
    carry. `custom`/None returns the caller's values untouched."""
    if profile is None or profile.is_custom:
        return key_usage, extended_key_usage, True
    name = profile.name

    allowed_types = profile.allowed_key_types
    if allowed_types and key_type not in allowed_types:
        raise ValueError(f"Profile '{name}' does not allow {key_type} keys "
                         f"(allowed: {', '.join(allowed_types)}).")
    if key_type == "RSA":
        if profile.min_rsa_bits and key_size < profile.min_rsa_bits:
            raise ValueError(f"Profile '{name}' requires RSA keys of at least {profile.min_rsa_bits} bits.")
        if profile.max_rsa_bits and key_size > profile.max_rsa_bits:
            raise ValueError(f"Profile '{name}' allows RSA keys of at most {profile.max_rsa_bits} bits.")
    elif key_type == "EC":
        sizes = profile.allowed_ec_sizes
        if sizes and key_size not in sizes:
            raise ValueError(f"Profile '{name}' allows EC curves of size "
                             f"{', '.join(str(s) for s in sizes)} only.")

    if profile.max_validity_days and validity_days and validity_days > profile.max_validity_days:
        raise ValueError(f"Profile '{name}' allows at most {profile.max_validity_days} days of validity "
                         f"(requested {validity_days}).")

    sans = [s for s in (san_list or []) if s and s.strip()]
    if profile.require_san and not sans:
        raise ValueError(f"Profile '{name}' requires at least one Subject Alternative Name.")
    allowed_san = profile.allowed_san_types
    if allowed_san:
        for entry in sans:
            kind = san_type(entry)  # raises for an unknown prefix (G4-4)
            if kind not in allowed_san:
                raise ValueError(f"Profile '{name}' does not allow {san_module.label(kind)} SANs "
                                 f"('{entry}'); allowed: {', '.join(san_module.label(t) for t in allowed_san)}.")
    if profile.cn_in_san and common_name:
        dns_values = {_san_value(s).lower() for s in sans if san_type(s) == "dns"}
        if common_name.strip().lower() not in dns_values:
            raise ValueError(f"Profile '{name}' requires the Common Name '{common_name}' to appear "
                             "among the DNS Subject Alternative Names.")

    return (profile.key_usage if profile.key_usage is not None else key_usage,
            profile.extended_key_usage if profile.extended_key_usage is not None else extended_key_usage,
            bool(profile.include_ocsp_aia))


def form_payload(profiles):
    """What the create/sign templates need to drive the checkboxes (JS)."""
    out = []
    for p in profiles:
        ku = p.key_usage or {}
        out.append({
            "id": p.id, "key": p.key, "name": p.name, "custom": p.is_custom,
            "ku": [f"ku_{f}" for f, v in ku.items() if v],
            "eku": [f"eku_{n}" for n in (p.extended_key_usage or [])],
            "default_validity_days": p.default_validity_days,
        })
    return out


def default_key(profiles):
    """Preselected profile in the forms: web_server (legacy default) if present."""
    keys = [p.key for p in profiles]
    return "web_server" if "web_server" in keys else (keys[0] if keys else "")


# --- admin CRUD ---------------------------------------------------------------

def _slug(name):
    slug = re.sub(r"[^a-z0-9]+", "_", (name or "").strip().lower()).strip("_")
    return slug or "profile"


def unique_key(name):
    base = _slug(name)
    key, n = base, 2
    while CertificateProfile.query.filter_by(key=key).first():
        key = f"{base}_{n}"
        n += 1
    return key


def validate(fields, existing=None):
    """Validate an admin form / import dict. Returns a list of error strings."""
    errors = []
    name = (fields.get("name") or "").strip()
    if not name:
        errors.append("Name is required.")
    elif len(name) > 100:
        errors.append("Name must be 100 characters or fewer.")
    else:
        clash = CertificateProfile.query.filter_by(name=name).first()
        if clash and (existing is None or clash.id != existing.id):
            errors.append(f"A profile named '{name}' already exists.")

    ku = fields.get("key_usage")
    if ku is not None:
        if not isinstance(ku, dict) or set(ku) - set(KU_FIELDS):
            errors.append("Key usage has unknown fields.")
        elif not any(bool(v) for v in ku.values()):
            errors.append("At least one Key Usage must be selected.")
    eku = fields.get("extended_key_usage")
    if eku is not None and (not isinstance(eku, list) or set(eku) - set(EKU_NAMES)):
        errors.append("Extended key usage has unknown values.")

    def _int(field, minimum=1):
        raw = fields.get(field)
        if raw in (None, ""):
            return None
        try:
            value = int(raw)
        except (TypeError, ValueError):
            errors.append(f"{field} must be a whole number.")
            return None
        if value < minimum:
            errors.append(f"{field} must be at least {minimum}.")
        return value

    default_days = _int("default_validity_days")
    max_days = _int("max_validity_days")
    if default_days and max_days and default_days > max_days:
        errors.append("The default validity cannot exceed the maximum validity.")
    min_rsa = _int("min_rsa_bits", 1024)
    max_rsa = _int("max_rsa_bits", 1024)
    if min_rsa and max_rsa and min_rsa > max_rsa:
        errors.append("The minimum RSA size cannot exceed the maximum.")

    types = fields.get("allowed_key_types")
    if types is not None and (not isinstance(types, list) or set(types) - set(KEY_TYPES)):
        errors.append("Allowed key types has unknown values.")
    if types is not None and not types:
        errors.append("At least one key type must be allowed.")
    ec = fields.get("allowed_ec_sizes")
    if ec is not None and (not isinstance(ec, list) or set(ec) - set(EC_SIZES)):
        errors.append("Allowed EC sizes has unknown values.")
    san = fields.get("allowed_san_types")
    if san is not None and (not isinstance(san, list) or set(san) - set(SAN_TYPES)):
        errors.append("Allowed SAN types has unknown values.")
    return errors


def _apply(row, fields):
    row.name = (fields.get("name") or "").strip()
    row.description = (fields.get("description") or "").strip()[:500]
    ku = fields.get("key_usage")
    eku = fields.get("extended_key_usage")
    if not row.is_custom:
        row.key_usage_json = json.dumps(ku) if ku is not None else None
        row.extended_key_usage_json = json.dumps(eku) if eku is not None else None
    row.include_ocsp_aia = bool(fields.get("include_ocsp_aia", True))
    row.max_validity_days = int(fields["max_validity_days"]) if fields.get("max_validity_days") else None
    default_days = int(fields.get("default_validity_days") or 365)
    if row.max_validity_days and default_days > row.max_validity_days:
        default_days = row.max_validity_days  # an unspecified default never exceeds the cap
    row.default_validity_days = default_days
    types = fields.get("allowed_key_types")
    row.allowed_key_types_json = json.dumps(types) if types else None
    row.min_rsa_bits = int(fields["min_rsa_bits"]) if fields.get("min_rsa_bits") else None
    row.max_rsa_bits = int(fields["max_rsa_bits"]) if fields.get("max_rsa_bits") else None
    ec = fields.get("allowed_ec_sizes")
    row.allowed_ec_sizes_json = json.dumps([int(s) for s in ec]) if ec else None
    san = fields.get("allowed_san_types")
    row.allowed_san_types_json = json.dumps(san) if san else None
    row.require_san = bool(fields.get("require_san", False))
    row.cn_in_san = bool(fields.get("cn_in_san", False))
    if "enabled" in fields:
        row.enabled = bool(fields["enabled"])


def create(fields, updated_by=None):
    errors = validate(fields)
    if errors:
        raise ValueError(" ".join(errors))
    row = CertificateProfile(key=unique_key(fields.get("name")), is_builtin=False, updated_by=updated_by)
    _apply(row, fields)
    db.session.add(row)
    db.session.flush()
    return row


def update(row, fields, updated_by=None):
    errors = validate(fields, existing=row)
    if errors:
        raise ValueError(" ".join(errors))
    _apply(row, fields)
    row.updated_by = updated_by
    db.session.flush()
    return row


def usage_counts(row):
    from ..models.certificate import Certificate
    from ..models.csr import CertificateSigningRequest
    return (Certificate.query.filter_by(profile_id=row.id).count(),
            CertificateSigningRequest.query.filter_by(profile_id=row.id).count())


def delete(row):
    if row.is_builtin:
        raise ValueError("Built-in profiles cannot be deleted (disable it instead).")
    certs, csrs = usage_counts(row)
    if certs or csrs:
        raise ValueError(f"Profile '{row.name}' is referenced by {certs} certificate(s) and "
                         f"{csrs} CSR(s); disable it instead of deleting.")
    db.session.delete(row)
    db.session.flush()


# --- export / import (CLI) -------------------------------------------------------

EXPORT_FIELDS = ("key", "name", "description", "enabled", "key_usage", "extended_key_usage",
                 "include_ocsp_aia", "default_validity_days", "max_validity_days",
                 "allowed_key_types", "min_rsa_bits", "max_rsa_bits", "allowed_ec_sizes",
                 "allowed_san_types", "require_san", "cn_in_san")


def export_all():
    return [{k: v for k, v in p.to_dict().items() if k in EXPORT_FIELDS} for p in list_profiles()]


def import_profiles(items, replace=False, updated_by=None):
    """Upsert by key. Returns (created, updated) counts. With replace=False an
    existing key is left untouched."""
    created = updated = 0
    for item in items:
        key = (item.get("key") or "").strip()
        if not key:
            raise ValueError("Every profile needs a 'key'.")
        row = CertificateProfile.query.filter_by(key=key).first()
        fields = dict(item)
        if row is None:
            errors = validate(fields)
            if errors:
                raise ValueError(f"{key}: " + " ".join(errors))
            row = CertificateProfile(key=key, is_builtin=(key in {b["key"] for b in BUILTINS}),
                                     updated_by=updated_by)
            _apply(row, fields)
            db.session.add(row)
            created += 1
        elif replace:
            errors = validate(fields, existing=row)
            if errors:
                raise ValueError(f"{key}: " + " ".join(errors))
            _apply(row, fields)
            row.updated_by = updated_by
            updated += 1
    db.session.flush()
    return created, updated
