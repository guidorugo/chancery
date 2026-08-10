"""Server-side issuance policy enforcement (B4, B5).

These checks run in the service layer so they apply regardless of the caller
(web form, Basic-Auth API, or a direct service call) — the UI checkboxes are
not a security boundary.
"""
from datetime import timedelta, timezone

from flask import current_app
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID


def _cfg(key, default):
    try:
        return current_app.config.get(key, default)
    except RuntimeError:  # outside app context — fall back to the secure default
        return default


def enforce_key_strength(key_type, key_size):
    """Reject weak key parameters before generating a key (B5)."""
    if key_type == "RSA":
        minimum = _cfg("MIN_RSA_KEY_SIZE", 2048)
        if key_size < minimum:
            raise ValueError(f"RSA key size must be at least {minimum} bits (got {key_size}).")
    elif key_type == "EC":
        if key_size not in (256, 384, 521):
            raise ValueError("EC key size must be one of 256, 384, or 521.")
    else:
        raise ValueError(f"Unsupported key type: {key_type}")


def enforce_public_key_strength(public_key):
    """Reject a weak public key presented in a CSR or import (B5)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        minimum = _cfg("MIN_RSA_KEY_SIZE", 2048)
        if public_key.key_size < minimum:
            raise ValueError(
                f"Public key is too weak: RSA {public_key.key_size} bits (minimum {minimum})."
            )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.key_size not in (256, 384, 521):
            raise ValueError("Unsupported EC curve; use P-256, P-384, or P-521.")


def bounded_not_after(now, validity_days, ca_not_after=None, is_ca=False):
    """Return `now + validity_days`, bounded by the configured maximum and by
    the issuing CA's own expiry (B4). Raises ValueError on violation.

    `ca_not_after` may be naive (SQLite drops tzinfo) — treated as UTC.
    """
    if validity_days is None or validity_days < 1:
        raise ValueError("Validity (days) must be a positive integer.")
    max_days = _cfg("MAX_CA_VALIDITY_DAYS", 7305) if is_ca else _cfg("MAX_CERT_VALIDITY_DAYS", 825)
    if validity_days > max_days:
        kind = "CA" if is_ca else "certificate"
        raise ValueError(f"{kind} validity {validity_days} days exceeds the maximum of {max_days} days.")
    not_after = now + timedelta(days=validity_days)
    if ca_not_after is not None:
        ca_na = ca_not_after if ca_not_after.tzinfo else ca_not_after.replace(tzinfo=timezone.utc)
        # A certificate must not outlive its issuer. Clamp rather than reject so
        # that "same validity as the CA" (which would outlive it by the
        # creation-time delta) issues cleanly, capped at the CA's expiry.
        if not_after > ca_na:
            not_after = ca_na
    return not_after


# Subject attributes we accept, in canonical order, each with its OID and a
# human label. cryptography enforces X.520 length limits on some of these
# (COUNTRY_NAME must be exactly 2, COMMON_NAME 1..64) and raises a terse,
# field-less ValueError — e.g. "Attribute's length must be >= 2 and <= 2, but
# it was 1" for a one-letter country. We validate here, in the service layer,
# so every caller (web form, Basic-Auth/JSON API, CLI, or a direct service
# call) gets a message that names the offending field.
_SUBJECT_ATTRS = (
    ("CN", "Common Name", NameOID.COMMON_NAME),
    ("O", "Organization", NameOID.ORGANIZATION_NAME),
    ("OU", "Organizational Unit", NameOID.ORGANIZATIONAL_UNIT_NAME),
    ("C", "Country", NameOID.COUNTRY_NAME),
    ("ST", "State/Province", NameOID.STATE_OR_PROVINCE_NAME),
    ("L", "Locality", NameOID.LOCALITY_NAME),
)


def build_subject(attrs):
    """Validate subject attributes and build an ``x509.Name``.

    Raises ``ValueError`` with a field-named message (the create routes surface
    it as a 400) instead of letting cryptography's terse length error bubble up
    as an opaque 500. Empty/omitted fields are skipped; values are stripped.
    """
    name_attrs = []
    for key, label, oid in _SUBJECT_ATTRS:
        raw = attrs.get(key)
        value = raw.strip() if isinstance(raw, str) else raw
        if not value:
            continue
        if key == "C" and len(value) != 2:
            raise ValueError(
                f"{label} (C) must be the two-letter ISO 3166 country code, "
                f"e.g. US, DE, GB (got '{value}')."
            )
        try:
            name_attrs.append(x509.NameAttribute(oid, value))
        except ValueError as exc:
            # Safety net for any other constraint cryptography enforces (e.g. a
            # Common Name over 64 chars, or a value it cannot encode): name the
            # field so the caller knows which one to fix.
            raise ValueError(f"{label} ({key}) is invalid: {exc}") from exc
    return x509.Name(name_attrs)
