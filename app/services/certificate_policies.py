"""Certificate Policies extension (F3, 2.23.0).

A CA can declare the policy OIDs it issues under — optionally with a CPS
(Certification Practice Statement) URI qualifier — as an RFC 5280 §4.2.1.4
`certificatePolicies` extension on its own certificate. Every certificate the
CA issues inherits that list unless the certificate profile (F1) declares its
own, which then wins. Stored as `[{"oid": "...", "cps_uri": "..."|null}]` on
`certificate_authorities.certificate_policies_json` and
`certificate_profiles.certificate_policies_json`.

Text form (one policy per line, CA create form / API / profile form):

    1.3.6.1.4.1.99999.1.1 https://pki.example/cps
    2.5.29.32.0                      # anyPolicy, no CPS
"""
import re
from urllib.parse import urlsplit

from cryptography import x509

ANY_POLICY = "2.5.29.32.0"
_OID = re.compile(r"^[0-2](\.\d+)+$")


def parse_entry(line):
    """`{"oid", "cps_uri"}` for one `OID [CPS-URI]` line, or None for a blank
    line. Raises ValueError for a bad OID or a CPS that is not an http(s) URL."""
    raw = (line or "").strip()
    if not raw or raw.startswith("#"):
        return None
    parts = raw.split(None, 1)
    oid = parts[0].strip()
    cps = parts[1].strip() if len(parts) > 1 else ""
    if not _OID.match(oid):
        raise ValueError(f"'{oid}' is not a valid policy OID (dotted digits, e.g. 1.3.6.1.4.1.99999.1.1).")
    arcs = oid.split(".")
    if arcs[0] in ("0", "1") and int(arcs[1]) > 39:
        raise ValueError(f"'{oid}' is not a valid OID (the second arc must be 0–39 under {arcs[0]}).")
    if any(len(a) > 1 and a.startswith("0") for a in arcs):
        raise ValueError(f"'{oid}' is not a valid OID (no leading zeros in an arc).")
    if cps:
        parts_url = urlsplit(cps)
        if parts_url.scheme not in ("http", "https") or not parts_url.netloc:
            raise ValueError(f"CPS URI '{cps}' must be an http:// or https:// URL.")
    return {"oid": oid, "cps_uri": cps or None}


def parse_entries(text_or_list):
    """Validated, de-duplicated (by OID) policy list from a textarea, a list of
    lines, or a list of dicts (import)."""
    if isinstance(text_or_list, str):
        items = text_or_list.splitlines()
    else:
        items = list(text_or_list or [])
    out, seen = [], set()
    for item in items:
        if isinstance(item, dict):
            line = f"{item.get('oid', '')} {item.get('cps_uri') or ''}"
        else:
            line = item
        parsed = parse_entry(line)
        if parsed is None or parsed["oid"] in seen:
            continue
        seen.add(parsed["oid"])
        out.append(parsed)
    return out


def normalise(text_or_list):
    """Policy list or None when empty."""
    return parse_entries(text_or_list) or None


def to_lines(policies):
    """Text form for a form field."""
    return "\n".join(f"{p['oid']} {p.get('cps_uri') or ''}".strip() for p in (policies or []))


def build_extension(policies):
    """`x509.CertificatePolicies` for a stored list, or None."""
    if not policies:
        return None
    infos = [x509.PolicyInformation(x509.ObjectIdentifier(p["oid"]), [p["cps_uri"]] if p.get("cps_uri") else None)
             for p in policies]
    return x509.CertificatePolicies(infos)


def from_certificate(cert):
    """Stored list for a certificate's certificatePolicies extension, or
    None. CPS URI qualifiers are kept; user-notice qualifiers are dropped."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
    except x509.ExtensionNotFound:
        return None
    out = []
    for info in ext:
        cps = next((q for q in (info.policy_qualifiers or []) if isinstance(q, str)), None)
        out.append({"oid": info.policy_identifier.dotted_string, "cps_uri": cps})
    return out or None


def for_issuance(ca, profile=None):
    """The policies an end-entity certificate issued by `ca` carries: the
    profile's own list when it declares one, else the CA's (None = no
    extension)."""
    if profile is not None and getattr(profile, "certificate_policies", None):
        return profile.certificate_policies
    return getattr(ca, "certificate_policies", None)
