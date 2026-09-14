"""Subject Alternative Name syntax, encoding and decoding (F4, G4-4).

The forms and the API take SANs as `TYPE:value` strings, one per entry:

    example.com            bare hostname → DNS
    DNS:example.com
    IP:192.0.2.10          also IPv6, e.g. IP:2001:db8::10
    EMAIL:alice@example.com
    URI:https://svc.example.com/id   (also spiffe://..., urn:...)
    UPN:alice@corp.example  Microsoft User Principal Name (otherName 1.3.6.1.4.1.311.20.2.3)

Anything else with a colon is refused instead of being silently issued as a
DNS name (G4-4): `https://x` becomes an error that says to use `URI:`, and a
bare IPv6 literal needs `IP:`.
"""
import ipaddress

from asn1crypto import core as asn1core
from cryptography import x509

UPN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")

TYPES = ("dns", "ip", "email", "uri", "upn")
_PREFIXES = {"DNS": "dns", "IP": "ip", "EMAIL": "email", "URI": "uri", "UPN": "upn"}
_LABELS = {"dns": "DNS", "ip": "IP", "email": "EMAIL", "uri": "URI", "upn": "UPN"}


def parse_entry(entry):
    """`(kind, value)` for one SAN string, or None for a blank entry.

    Raises ValueError for an unknown prefix or an empty value.
    """
    raw = (entry or "").strip()
    if not raw:
        return None
    head, sep, rest = raw.partition(":")
    if sep:
        kind = _PREFIXES.get(head.strip().upper())
        if kind is None:
            raise ValueError(
                f"Unsupported SAN entry '{raw}': use a bare hostname or one of DNS:, IP:, "
                "EMAIL:, URI:, UPN: (a URL needs the URI: prefix, an IPv6 address the IP: prefix).")
        value = rest.strip()
        if not value:
            raise ValueError(f"SAN entry '{raw}' has no value.")
        return kind, value
    return "dns", raw


def san_type(entry):
    """Kind of one entry ('dns', 'ip', 'email', 'uri', 'upn'); None for blank."""
    parsed = parse_entry(entry)
    return parsed[0] if parsed else None


def to_general_name(kind, value):
    if kind == "dns":
        return x509.DNSName(value)
    if kind == "ip":
        try:
            return x509.IPAddress(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError(f"Invalid IP address in SAN: '{value}'.") from exc
    if kind == "email":
        return x509.RFC822Name(value)
    if kind == "uri":
        return x509.UniformResourceIdentifier(value)
    if kind == "upn":
        return x509.OtherName(UPN_OID, asn1core.UTF8String(value).dump())
    raise ValueError(f"Unsupported SAN type '{kind}'.")


def build_general_names(entries):
    """List of pyca GeneralName objects for the given `TYPE:value` strings.
    Blank entries are skipped; a bad entry raises ValueError."""
    names = []
    for entry in entries or []:
        parsed = parse_entry(entry)
        if parsed is None:
            continue
        names.append(to_general_name(*parsed))
    return names


def build_extension(entries):
    """`x509.SubjectAlternativeName` for the entries, or None when empty."""
    names = build_general_names(entries)
    return x509.SubjectAlternativeName(names) if names else None


def general_name_to_string(name):
    """Canonical `TYPE:value` for a GeneralName we understand; None otherwise
    (directoryName, registeredID and other otherNames are not carried)."""
    if isinstance(name, x509.DNSName):
        return f"DNS:{name.value}"
    if isinstance(name, x509.IPAddress):
        return f"IP:{name.value}"
    if isinstance(name, x509.RFC822Name):
        return f"EMAIL:{name.value}"
    if isinstance(name, x509.UniformResourceIdentifier):
        return f"URI:{name.value}"
    if isinstance(name, x509.OtherName) and name.type_id == UPN_OID:
        try:
            return f"UPN:{asn1core.UTF8String.load(name.value).native}"
        except (ValueError, TypeError):
            return None
    return None


def extension_to_strings(san_extension_value):
    """All carried entries of a SubjectAlternativeName extension value."""
    out = []
    for name in san_extension_value:
        text = general_name_to_string(name)
        if text:
            out.append(text)
    return out


def label(kind):
    return _LABELS.get(kind, kind.upper())
