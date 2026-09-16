"""X.509 Name Constraints on CAs (F2, 2.22.0).

A CA can carry an RFC 5280 §4.2.1.10 `NameConstraints` extension (critical)
that limits the names its subtree may certify. Two halves live here:

- **Encoding**: constraint entries use the SAN spelling the rest of the app
  uses — `DNS:example.com`, `IP:10.0.0.0/8` (a network, not a host),
  `EMAIL:example.com` / `EMAIL:user@example.com`, `URI:example.com` (a host) —
  and are stored on the CA as `{"permitted": [...], "excluded": [...]}`.
- **Enforcement**: pyca does not validate constraints at issuance, so without
  a check here a constrained CA would happily sign a certificate every
  client rejects. `enforce()` walks the issuing chain and applies the RFC
  matching rules to the requested names (SANs, plus a Common Name that looks
  like a hostname): for every name type that appears in a CA's permitted
  subtrees the name must fall inside one of them, and a name inside any
  excluded subtree is refused — excluded wins.

Only dnsName, iPAddress, rfc822Name and uniformResourceIdentifier constraints
are generated and enforced. Other constraint types found on an imported CA
are kept for display (`other:` prefix) and are not evaluated here.
"""
import ipaddress
import json
import re
from urllib.parse import urlsplit

from cryptography import x509

from . import san as san_module

KINDS = ("dns", "ip", "email", "uri")
_PREFIXES = {"DNS": "dns", "IP": "ip", "EMAIL": "email", "URI": "uri"}
_LABELS = {"dns": "DNS", "ip": "IP", "email": "EMAIL", "uri": "URI", "other": "other"}
_HOSTNAME = re.compile(r"^(\*\.)?(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$")


# --- parsing -----------------------------------------------------------------

def parse_entry(entry):
    """`(kind, value)` for one constraint line, or None for a blank line.
    Raises ValueError for an unknown prefix, a bad value, or an IP that is
    not written as a network (RFC 5280 constrains networks, not hosts)."""
    raw = (entry or "").strip()
    if not raw:
        return None
    head, sep, rest = raw.partition(":")
    kind = _PREFIXES.get(head.strip().upper()) if sep else None
    if kind is None:
        raise ValueError(f"Unsupported name-constraint entry '{raw}': use DNS:, IP:, EMAIL: or URI:.")
    value = rest.strip()
    if not value:
        raise ValueError(f"Name-constraint entry '{raw}' has no value.")
    if kind == "dns":
        value = value.lower().rstrip(".")
        if value.startswith("*"):
            raise ValueError(f"DNS name constraint '{raw}' must not be a wildcard; use the parent domain.")
        if not re.match(r"^\.?(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$", value):
            raise ValueError(f"DNS name constraint '{raw}' is not a valid domain.")
    elif kind == "ip":
        if "/" not in value:
            raise ValueError(f"IP name constraint '{raw}' must be a network in CIDR form (e.g. 10.0.0.0/8).")
        try:
            value = str(ipaddress.ip_network(value, strict=True))
        except ValueError as exc:
            raise ValueError(f"IP name constraint '{raw}' is not a valid network: {exc}") from exc
    elif kind == "email":
        value = value.lower()
        host = value.rpartition("@")[2] if "@" in value else value
        if not re.match(r"^\.?(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$", host) or not host:
            raise ValueError(f"Email name constraint '{raw}' must be a domain, .domain or user@domain.")
    elif kind == "uri":
        value = value.lower().rstrip(".")
        if "/" in value or ":" in value:
            raise ValueError(f"URI name constraint '{raw}' must be a host name (RFC 5280 constrains the host part), not a URL.")
        if not re.match(r"^\.?(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$", value):
            raise ValueError(f"URI name constraint '{raw}' is not a valid host name.")
    return kind, value


def parse_entries(text_or_list):
    """Validated, de-duplicated `KIND:value` strings from a textarea or list."""
    lines = text_or_list.splitlines() if isinstance(text_or_list, str) else list(text_or_list or [])
    out = []
    for line in lines:
        parsed = parse_entry(line)
        if parsed is None:
            continue
        s = f"{_LABELS[parsed[0]]}:{parsed[1]}"
        if s not in out:
            out.append(s)
    return out


def normalise(permitted=None, excluded=None):
    """`{"permitted": [...], "excluded": [...]}` or None when both are empty."""
    p, e = parse_entries(permitted), parse_entries(excluded)
    if not p and not e:
        return None
    return {"permitted": p, "excluded": e}


def _split(entry):
    kind, _, value = entry.partition(":")
    return kind.lower(), value


# --- X.509 encoding ----------------------------------------------------------

def _general_name(kind, value):
    if kind == "dns":
        return x509.DNSName(value)
    if kind == "ip":
        return x509.IPAddress(ipaddress.ip_network(value))
    if kind == "email":
        return x509.RFC822Name(value)
    if kind == "uri":
        return x509.UniformResourceIdentifier(value)
    return None


def build_extension(constraints):
    """`x509.NameConstraints` for a stored dict, or None when empty."""
    if not constraints:
        return None
    subtrees = {}
    for side in ("permitted", "excluded"):
        names = []
        for entry in constraints.get(side) or []:
            kind, value = _split(entry)
            gn = _general_name(kind, value)
            if gn is not None:
                names.append(gn)
        subtrees[side] = names or None
    if not subtrees["permitted"] and not subtrees["excluded"]:
        return None
    return x509.NameConstraints(permitted_subtrees=subtrees["permitted"], excluded_subtrees=subtrees["excluded"])


def _to_string(general_name):
    if isinstance(general_name, x509.DNSName):
        return f"DNS:{general_name.value.lower()}"
    if isinstance(general_name, x509.IPAddress):
        return f"IP:{general_name.value}"
    if isinstance(general_name, x509.RFC822Name):
        return f"EMAIL:{general_name.value.lower()}"
    if isinstance(general_name, x509.UniformResourceIdentifier):
        return f"URI:{general_name.value.lower()}"
    return f"other:{general_name.__class__.__name__}"


def from_certificate(cert):
    """The stored dict for a certificate's NameConstraints extension, or
    None when it has none (imported CAs, F2)."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return None
    return {
        "permitted": [_to_string(n) for n in (ext.permitted_subtrees or [])],
        "excluded": [_to_string(n) for n in (ext.excluded_subtrees or [])],
    }


# --- matching (RFC 5280 §4.2.1.10) --------------------------------------------

def _dns_within(name, constraint):
    """`name` (may be a wildcard) is inside the dnsName constraint."""
    name = name.lower().rstrip(".")
    constraint = constraint.lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]                     # everything a wildcard can match must be inside
        return name == constraint.lstrip(".") or name.endswith("." + constraint.lstrip("."))
    if constraint.startswith("."):          # subdomains only
        return name.endswith(constraint)
    return name == constraint or name.endswith("." + constraint)


def _ip_within(name, constraint):
    try:
        net = ipaddress.ip_network(constraint)
        addr = ipaddress.ip_address(name)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


def _email_within(name, constraint):
    name = name.lower()
    constraint = constraint.lower()
    if "@" in constraint:
        return name == constraint
    host = name.rpartition("@")[2]
    if constraint.startswith("."):
        return host.endswith(constraint)
    return host == constraint


def _uri_within(name, constraint):
    host = (urlsplit(name).hostname or "").lower().rstrip(".")
    if not host:
        return False                        # RFC 5280: the constraint applies to the host part
    constraint = constraint.lower().rstrip(".")
    if constraint.startswith("."):
        return host.endswith(constraint)
    return host == constraint


_WITHIN = {"dns": _dns_within, "ip": _ip_within, "email": _email_within, "uri": _uri_within}


def looks_like_hostname(common_name):
    return bool(common_name) and bool(_HOSTNAME.match(common_name.strip()))


def requested_names(subject_attrs, san_list):
    """`(kind, value)` pairs a constraint can apply to: the SANs of the
    supported types, plus a Common Name that looks like a hostname (treated
    as a dnsName, as most validators do)."""
    names = []
    for entry in san_list or []:
        parsed = san_module.parse_entry(entry)
        if parsed and parsed[0] in KINDS:
            names.append(parsed)
    cn = (subject_attrs or {}).get("CN") or (subject_attrs or {}).get("commonName")
    if looks_like_hostname(cn):
        names.append(("dns", cn.strip().lower().rstrip(".")))
    return names


def check_names(constraints, names, ca_label="the CA"):
    """Raise ValueError naming the first requested name a CA's constraints
    refuse."""
    if not constraints:
        return
    permitted = [_split(e) for e in constraints.get("permitted") or []]
    excluded = [_split(e) for e in constraints.get("excluded") or []]
    for kind, value in names:
        label = f"{_LABELS.get(kind, kind)} name '{value}'"
        for ckind, cvalue in excluded:
            if ckind == kind and _WITHIN[kind](value, cvalue):
                raise ValueError(f"{label} is excluded by {ca_label}'s name constraints ({_LABELS[ckind]}:{cvalue}).")
        same_type = [(ck, cv) for ck, cv in permitted if ck == kind]
        if same_type and not any(_WITHIN[kind](value, cv) for _ck, cv in same_type):
            allowed = ", ".join(f"{_LABELS[ck]}:{cv}" for ck, cv in same_type)
            raise ValueError(f"{label} is outside {ca_label}'s permitted name constraints ({allowed}).")


def enforce(ca, subject_attrs, san_list):
    """Check a certificate request against the name constraints of `ca` and
    every CA above it. Raises ValueError with the offending name and CA."""
    names = requested_names(subject_attrs, san_list)
    if not names:
        return
    current = ca
    seen = set()
    while current is not None and current.id not in seen:
        seen.add(current.id)
        check_names(current.name_constraints, names, ca_label=f"CA '{current.name}'")
        current = current.parent
