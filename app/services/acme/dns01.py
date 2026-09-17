"""dns-01 validation (RFC 8555 §8.4), 3.6.0.

The client publishes a TXT record `_acme-challenge.<identifier>` whose value is
the base64url SHA-256 digest of the key authorization; the CA looks it up and
compares. A wildcard identifier uses its base name (`*.example.lan` →
`_acme-challenge.example.lan`), which is the only way RFC 8555 lets a wildcard
be proven.

Lookups go to `ACME_DNS_RESOLVERS` (comma-separated `host[:port]`; every
listed server must agree — a cheap multi-perspective check for a LAN without
DNSSEC, and pinning the authoritative server sidesteps negative caching) or,
when unset, to the container's own resolver. Nothing here fetches over HTTP,
so the http-01 outbound policy does not apply: answers are only compared.

Tests monkeypatch `lookup_txt`.
"""
import base64
import hashlib
import socket

import dns.exception
import dns.resolver
from flask import current_app


class DnsLookupError(Exception):
    """The query itself failed (timeout, SERVFAIL, no resolver) — unlike a
    clean 'no such record' answer, which `lookup_txt` returns as []."""


def txt_name(identifier):
    base = identifier[2:] if identifier.startswith("*.") else identifier
    return f"_acme-challenge.{base}"


def txt_value(key_authorization):
    digest = hashlib.sha256(key_authorization.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def configured_resolvers():
    """`[(ip, port), ...]` from ACME_DNS_RESOLVERS; [] means the system
    resolver. A hostname (e.g. a compose service name) is resolved here."""
    raw = current_app.config.get("ACME_DNS_RESOLVERS") or ""
    out = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        host, port = item, 53
        if item.startswith("["):                     # [v6]:port
            host, _, rest = item[1:].partition("]")
            if rest.startswith(":"):
                port = int(rest[1:])
        elif item.count(":") == 1:
            host, port = item.rsplit(":", 1)
            port = int(port)
        try:
            ip = socket.getaddrinfo(host, None)[0][4][0]
        except OSError as exc:
            raise DnsLookupError(f"cannot resolve ACME_DNS_RESOLVERS entry {host!r}: {exc}")
        out.append((ip, port))
    return out


def lookup_txt(name, nameserver=None, timeout=5.0):
    """TXT strings at `name` (CNAME chains are followed); [] when the name or
    the record does not exist; DnsLookupError when the query fails."""
    if nameserver:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver[0]]
        resolver.port = nameserver[1]
    else:
        try:
            resolver = dns.resolver.Resolver()
        except dns.exception.DNSException as exc:     # no usable resolv.conf
            raise DnsLookupError(f"no system resolver: {exc}")
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(name, "TXT", search=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, OSError) as exc:
        text = str(exc)
        raise DnsLookupError(f"{exc.__class__.__name__}: {text}" if text else exc.__class__.__name__)
    return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer]


def validate(identifier, expected):
    """Look the record up on every configured resolver. Returns
    (ok, error_type, detail); every failure is retryable — propagation and
    caches are the usual causes, and the attempt budget bounds the retries."""
    name = txt_name(identifier)
    timeout = float(current_app.config.get("ACME_DNS_TIMEOUT_SECONDS", 5))
    try:
        servers = configured_resolvers() or [None]
    except DnsLookupError as exc:
        return False, "dns", str(exc)
    missing, others = [], set()
    for server in servers:
        label = f"{server[0]}:{server[1]}" if server else "the system resolver"
        try:
            values = lookup_txt(name, server, timeout)
        except DnsLookupError as exc:
            return False, "dns", f"Lookup of TXT {name} via {label} failed: {exc}"
        if expected in values:
            continue
        missing.append(label)
        others.update(values)
    if not missing:
        return True, None, None
    where = ", ".join(missing)
    if others:
        return False, "incorrectResponse", (f"TXT {name} (via {where}) holds {len(others)} record(s) "
                                            "but not the expected key authorization digest.")
    return False, "dns", f"No TXT record {name} (via {where})."
