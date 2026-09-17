"""Outbound target policy (G7-6): the server fetches URLs chosen by remote
parties (http-01 validation, webhooks). Refuse targets that would turn those
fetches into a probe of the host itself or of its link: loopback, link-local,
multicast, unspecified and reserved addresses, and the machine's own
addresses. RFC 1918 space stays allowed — a LAN CA validates LAN hosts.
"""
import ipaddress
import socket


class OutboundTargetError(ValueError):
    pass


def resolve(host):
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise OutboundTargetError(f"{host!r} does not resolve: {exc}")
    addresses = []
    for info in infos:
        address = info[4][0].split("%", 1)[0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise OutboundTargetError(f"{host!r} does not resolve.")
    return addresses


def own_addresses():
    """Best-effort set of this machine's addresses."""
    found = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(info[4][0].split("%", 1)[0])
    except (socket.gaierror, OSError):
        pass
    return found


def check_outbound_target(host, allow_loopback=False):
    """Resolve `host` and refuse addresses the server must not talk to.
    Returns the resolved addresses. `allow_loopback` is for tests only."""
    host = (host or "").strip().strip("[]").lower()
    if not host:
        raise OutboundTargetError("No host given.")
    own = set() if allow_loopback else own_addresses()
    addresses = resolve(host)
    for text in addresses:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            raise OutboundTargetError(f"{host!r} resolved to an invalid address {text!r}.")
        if ip.is_loopback or text in own:
            if allow_loopback:
                continue
            raise OutboundTargetError(f"{host!r} resolves to this server ({text}); refusing to contact it.")
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or (ip.is_reserved and not ip.is_private):
            raise OutboundTargetError(f"{host!r} resolves to {text}, which is not a routable target.")
    return addresses
