"""Public hostname resolution for the URLs embedded in certificates (G8-3, C4).

The AIA (OCSP) and CRL Distribution Point URLs are baked into every issued
certificate for its whole lifetime, so the hostname must be one relying
parties can reach. `SERVER_NAME_FOR_OCSP` pins it; while it is left at the
default (`localhost:5000`) the request's Host header is used, which is only
right when the admin issues through the same name clients use.

A loopback name is never right for a relying party — it resolves to the
verifier itself — so embedding one is refused outside debug/testing.
"""
from urllib.parse import urlsplit

from flask import current_app, request

DEFAULT_SERVER_NAME = "localhost:5000"

_LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "::"}


def public_scheme():
    return current_app.config.get("OCSP_URL_SCHEME", "http")


def public_host():
    """`host[:port]` to embed: the pinned `SERVER_NAME_FOR_OCSP`, or the request Host while at the default."""
    configured = current_app.config.get("SERVER_NAME_FOR_OCSP") or DEFAULT_SERVER_NAME
    if configured == DEFAULT_SERVER_NAME:
        return request.host
    return configured


def host_only(hostport):
    """Strip a port from `host:port` / `[v6]:port`; lowercase."""
    value = (hostport or "").strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end > 0 else value
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value


def is_loopback(hostport):
    host = host_only(hostport)
    return host in _LOOPBACK_NAMES or host.startswith("127.") or host.endswith(".localhost")


def check_embeddable(url_or_host):
    """Raise ValueError when the host would be useless to a relying party.

    Allowed in TESTING/debug so the dev server and the test suite keep working
    against localhost.
    """
    if current_app.config.get("TESTING") or current_app.debug:
        return
    host = urlsplit(url_or_host).netloc if "://" in url_or_host else url_or_host
    if is_loopback(host):
        raise ValueError(
            f"Refusing to embed the loopback hostname '{host_only(host)}' in the certificate's "
            "OCSP/CRL URLs: relying parties could never reach it. Set SERVER_NAME_FOR_OCSP "
            "to the hostname clients use, or issue through that hostname.")


def ocsp_url(ca_id):
    return f"{public_scheme()}://{public_host()}/public/ocsp/{ca_id}"


def crl_url(ca_id):
    return f"{public_scheme()}://{public_host()}/public/crl/{ca_id}.crl"


def issuance_urls(ca_id, crl_dp_override=None):
    """(ocsp_url, crl_dp_url) for a certificate about to be issued by `ca_id`.

    `crl_dp_override` is the operator-edited CDP field (blank = auto). Raises
    ValueError when either URL points at a loopback host (see check_embeddable).
    """
    aia = ocsp_url(ca_id)
    cdp = (crl_dp_override or "").strip() or crl_url(ca_id)
    check_embeddable(aia)
    check_embeddable(cdp)
    return aia, cdp
