"""http-01 validation (RFC 8555 §8.3): fetch
http://<identifier>:<ACME_HTTP01_PORT>/.well-known/acme-challenge/<token>
and compare the body with the key authorization. Redirects are followed a few
hops, each hop re-checked against the outbound policy. Returns
(ok, error_type, detail)."""
import socket
import urllib.error
import urllib.parse
import urllib.request

from flask import current_app

from ..net_policy import OutboundTargetError, check_outbound_target

MAX_REDIRECTS = 5
MAX_BODY = 4096


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def challenge_url(host, token):
    port = int(current_app.config.get("ACME_HTTP01_PORT", 80))
    hostport = host if port == 80 else f"{host}:{port}"
    return f"http://{hostport}/.well-known/acme-challenge/{token}"


def fetch_http01(host, token, expected):
    timeout = float(current_app.config.get("ACME_HTTP01_TIMEOUT_SECONDS", 10))
    allow_loopback = bool(current_app.config.get("ACME_VALIDATION_ALLOW_LOOPBACK", False))
    # Test hook: connect to this host for the identifier's own URL instead of
    # resolving the identifier (redirect targets are still policy-checked).
    connect_host = current_app.config.get("ACME_VALIDATION_CONNECT_HOST") or None
    url = challenge_url(connect_host or host, token)
    opener = urllib.request.build_opener(_NoRedirect())
    for hop in range(MAX_REDIRECTS + 1):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            return False, "connection", f"Refusing to follow a {parsed.scheme!r} URL."
        try:
            check_outbound_target(parsed.hostname or "", allow_loopback=allow_loopback or (hop == 0 and bool(connect_host)))
        except OutboundTargetError as exc:
            return False, "connection", str(exc)
        req = urllib.request.Request(url, headers={"User-Agent": "Chancery-ACME/1.0", "Accept": "*/*", "Host": host if (hop == 0 and connect_host) else (parsed.netloc or host)})
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(MAX_BODY + 1)
                status = resp.status
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308) and exc.headers.get("Location"):
                url = urllib.parse.urljoin(url, exc.headers["Location"])
                continue
            return False, "incorrectResponse", f"{url} answered HTTP {exc.code}."
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            return False, "connection", f"Could not fetch {url}: {reason}"
        if status != 200:
            return False, "incorrectResponse", f"{url} answered HTTP {status}."
        if len(body) > MAX_BODY:
            return False, "incorrectResponse", f"{url} returned more than {MAX_BODY} bytes."
        got = body.decode("utf-8", "replace").strip()
        if got == expected:
            return True, None, None
        return False, "incorrectResponse", (f"{url} returned a key authorization that does not match "
                                            f"(got {got[:32]!r}…)." if len(got) > 32 else
                                            f"{url} returned a key authorization that does not match (got {got!r}).")
    return False, "connection", f"Too many redirects fetching {url}."
