"""Prometheus ``/metrics`` endpoint (2.7.0).

Opt-in via ``METRICS_ENABLED`` (404 until enabled). When enabled it requires a
valid **dedicated bearer token** (a ``MetricsToken`` — never a user credential),
unless ``METRICS_ALLOW_UNAUTHENTICATED`` is set for an isolated network. The
blueprint is exempt from rate limiting and the forced-password-change guard
(wired in ``app/__init__.py``), exactly like ``/health``.

Per-scrape auth is intentionally NOT audited (a scraper hits this every few
seconds; auditing would flood the log — mirrors ``/health`` being unaudited).
"""
from flask import Blueprint, Response, current_app, request

from ..extensions import db
from ..services import metrics_service, metrics_token_service

metrics_bp = Blueprint("metrics", __name__)

_PLAIN = "text/plain; charset=utf-8"


def _bearer(req):
    """Extract the token from an ``Authorization: Bearer <token>`` header (only —
    never a query string, which would leak into access logs)."""
    header = req.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer "):].strip()
    return ""


@metrics_bp.route("/metrics", methods=["GET"])
def metrics():
    if not current_app.config.get("METRICS_ENABLED", False):
        # Return 404 directly (not abort) so the JSON error handler can't turn a
        # scraper's Accept:*/* into a JSON body — keep it trivially text/plain.
        return Response("Not found\n", status=404, content_type=_PLAIN)

    if not current_app.config.get("METRICS_ALLOW_UNAUTHENTICATED", False):
        token = metrics_token_service.verify(_bearer(request))
        if token is None:
            resp = Response("Unauthorized\n", status=401, content_type=_PLAIN)
            resp.headers["WWW-Authenticate"] = 'Bearer realm="cert-manager-metrics"'
            return resp
        metrics_token_service.touch(token)

    try:
        body = metrics_service.render(current_app.config)
    except Exception:
        current_app.logger.exception("metrics collection failed")
        db.session.rollback()
        return Response("# metrics collection failed\n", status=503,
                        content_type=metrics_service.CONTENT_TYPE)
    finally:
        # A frequent scrape must not leave a read transaction/connection open.
        db.session.rollback()

    return Response(body, status=200, content_type=metrics_service.CONTENT_TYPE)
