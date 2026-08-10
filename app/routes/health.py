"""Unauthenticated health endpoint for monitoring and container healthchecks.

`GET /health` performs a cheap database round-trip and reports overall status
(200 healthy / 503 unhealthy). It deliberately exposes no secrets, version, or
internal error detail — checks report enum states only. No auth and no CSRF
(GET), and it must stay reachable while the forced-password-change guard is
active (the guard exempts this blueprint).
"""
from flask import Blueprint, jsonify

from ..extensions import db

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health():
    checks = {}
    healthy = True
    try:
        # Cheapest possible liveness-of-DB probe; no key decryption, no crypto,
        # nothing that an unauthenticated flood could turn into real work.
        from sqlalchemy import text
        db.session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"
        healthy = False
    finally:
        # Frequent probes must not leave a transaction/connection open.
        db.session.rollback()

    return jsonify({"status": "ok" if healthy else "unhealthy", "checks": checks}), \
        (200 if healthy else 503)
