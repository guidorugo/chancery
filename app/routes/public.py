import base64
import binascii
from datetime import datetime, timezone
from urllib.parse import unquote

from flask import Blueprint, Response, current_app, request
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from werkzeug.http import http_date

from ..extensions import db, csrf
from ..models.ca import CertificateAuthority
from ..services import audit_service, crl_service, ocsp_service
from ..services.filenames import content_disposition

public_bp = Blueprint("public", __name__, url_prefix="/public")


def _ca_disposition(ca, extension):
    # G8-1: ASCII filename (falls back to the CA id for names with no
    # printable ASCII) plus an RFC 5987 filename* with the real name.
    return content_disposition(ca.name, extension, fallback=f"ca-{ca.id}")


def _current_crl(ca):
    """The CA's cached CRL, regenerated first when it is past nextUpdate and
    the CA can still sign (lazy refresh, G4-1 belt-and-braces to the
    scheduler). A refresh failure serves the stale CRL rather than nothing.
    Returns a pyca CRL or None."""
    if not ca.crl_pem:
        return None
    try:
        crl = x509.load_pem_x509_crl(ca.crl_pem.encode())
    except Exception:
        current_app.logger.exception("Cached CRL for CA %s is unreadable", ca.id)
        return None
    next_update = crl.next_update_utc
    if (next_update is not None and next_update <= datetime.now(timezone.utc)
            and not ca.is_revoked and ca.has_signing_key and ca.approval_status != "pending"):
        try:
            crl = crl_service.generate_crl(ca, current_app.config["MASTER_PASSPHRASE"])
            audit_service.log_action("crl_refreshed", target_type="ca", target_id=ca.id,
                                     details={"trigger": "lazy", "crl_number": ca.crl_number},
                                     actor="system")
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Lazy CRL refresh failed for CA %s; serving the stale CRL", ca.id)
    return crl


def _crl_headers(ca, crl, extension):
    """Content-Disposition plus HTTP caching headers derived from the CRL's
    own validity window (G8-4): Last-Modified = thisUpdate, Expires =
    nextUpdate, Cache-Control max-age = seconds until nextUpdate."""
    headers = {"Content-Disposition": _ca_disposition(ca, extension),
               "Last-Modified": http_date(crl.last_update_utc)}
    next_update = crl.next_update_utc
    if next_update is not None:
        max_age = max(0, int((next_update - datetime.now(timezone.utc)).total_seconds()))
        headers["Expires"] = http_date(next_update)
        headers["Cache-Control"] = f"public, max-age={max_age}"
    return headers


@public_bp.route("/crl/<int:ca_id>.crl")
def download_crl_der(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404
    # C1: the public CRL endpoint is strictly read-only — it serves the cached
    # CRL and never decrypts the CA key or writes to the DB. Keyed CAs get an
    # initial CRL at creation; revocation refreshes it (B2). No cached CRL
    # (e.g. certificate-only CA) → 404.
    crl = _current_crl(ca)
    if crl is None:
        return "CRL not available for this CA", 404
    try:
        return Response(
            crl.public_bytes(serialization.Encoding.DER),
            mimetype="application/pkix-crl",
            headers=_crl_headers(ca, crl, "crl"),
        )
    except Exception:
        current_app.logger.exception("Error serving cached CRL (DER)")
        return "Internal server error", 500


@public_bp.route("/crl/<int:ca_id>.pem")
def download_crl_pem(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404
    crl = _current_crl(ca)
    if crl is None:
        return "CRL not available for this CA", 404
    try:
        return Response(
            crl.public_bytes(serialization.Encoding.PEM),
            mimetype="application/x-pem-file",
            headers=_crl_headers(ca, crl, "crl.pem"),
        )
    except Exception:
        current_app.logger.exception("Error generating CRL (PEM)")
        return "Internal server error", 500


@public_bp.route("/ca/<int:ca_id>.crt")
def download_ca_cert(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404

    return Response(
        ca.certificate_pem,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": _ca_disposition(ca, "crt")},
    )


@public_bp.route("/ca/<int:ca_id>/alt/<int:alt_id>.crt")
def download_ca_alt_cert(ca_id, alt_id):
    """F11: an approved alternate certificate for the CA's key (a previous
    primary or a cross-certificate), so relying parties can fetch either
    trust path."""
    from ..models.ca_certificate import CaCertificate
    ca = db.session.get(CertificateAuthority, ca_id)
    row = db.session.get(CaCertificate, alt_id)
    if not ca or row is None or row.ca_id != ca.id or row.approval_status != "approved":
        return "CA certificate not found", 404
    return Response(
        row.certificate_pem,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": content_disposition(f"{ca.name}-alt-{row.id}", "crt", fallback=f"ca-{ca.id}-alt-{row.id}")},
    )


def _ocsp_respond(ca, ocsp_request_der):
    passphrase = current_app.config["MASTER_PASSPHRASE"]
    try:
        response_der = ocsp_service.build_ocsp_response(ocsp_request_der, ca, passphrase)
    except ocsp_service.MalformedOcspRequest as exc:
        # G8-2: an unparseable request is a client error. RFC 6960 §4.2.1 wants
        # an OCSP-level `malformedRequest` at HTTP 200 — not a 500, and not a
        # traceback in the log for every scanner probe.
        current_app.logger.info("OCSP malformed request for CA %s: %s", ca.id, exc)
        response_der = ocsp_service.malformed_response()
    except Exception:
        current_app.logger.exception("OCSP responder error")
        return "Internal server error", 500
    return Response(response_der, mimetype="application/ocsp-response")


@public_bp.route("/ocsp/<int:ca_id>", methods=["POST"])
@csrf.exempt
def ocsp_responder(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404
    return _ocsp_respond(ca, request.get_data())


@public_bp.route("/ocsp/<int:ca_id>/<path:encoded>", methods=["GET"])
def ocsp_responder_get(ca_id, encoded):
    """RFC 6960 §A.1 GET form: the base64 DER OCSPRequest, URL-encoded, appended
    to the responder URL. Windows CryptoAPI and several appliances use it by
    default for small requests (G8-2)."""
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404
    try:
        ocsp_request_der = base64.b64decode(unquote(encoded), validate=False)
    except (binascii.Error, ValueError) as exc:
        current_app.logger.info("OCSP GET with undecodable base64 for CA %s: %s", ca.id, exc)
        return Response(ocsp_service.malformed_response(), mimetype="application/ocsp-response")
    return _ocsp_respond(ca, ocsp_request_der)
