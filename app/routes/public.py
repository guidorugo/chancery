import base64
import binascii
from urllib.parse import unquote

from flask import Blueprint, Response, current_app, request
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..extensions import db, csrf
from ..models.ca import CertificateAuthority
from ..services import ocsp_service
from ..services.filenames import content_disposition

public_bp = Blueprint("public", __name__, url_prefix="/public")


def _ca_disposition(ca, extension):
    # G8-1: ASCII filename (falls back to the CA id for names with no
    # printable ASCII) plus an RFC 5987 filename* with the real name.
    return content_disposition(ca.name, extension, fallback=f"ca-{ca.id}")


@public_bp.route("/crl/<int:ca_id>.crl")
def download_crl_der(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404
    # C1: the public CRL endpoint is strictly read-only — it serves the cached
    # CRL and never decrypts the CA key or writes to the DB. Keyed CAs get an
    # initial CRL at creation; revocation refreshes it (B2). No cached CRL
    # (e.g. certificate-only CA) → 404.
    if not ca.crl_pem:
        return "CRL not available for this CA", 404
    try:
        crl = x509.load_pem_x509_crl(ca.crl_pem.encode())
        return Response(
            crl.public_bytes(serialization.Encoding.DER),
            mimetype="application/pkix-crl",
            headers={"Content-Disposition": _ca_disposition(ca, "crl")},
        )
    except Exception:
        current_app.logger.exception("Error serving cached CRL (DER)")
        return "Internal server error", 500


@public_bp.route("/crl/<int:ca_id>.pem")
def download_crl_pem(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404
    if not ca.crl_pem:  # C1: read-only, see download_crl_der
        return "CRL not available for this CA", 404
    try:
        return Response(
            ca.crl_pem,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": _ca_disposition(ca, "crl.pem")},
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
