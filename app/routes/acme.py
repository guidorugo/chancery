"""F14: ACME (RFC 8555) endpoints, one directory per CA:
/acme/<ca_id>/directory. No session, CSRF or password-change gate — the
requests are authenticated by their JWS. Every response carries a fresh
Replay-Nonce and a Link to the directory; errors are problem+json."""
import json
import logging

from flask import Blueprint, Response, current_app, g, jsonify, request
from werkzeug.exceptions import HTTPException

from ..extensions import csrf, db
from ..models.ca import CertificateAuthority
from ..services.acme import jws, service
from ..services.acme.problem import AcmeProblem

logger = logging.getLogger(__name__)
acme_bp = Blueprint("acme", __name__, url_prefix="/acme/<int:ca_id>")
csrf.exempt(acme_bp)


@acme_bp.url_value_preprocessor
def _pull_ca_id(endpoint, values):
    g.acme_ca_id = values.pop("ca_id", None)


@acme_bp.url_defaults
def _push_ca_id(endpoint, values):
    if "ca_id" not in values and getattr(g, "acme_ca_id", None) is not None:
        values["ca_id"] = g.acme_ca_id


def _ca_available(ca):
    return (ca is not None and ca.acme_enabled and not ca.is_revoked and ca.has_signing_key
            and ca.approval_status == "approved" and ca.expiry_status != "expired")


@acme_bp.before_request
def _load_ca():
    if not current_app.config.get("ACME_ENABLED"):
        raise AcmeProblem("malformed", "ACME is not enabled on this server (ACME_ENABLED).", status=404)
    ca = db.session.get(CertificateAuthority, g.acme_ca_id) if g.acme_ca_id else None
    if not _ca_available(ca):
        raise AcmeProblem("malformed", "No ACME directory for this CA.", status=404)
    g.acme_ca = ca


@acme_bp.after_request
def _acme_headers(response):
    try:
        response.headers["Replay-Nonce"] = service.issue_nonce()
    except Exception:       # never let nonce bookkeeping break a response
        logger.exception("Could not issue an ACME nonce")
        db.session.rollback()
    response.headers.add("Link", f'<{service.acme_url("acme.directory", g.acme_ca_id)}>;rel="index"')
    response.headers["Cache-Control"] = "no-store"
    return response


@acme_bp.errorhandler(AcmeProblem)
def _problem(exc):
    if exc.status >= 500:
        db.session.rollback()
    return exc.response()


@acme_bp.errorhandler(Exception)
def _unexpected(exc):
    if isinstance(exc, HTTPException):
        return AcmeProblem("malformed", exc.description, status=exc.code).response()
    logger.exception("ACME request failed")
    db.session.rollback()
    return AcmeProblem("serverInternal", "Internal error.", status=500).response()


def _json(data, status=200, **headers):
    response = jsonify(data)
    response.status_code = status
    for k, v in headers.items():
        response.headers[k] = v
    return response


def _verified(allow_jwk=False, allow_kid=True, post_as_get=False):
    """Parse and verify the request JWS, check the nonce, return Verified."""
    if request.mimetype != "application/jose+json":
        raise AcmeProblem("malformed", "Content-Type must be application/jose+json.", status=415)
    ca = g.acme_ca
    body = jws.parse(request.get_data(cache=False, as_text=False))
    url = request.url if not current_app.config.get("ACME_BASE_URL") else \
        current_app.config["ACME_BASE_URL"].rstrip("/") + request.path
    verified = jws.verify(body, url, lambda kid: service.account_for_kid(ca, kid), allow_jwk=allow_jwk, allow_kid=allow_kid)
    if not service.consume_nonce(verified.protected.get("nonce")):
        raise AcmeProblem("badNonce", "The nonce is unknown, expired or already used; retry with a fresh one.")
    if post_as_get and verified.payload is not None:
        raise AcmeProblem("malformed", "This resource is fetched with POST-as-GET (empty payload).")
    return verified


@acme_bp.route("/directory", methods=["GET"])
def directory():
    return _json(service.directory(g.acme_ca))


@acme_bp.route("/new-nonce", methods=["HEAD", "GET"])
def new_nonce():
    return Response(status=200 if request.method == "HEAD" else 204)


@acme_bp.route("/new-account", methods=["POST"])
def new_account():
    ca = g.acme_ca
    verified = _verified(allow_jwk=True, allow_kid=False)
    account, created = service.new_account(ca, verified, service.acme_url("acme.new_account", ca.id))
    db.session.commit()
    return _json(service.account_dict(ca, account), 201 if created else 200,
                 Location=service.account_url(ca.id, account.id))


@acme_bp.route("/account/<int:account_id>", methods=["POST"])
def account(account_id):
    ca = g.acme_ca
    verified = _verified()
    if verified.account.id != account_id:
        raise AcmeProblem("unauthorized", "The account URL does not match the signing account.")
    if verified.payload:
        service.update_account(ca, verified.account, verified.payload)
        db.session.commit()
    return _json(service.account_dict(ca, verified.account), Location=service.account_url(ca.id, account_id))


@acme_bp.route("/account/<int:account_id>/orders", methods=["POST"])
def account_orders(account_id):
    ca = g.acme_ca
    verified = _verified(post_as_get=True)
    if verified.account.id != account_id:
        raise AcmeProblem("unauthorized", "The account URL does not match the signing account.")
    orders = verified.account.orders.order_by(db.desc("id")).limit(100).all()
    return _json({"orders": [service.acme_url("acme.order", ca.id, order_id=o.id) for o in orders]})


@acme_bp.route("/new-order", methods=["POST"])
def new_order():
    ca = g.acme_ca
    verified = _verified()
    order = service.new_order(ca, verified.account, verified.payload)
    db.session.commit()
    return _json(service.order_dict(ca, order), 201, Location=service.acme_url("acme.order", ca.id, order_id=order.id))


@acme_bp.route("/order/<int:order_id>", methods=["POST"])
def order(order_id):
    ca = g.acme_ca
    verified = _verified(post_as_get=True)
    row = service.load_order(ca, verified.account, order_id)
    db.session.commit()
    headers = {"Location": service.acme_url("acme.order", ca.id, order_id=row.id)}
    if row.status == "processing":
        headers["Retry-After"] = "5"
    return _json(service.order_dict(ca, row), **headers)


@acme_bp.route("/order/<int:order_id>/finalize", methods=["POST"])
def finalize(order_id):
    ca = g.acme_ca
    verified = _verified()
    row = service.load_order(ca, verified.account, order_id)
    row = service.finalize(ca, verified.account, row, verified.payload)
    return _json(service.order_dict(ca, row), Location=service.acme_url("acme.order", ca.id, order_id=row.id))


@acme_bp.route("/authz/<int:authz_id>", methods=["POST"])
def authorization(authz_id):
    ca = g.acme_ca
    verified = _verified()
    authz = service.load_authz(ca, verified.account, authz_id)
    if verified.payload and verified.payload.get("status") == "deactivated":
        service.deactivate_authz(authz)
    db.session.commit()
    return _json(service.authz_dict(ca, authz))


@acme_bp.route("/chall/<int:challenge_id>", methods=["POST"])
def challenge(challenge_id):
    ca = g.acme_ca
    verified = _verified()
    row = service.load_challenge(ca, verified.account, challenge_id)
    if verified.payload is not None:      # {} = "please validate"; POST-as-GET just reads
        row = service.respond_challenge(ca, verified.account, row)
    db.session.commit()
    authz_url = service.acme_url("acme.authorization", ca.id, authz_id=row.authorization_id)
    response = _json(service.challenge_dict(ca, row))
    response.headers.add("Link", f'<{authz_url}>;rel="up"')
    return response


@acme_bp.route("/cert/<int:cert_id>", methods=["POST"])
def certificate(cert_id):
    ca = g.acme_ca
    verified = _verified(post_as_get=True)
    cert = service.certificate_for(ca, verified.account, cert_id)
    return Response(service.certificate_chain_pem(cert), mimetype="application/pem-certificate-chain")


@acme_bp.route("/revoke-cert", methods=["POST"])
def revoke_cert():
    ca = g.acme_ca
    verified = _verified(allow_jwk=True)
    service.revoke(ca, verified, verified.payload)
    return Response(status=200)


@acme_bp.route("/key-change", methods=["POST"])
def key_change():
    ca = g.acme_ca
    verified = _verified()
    inner = verified.payload
    if not isinstance(inner, dict):
        raise AcmeProblem("malformed", "keyChange payload must be the inner JWS.")
    service.change_key(ca, verified.account, inner, service.acme_url("acme.key_change", ca.id))
    db.session.commit()
    return _json(service.account_dict(ca, verified.account))
