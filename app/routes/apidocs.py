"""F22 (3.8.0): the OpenAPI document and the Swagger UI page.

``GET /api/openapi.json`` — the OpenAPI 3.1 document for the caller's role.
``GET /api/docs``         — Swagger UI, loaded from jsdelivr with SRI pins.

Both require a signed-in account (session, Basic Auth or an API token with the
``read`` scope — the usual ``required_scope`` rule for a GET) and answer 404 for
everyone while ``API_DOCS_ENABLED`` is false, before any authentication, so a
disabled deployment looks like one without the feature (the ``/metrics``
pattern). Nothing here is exempt from the rate limiter, the forced password
change / 2FA gate or the token scope check, and neither route changes state.

The page never relaxes the Content-Security-Policy: Swagger UI's bundle and
stylesheet come from the one CDN origin the CSP already allows, pinned to an
exact version with sub-resource integrity, and the inline initialisation carries
the per-request nonce. "Try it out" never sends the browser session (the request
interceptor omits credentials), so the page can only act with the API credential
typed into *Authorize*.
"""
import json

from flask import Blueprint, Response, abort, current_app, make_response, render_template
from flask_login import current_user, login_required

from ..services.openapi import document_for

apidocs_bp = Blueprint("apidocs", __name__, url_prefix="/api")

# Swagger UI pin — the single place the version and the SRI hashes live. Bump
# procedure: fetch the two files for the new version from jsdelivr, compute
# `openssl dgst -sha384 -binary <file> | base64`, update the three constants,
# run the suite (tests/test_openapi.py checks the template uses exactly these).
SWAGGER_UI_VERSION = "5.33.2"
SWAGGER_UI_CSS_SRI = "sha384-Ov4/wv3j2bmct8cDc5X4ngJZohVPzEmc6uDPH8WeljUxO5vtoykvMEfbu9Vh6RaW"
SWAGGER_UI_JS_SRI = "sha384-gNnUp++d7WqR9OKX4OMoUmV2w0JxEs1uu6NPXgcynGClIX5DOu6ol4Lp+lINyZcJ"
SWAGGER_UI_CDN = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@"

TRY_IT_OUT_MODES = ("all", "read", "off")
_SUBMIT_METHODS = {
    "all": ["get", "put", "post", "delete", "options", "head", "patch", "trace"],
    "read": ["get"],
    "off": [],
}


def try_it_out_mode(config):
    """`API_DOCS_TRY_IT_OUT`, validated at startup by `_check_api_docs`."""
    return (config.get("API_DOCS_TRY_IT_OUT") or "all").lower()


@apidocs_bp.before_request
def _gate():
    # Before the view's @login_required, so "disabled" is a plain 404 for
    # everyone rather than a login redirect that reveals the feature exists.
    if not current_app.config.get("API_DOCS_ENABLED", True):
        abort(404)


@apidocs_bp.route("/openapi.json", methods=["GET"])
@login_required
def openapi_json():
    document = document_for(current_user)
    # Deterministic bytes (insertion order, no key sorting) and always JSON
    # regardless of the Accept header — this is a document, not a negotiated page.
    body = json.dumps(document, ensure_ascii=False, indent=2)
    response = Response(body, mimetype="application/json")
    response.headers["Cache-Control"] = "no-store"
    return response


@apidocs_bp.route("/docs", methods=["GET"])
@login_required
def docs():
    mode = try_it_out_mode(current_app.config)
    response = make_response(render_template(
        "apidocs/index.html",
        swagger_ui={"version": SWAGGER_UI_VERSION, "cdn": SWAGGER_UI_CDN,
                    "css_sri": SWAGGER_UI_CSS_SRI, "js_sri": SWAGGER_UI_JS_SRI},
        submit_methods=_SUBMIT_METHODS.get(mode, _SUBMIT_METHODS["all"]),
        try_it_out_mode=mode,
    ))
    response.headers["Cache-Control"] = "no-store"
    return response
