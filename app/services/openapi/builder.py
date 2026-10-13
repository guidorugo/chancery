"""Assembles the OpenAPI 3.1 document from ``app.url_map`` and the metadata in
``operations.py`` / ``schemas.py`` (F22, 3.8.0).

Static-document rule
--------------------
The document is a pure function of the code, the running version and a handful
of non-secret policy limits from the config. It never contains anything from the
database (no CA ids or names, no profile keys), from the request (no ``servers``
entry, no Host-derived URLs — paths are relative) or from a secret. That is what
makes it safe to hand to Swagger UI's renderer and to code generators, and it is
enforced by ``tests/test_openapi.py``.

Role filtering
--------------
``document_for(user)`` returns the administrator document or the requester
document (administrator-only operations and the schemas only they reference are
left out). Both are built once per process and cached on the app.

Fail closed
-----------
A ``url_map`` rule that is neither documented nor excluded is a test failure; at
run time it is logged and omitted, never a 500.
"""
import logging
import os
import re

from flask import current_app
from werkzeug.routing import IntegerConverter

from .. import api_token_service
from . import operations as ops
from . import schemas

logger = logging.getLogger(__name__)

OPENAPI_VERSION = "3.1.0"
SKIP_METHODS = {"HEAD", "OPTIONS"}
_RULE_PART = re.compile(r"<(?:[a-zA-Z_][a-zA-Z0-9_]*(?:\([^)]*\))?:)?([a-zA-Z_][a-zA-Z0-9_]*)>")
_SCHEMA_REF = re.compile(r"#/components/schemas/([A-Za-z0-9_]+)")
_RESPONSE_REF = re.compile(r"#/components/responses/([A-Za-z0-9_]+)")
_reported_missing = set()

DEFAULT_SECURITY = [{"basicAuth": []}, {"apiToken": []}]

SECURITY_SCHEMES = {
    "basicAuth": {
        "type": "http", "scheme": "basic",
        "description": "Account username and password (`curl -u user:pass`). Implies JSON responses. Refused "
                       "for an account with two-factor authentication (use an API token) and until a forced "
                       "first-login password change has been done in the browser. Every failed attempt counts "
                       "toward the account lockout (`LOGIN_LOCKOUT_THRESHOLD`).",
    },
    "apiToken": {
        "type": "http", "scheme": "bearer", "bearerFormat": "chy_api_<id>_<secret>",
        "description": "Scoped API token (Preferences → API Tokens, or `flask api-token create`). Each operation "
                       "names the scope it needs in `x-chancery-scope` (`read`, `issue`, `revoke`, `admin`; "
                       "`admin` implies the others). A token never exceeds its owner's role and must expire.",
    },
    "metricsToken": {
        "type": "http", "scheme": "bearer", "bearerFormat": "cmt_<secret>",
        "description": "Dedicated metrics token (`flask metrics-token create`), accepted only by `GET /metrics`.",
    },
}

INFO_DESCRIPTION = """Chancery is a web application whose data routes serve **JSON to API clients and HTML to
browsers** from the same URLs. This document describes the JSON contract plus the public, binary and
monitoring endpoints. Browser-only pages (login, 2FA, the HTML forms, the user-management console) are
not part of it — the README lists them.

### Authentication
* **API token** (recommended): `Authorization: Bearer chy_api_…` — scoped, expiring, revocable, works for
  accounts that use two-factor authentication. Each operation shows the scope it needs.
* **HTTP Basic**: `-u user:password` — refused for 2FA-enabled accounts; a wrong password counts toward the
  login lockout.
* A **browser session** can *read* through the API (send `Accept: application/json`), but its writes need the
  page's CSRF token, which this page never exposes — *Try it out* therefore always sends the credentials from
  **Authorize** and never your session cookie.

### Conventions
* Responses are JSON when you authenticate with a token or Basic Auth, or send `Accept: application/json`.
* Request bodies are **form-encoded** (`-d field=value`); the CA import is `multipart/form-data`. Checkbox-style
  fields take `on`; a few take `on|1|true|yes` (noted per field).
* Errors are `{"error": "…"}` with a 4xx/5xx status; downloads and public endpoints answer with bytes and plain-text 404s.
  Every endpoint may also answer `429` when the per-IP rate limit (`RATE_LIMIT_DEFAULT`) is exceeded.
* The list endpoints return a bare array, or the `{items, page, per_page, total, pages}` envelope when `page`
  or `per_page` is given (`per_page` ≤ 500).
* This document is filtered to **your role**; `x-chancery-role` and `x-chancery-scope` annotate every operation.
* Operations marked **returns private-key material** show the key in this page's response panel — use `curl`
  unless that is what you want.
* Limits that depend on this deployment's configuration are in `info.x-chancery-limits`.
"""


# --- public entry points ---------------------------------------------------------

def document_for(user):
    """The document for ``user``'s role (administrator or requester)."""
    return build("admin" if getattr(user, "is_admin", False) else "requester")


def build(role):
    """The cached document for ``role`` (``admin`` | ``requester``)."""
    assert role in ("admin", "requester"), role
    cache = current_app.extensions.setdefault("chancery_openapi", {})
    if role not in cache:
        cache[role] = _build(role)
    return cache[role]


def app_version():
    from ..._version import __version__
    return os.environ.get("APP_VERSION") or __version__


def openapi_path(rule_string):
    """``/ca/<int:ca_id>/alt/<int:alt_id>.crt`` → ``/ca/{ca_id}/alt/{alt_id}.crt``."""
    return _RULE_PART.sub(r"{\1}", rule_string)


def rule_keys(url_map):
    """Every ``endpoint:METHOD`` the document must account for."""
    keys = set()
    for rule in url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        for method in rule.methods - SKIP_METHODS:
            keys.add(f"{rule.endpoint}:{method}")
    return keys


# --- assembly ----------------------------------------------------------------------

def _build(role):
    paths = {}
    rules = sorted(current_app.url_map.iter_rules(), key=lambda r: (openapi_path(r.rule), r.endpoint))
    for rule in rules:
        if rule.endpoint == "static":
            continue
        for method in sorted(rule.methods - SKIP_METHODS):
            key = f"{rule.endpoint}:{method}"
            if key in ops.EXCLUDED:
                continue
            meta = ops.OPERATIONS.get(key)
            if meta is None:
                if current_app.testing:
                    raise LookupError(f"{key} is neither documented nor excluded in app/services/openapi/operations.py")
                if key not in _reported_missing:
                    _reported_missing.add(key)
                    logger.error("OpenAPI: %s is neither documented nor excluded; omitted", key)
                continue
            if meta["role"] == "admin" and role != "admin":
                continue
            path = openapi_path(rule.rule)
            paths.setdefault(path, {})[method.lower()] = _operation(rule, method, meta, role)

    document = {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": "Chancery API",
            "version": app_version(),
            "description": INFO_DESCRIPTION,
            "x-chancery-limits": _limits(),
        },
        "tags": [{"name": name, "description": description} for name, description in ops.TAGS],
        "paths": paths,
        "components": {
            "schemas": dict(schemas.SCHEMAS),
            "responses": {name: _component_response(*spec) for name, spec in ops.COMPONENT_RESPONSES.items()},
            "securitySchemes": dict(SECURITY_SCHEMES),
        },
        "security": [dict(s) for s in DEFAULT_SECURITY],
    }
    _prune(document)
    return document


def _limits():
    cfg = current_app.config
    return {
        "min_rsa_key_size": int(cfg.get("MIN_RSA_KEY_SIZE", 2048)),
        "max_rsa_key_size": int(cfg.get("MAX_RSA_KEY_SIZE", 8192)),
        "max_cert_validity_days": int(cfg.get("MAX_CERT_VALIDITY_DAYS", 1825)),
        "max_intermediate_validity_days": int(cfg.get("MAX_INTERMEDIATE_VALIDITY_DAYS", 3650)),
        "max_ca_validity_days": int(cfg.get("MAX_CA_VALIDITY_DAYS", 7300)),
        "api_token_max_days": int(cfg.get("API_TOKEN_MAX_DAYS", 365)),
        "cert_expiry_warning_days": int(cfg.get("CERT_EXPIRY_WARNING_DAYS", 30)),
        "max_per_page": 500,
    }


def _resolve(value):
    if isinstance(value, ops.Cfg):
        return int(current_app.config.get(value.key, value.default))
    return value


def _operation(rule, method, meta, role):
    scope = api_token_service.required_scope(method, rule.endpoint)
    responses = dict(meta["role_responses"].get(role, meta["responses"]))
    if meta["role"] != "public":
        # Every authenticated operation can refuse the credential (401) or the
        # role / token scope / ownership (403) before the view runs.
        responses.setdefault(401, "Unauthorized")
        responses.setdefault(403, "Forbidden")
    operation = {
        "operationId": f"{rule.endpoint.replace('.', '_')}_{method.lower()}",
        "tags": [meta["tag"]],
        "summary": meta["summary"],
        "description": _description(meta, scope),
        "x-chancery-role": meta["role"],
    }
    if scope is not None:
        operation["x-chancery-scope"] = scope
    parameters = _path_parameters(rule) + [_query_parameter(q) for q in meta["query"]]
    if parameters:
        operation["parameters"] = parameters
    if meta["body"] is not None:
        operation["requestBody"] = _request_body(meta)
    operation["responses"] = {str(status): _response(spec) for status, spec in sorted(responses.items())}
    if meta["security"] is not None:
        operation["security"] = meta["security"]
    elif meta["role"] == "public":
        operation["security"] = []
    else:
        operation["security"] = [dict(s) for s in DEFAULT_SECURITY]
    if meta["key_material"]:
        operation["x-chancery-key-material"] = True
    return operation


def _description(meta, scope):
    text = meta["description"].strip()
    if meta["role"] == "public" and meta["security"] is None:
        access = "*No authentication.*"
    elif meta["role"] == "admin":
        access = f"*Role:* administrator · *Token scope:* `{scope}`."
    elif meta["role"] == "any":
        access = f"*Role:* any signed-in account · *Token scope:* `{scope}`."
    else:
        access = "*Authentication:* see the security requirement."
    return f"{text}\n\n{access}" if text else access


def _path_parameters(rule):
    parameters = []
    for name in _RULE_PART.findall(rule.rule):
        converter = rule._converters.get(name)
        schema = {"type": "integer"} if isinstance(converter, IntegerConverter) else {"type": "string"}
        try:
            description = ops.PATH_PARAMS[name]
        except KeyError:
            if current_app.testing:
                raise
            description = name
        parameters.append({"name": name, "in": "path", "required": True, "description": description,
                           "schema": schema})
    return parameters


def _query_parameter(q):
    schema = {"type": q["type"]}
    for key in ("enum", "default", "minimum", "maximum"):
        if q.get(key) is not None:
            schema[key] = _resolve(q[key])
    return {"name": q["name"], "in": "query", "required": False, "description": q["description"], "schema": schema}


def _field_schema(f):
    if f["type"] == "array":
        schema = {"type": "array", "items": {"type": f["items"] or "string"}}
    else:
        schema = {"type": f["type"]}
    schema["description"] = f["description"]
    for key in ("enum", "default", "format", "minimum", "maximum"):
        if f.get(key) is not None:
            schema[key] = _resolve(f[key])
    return schema


def _request_body(meta):
    if meta["body_type"] not in (ops.FORM, ops.MULTIPART):
        return {"required": True, "content": {meta["body_type"]: {"schema": {"type": "string", "format": "binary"}}}}
    properties = {}
    required = []
    for f in meta["body"]:
        properties[f["name"]] = _field_schema(f)
        if f["required"]:
            required.append(f["name"])
    schema = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return {"required": bool(required), "content": {meta["body_type"]: {"schema": schema}}}


def _schema_ref(name):
    return {"$ref": f"#/components/schemas/{name}"}


def _content(content):
    """Normalise a response's content spec into an OpenAPI ``content`` map."""
    if isinstance(content, str):
        return {"application/json": {"schema": _schema_ref(content)}}
    if isinstance(content, dict) and content and all("/" in key for key in content):
        media = {}
        for media_type, schema in content.items():
            if schema is None:
                media[media_type] = {}
            elif isinstance(schema, str):
                media[media_type] = {"schema": _schema_ref(schema)}
            else:
                media[media_type] = {"schema": schema}
        return media
    return {"application/json": {"schema": content}}


def _response(spec):
    if isinstance(spec, str):
        return {"$ref": f"#/components/responses/{spec}"}
    description, content = spec
    response = {"description": description}
    if content is not None:
        response["content"] = _content(content)
    return response


def _component_response(description, schema_name, media_type="application/json"):
    response = {"description": description}
    if schema_name is not None:
        response["content"] = {media_type: {"schema": _schema_ref(schema_name)}}
    elif media_type != "application/json":
        response["content"] = {media_type: {"schema": {"type": "string"}}}
    return response


def _prune(document):
    """Drop tags, component responses and schemas nothing in ``paths`` refers to
    (transitively), so a requester's document carries no administrator-only shapes."""
    import json
    paths_json = json.dumps(document["paths"])
    used_tags = {tag for item in document["paths"].values() for operation in item.values() for tag in operation["tags"]}
    document["tags"] = [tag for tag in document["tags"] if tag["name"] in used_tags]
    used_responses = set(_RESPONSE_REF.findall(paths_json))
    document["components"]["responses"] = {
        name: spec for name, spec in document["components"]["responses"].items() if name in used_responses}
    reachable = set(_SCHEMA_REF.findall(paths_json + json.dumps(document["components"]["responses"])))
    all_schemas = document["components"]["schemas"]
    frontier = set(reachable)
    while frontier:
        name = frontier.pop()
        for ref in _SCHEMA_REF.findall(json.dumps(all_schemas.get(name, {}))):
            if ref not in reachable:
                reachable.add(ref)
                frontier.add(ref)
    document["components"]["schemas"] = {name: schema for name, schema in all_schemas.items() if name in reachable}
