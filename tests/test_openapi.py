"""F22 (3.8.0): the OpenAPI document and the Swagger UI page.

Four families of checks:
* access — login required, 404 when disabled, role filtering, token scope, the
  password-change gate, rate limiting (in test_rate_limiting);
* the static-document rule — nothing from the database or the request ever
  reaches the document, no absolute URLs, deterministic bytes;
* drift gates — every url_map rule is documented or excluded, the declared role
  matches the view's decorator, every documented field name is a literal in the
  route module, every form/query literal a documented view reads is documented,
  every component schema matches the live serializer output and every exercised
  response matches its documented schema / media type;
* the page — CSP unchanged (nonce, no unsafe-eval), SRI pins equal to the one
  constant, the hardening switches in the init script, no session credentials
  for "Try it out", `no-store`.
"""
import base64
import inspect
import json
import pathlib
import re
import sys

import pytest

from app import create_app
from app.extensions import db as _db
from app.models.user import User
from app.routes import apidocs
from app.services import api_token_service
from app.services.openapi import app_version, build, openapi_path, rule_keys
from app.services.openapi import operations as ops
from app.services.openapi import schemas as sch
from tests.conftest import TestConfig

JSON = {"Accept": "application/json"}
ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = "/api/openapi.json"
DOCS = "/api/docs"


def _basic(username, password):
    return {"Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()}


def _validate(spec, schema, instance):
    """Validate `instance` against `schema` (which may `$ref` the document's components)."""
    jsonschema = pytest.importorskip("jsonschema")
    root = dict(schema)
    root["components"] = spec["components"]
    root.setdefault("$schema", "https://json-schema.org/draft/2020-12/schema")
    jsonschema.Draft202012Validator(root).validate(instance)


def _schema_ref(name):
    return {"$ref": f"#/components/schemas/{name}"}


@pytest.fixture
def requester_client(app, csr_requester):
    """A second client: `auth_admin` and `requester_client` share one test
    client, so a test that needs both roles at once logs the requester in here."""
    c = app.test_client()
    c.post("/auth/login", data={"username": "testrequester", "password": "requesterpass"})
    return c


@pytest.fixture
def admin_spec(auth_admin):
    r = auth_admin.get(SPEC)
    assert r.status_code == 200 and r.content_type == "application/json"
    return r.get_json()


@pytest.fixture
def requester_spec(requester_client):
    r = requester_client.get(SPEC)
    assert r.status_code == 200
    return r.get_json()


def _ops(spec):
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            yield path, method, operation


# --- access -----------------------------------------------------------------------------

class TestAccess:
    def test_anonymous_browser_is_sent_to_login(self, client):
        for path in (SPEC, DOCS):
            r = client.get(path)
            assert r.status_code == 302 and "/auth/login" in r.headers["Location"]

    def test_anonymous_json_client_gets_401(self, client):
        for path in (SPEC, DOCS):
            r = client.get(path, headers=JSON)
            assert r.status_code == 401 and r.get_json() == {"error": "Authentication required."}

    def test_disabled_is_404_for_everyone(self):
        class Disabled(TestConfig):
            API_DOCS_ENABLED = False
        app = create_app(Disabled)
        with app.app_context():
            _db.create_all()
            user = User(username="offadmin", role="admin")
            user.set_password("adminpass-off")
            _db.session.add(user)
            _db.session.commit()
            c = app.test_client()
            assert c.get(SPEC).status_code == 404            # anonymous: no login redirect
            assert c.get(SPEC, headers=JSON).status_code == 404
            c.post("/auth/login", data={"username": "offadmin", "password": "adminpass-off"})
            assert c.get(SPEC).status_code == 404 and c.get(DOCS).status_code == 404
            assert b">API Reference</a>" not in c.get("/").data
            _db.session.remove()
            _db.drop_all()

    def test_sidebar_links_the_page_when_enabled(self, auth_admin, requester_client):
        assert b">API Reference</a>" in auth_admin.get("/").data
        assert b">API Reference</a>" in requester_client.get("/").data

    def test_session_basic_and_token_can_read_the_document(self, client, admin_user, auth_admin, app):
        assert auth_admin.get(SPEC).status_code == 200
        r = client.get(SPEC, headers=_basic("testadmin", "adminpass"))
        assert r.status_code == 200 and r.content_type == "application/json"
        plaintext, _ = api_token_service.create(admin_user, "docs-read", ["read"], 5)
        _db.session.commit()
        r = client.get(SPEC, headers={"Authorization": f"Bearer {plaintext}"})
        assert r.status_code == 200 and r.get_json()["openapi"] == "3.1.0"

    def test_token_without_read_scope_is_refused(self, client, admin_user):
        plaintext, _ = api_token_service.create(admin_user, "docs-issue", ["issue"], 5)
        _db.session.commit()
        r = client.get(SPEC, headers={"Authorization": f"Bearer {plaintext}"})
        assert r.status_code == 403 and "lacks the 'read' scope" in r.get_json()["error"]

    def test_metrics_token_is_refused(self, client):
        r = client.get(SPEC, headers={"Authorization": "Bearer cmt_not_an_api_token"})
        assert r.status_code == 401

    def test_password_change_gate_applies(self, client, admin_user):
        admin_user.must_change_password = True
        _db.session.commit()
        client.post("/auth/login", data={"username": "testadmin", "password": "adminpass"})
        r = client.get(DOCS)
        assert r.status_code == 302 and "/auth/change-password" in r.headers["Location"]
        r = client.get(SPEC, headers=_basic("testadmin", "adminpass"))
        assert r.status_code == 403                          # AUTH-3 gate for Basic Auth too

    def test_requester_document_omits_admin_operations(self, requester_spec, admin_spec):
        roles = {op["x-chancery-role"] for _, _, op in _ops(requester_spec)}
        assert roles == {"any", "public"}
        assert "/users/" not in requester_spec["paths"] and "/ca/" not in requester_spec["paths"]
        assert "/csr/" in requester_spec["paths"] and "/certificates/" in requester_spec["paths"]
        assert "User" not in requester_spec["components"]["schemas"]
        assert "CertificateAuthorityDetail" not in requester_spec["components"]["schemas"]
        assert "/users/" in admin_spec["paths"] and "/ca/" in admin_spec["paths"]
        assert "admin" in {op["x-chancery-role"] for _, _, op in _ops(admin_spec)}
        # the requester's dashboard answer differs from the administrator's
        assert requester_spec["paths"]["/"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] == _schema_ref("DashboardRequester")
        assert admin_spec["paths"]["/"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] == _schema_ref("DashboardAdmin")

    def test_version_only_to_authenticated_callers(self, admin_spec, client):
        assert admin_spec["info"]["version"] == app_version()
        assert client.get("/health").get_json() == {"status": "ok", "checks": {"database": "ok"}}

    def test_no_store(self, auth_admin):
        for path in (SPEC, DOCS):
            assert auth_admin.get(path).headers["Cache-Control"] == "no-store"


# --- the static-document rule ----------------------------------------------------------------

class TestStaticDocument:
    MARKER = "ZZMARKERZZ"

    def test_nothing_from_the_database_reaches_the_document(self, auth_admin, requester_client):
        m = self.MARKER
        assert auth_admin.post("/ca/create", headers=JSON, data={
            "mode": "generate", "name": f"{m}-ca", "cn": f"{m} Root", "key_type": "EC", "key_size": "256",
            "validity_days": "365", "ca_type": "root", "nc_permitted": f"DNS:{m.lower()}.example",
            "certificate_policies": "1.3.6.1.4.1.99999.1"}).status_code == 201
        assert auth_admin.post("/users/profiles/new", headers=JSON, data={
            "name": f"{m} profile", "description": f"{m} description", "enabled": "on",
            "default_validity_days": "90", "ku_digital_signature": "on"}).status_code == 201
        assert auth_admin.post("/users/create", data={"username": f"{m.lower()}user", "password": "x" * 16,
                                                      "role": "csr_requester"}).status_code == 302
        assert auth_admin.post("/users/api-tokens", headers=JSON, data={
            "name": f"{m}-token", "expires_in_days": "5", "scopes": "read"}).status_code == 201
        for client in (auth_admin, requester_client):
            body = client.get(SPEC).get_data(as_text=True)
            assert m.lower() not in body.lower()

    def test_host_header_is_not_reflected_and_no_servers_entry(self, client, admin_user):
        # Basic Auth rather than the session: the hostile Host would not carry the
        # localhost session cookie, and the request must still be authenticated.
        r = client.get(SPEC, base_url="http://evil.example", headers=_basic("testadmin", "adminpass"))
        assert r.status_code == 200
        body = r.get_data(as_text=True)
        assert "evil.example" not in body
        assert "servers" not in r.get_json()
        assert "://" not in body                       # relative paths only, no URLs at all

    def test_deterministic_bytes(self, auth_admin):
        assert auth_admin.get(SPEC).data == auth_admin.get(SPEC).data

    def test_cached_per_role_and_per_app(self, app):
        with app.app_context():
            assert build("admin") is build("admin")
            assert build("admin") is not build("requester")


# --- validity -------------------------------------------------------------------------------------

class TestValidity:
    def test_openapi_validator_accepts_both_documents(self, admin_spec, requester_spec):
        validator = pytest.importorskip("openapi_spec_validator")
        validator.validate(admin_spec)
        validator.validate(requester_spec)

    def test_structure(self, admin_spec):
        spec = admin_spec
        assert spec["openapi"] == "3.1.0" and spec["info"]["title"] == "Chancery API"
        assert set(spec["components"]["securitySchemes"]) == {"basicAuth", "apiToken", "metricsToken"}
        tag_names = [t["name"] for t in spec["tags"]]
        operation_ids = []
        for path, method, op in _ops(spec):
            assert op["summary"] and op["tags"] and op["responses"], (path, method)
            assert op["tags"][0] in tag_names, (path, method)
            operation_ids.append(op["operationId"])
            declared = {p["name"] for p in op.get("parameters", []) if p["in"] == "path"}
            assert declared == set(re.findall(r"{([^}]+)}", path)), (path, method)
            assert op["x-chancery-role"] in ("admin", "any", "public")
            if op["x-chancery-role"] == "public" and "metricsToken" not in json.dumps(op.get("security")):
                assert op["security"] == []
            else:
                assert op["security"], (path, method)
        assert len(operation_ids) == len(set(operation_ids))

    def test_every_ref_resolves(self, admin_spec, requester_spec):
        for spec in (admin_spec, requester_spec):
            body = json.dumps(spec)
            for name in set(re.findall(r"#/components/schemas/([A-Za-z0-9_]+)", body)):
                assert name in spec["components"]["schemas"], name
            for name in set(re.findall(r"#/components/responses/([A-Za-z0-9_]+)", body)):
                assert name in spec["components"]["responses"], name
        # nothing in schemas.py is dead: every component is used by one of the two documents
        used = set(admin_spec["components"]["schemas"]) | set(requester_spec["components"]["schemas"])
        assert used == set(sch.SCHEMAS)

    def test_limits_come_from_config(self, admin_spec, app):
        limits = admin_spec["info"]["x-chancery-limits"]
        assert limits["max_cert_validity_days"] == app.config["MAX_CERT_VALIDITY_DAYS"]
        assert limits["api_token_max_days"] == app.config["API_TOKEN_MAX_DAYS"]
        renew = admin_spec["paths"]["/certificates/{cert_id}/renew"]["post"]
        field = renew["requestBody"]["content"][ops.FORM]["schema"]["properties"]["validity_days"]
        assert field["maximum"] == app.config["MAX_CERT_VALIDITY_DAYS"]


# --- drift gates ---------------------------------------------------------------------------------------

_FORM_LITERAL = re.compile(r'(?:form|values|files|args)\.get(?:list)?\(\s*"([A-Za-z_][A-Za-z0-9_]*)"')
_MEMBERSHIP_LITERAL = re.compile(r'"([A-Za-z_][A-Za-z0-9_]*)"\s+in\s+request\.(?:form|values|files|args)')


def _view_source(app, endpoint):
    return inspect.getsource(inspect.unwrap(app.view_functions[endpoint]))


def _module_source(app, endpoint):
    return inspect.getsource(sys.modules[app.view_functions[endpoint].__module__])


class TestDriftGates:
    def test_every_rule_is_documented_or_excluded(self, app):
        keys = rule_keys(app.url_map)
        documented, excluded = set(ops.OPERATIONS), set(ops.EXCLUDED)
        assert not (documented & excluded)
        assert keys - documented - excluded == set(), "undocumented endpoints"
        assert (documented | excluded) - keys == set(), "stale metadata"
        assert all(reason for reason in ops.EXCLUDED.values())

    def test_role_matches_the_views_decorator(self, app):
        with app.app_context():
            for key, meta in ops.OPERATIONS.items():
                endpoint = key.split(":")[0]
                header = _view_source(app, endpoint).split("\ndef ", 1)[0]
                if "@admin_required" in header:
                    expected = "admin"
                elif "@login_required" in header or "@role_required" in header:
                    expected = "any"
                else:
                    expected = "public"
                assert meta["role"] == expected, (key, meta["role"], expected)

    def test_every_path_parameter_is_described(self, app):
        names = set()
        for rule in app.url_map.iter_rules():
            if rule.endpoint != "static":
                names |= set(rule.arguments)
        assert names <= set(ops.PATH_PARAMS), names - set(ops.PATH_PARAMS)

    def test_documented_names_are_literals_in_the_route_module(self, app):
        with app.app_context():
            for key, meta in ops.OPERATIONS.items():
                source = _module_source(app, key.split(":")[0])
                names = [f["name"] for f in (meta["body"] or []) if f["literal"]]
                names += [q["name"] for q in meta["query"] if q["literal"]]
                missing = [n for n in names if f'"{n}"' not in source]
                assert not missing, (key, missing)

    def test_every_literal_a_documented_view_reads_is_documented(self, app):
        by_endpoint = {}
        for key, meta in ops.OPERATIONS.items():
            endpoint = key.split(":")[0]
            names = by_endpoint.setdefault(endpoint, set())
            names |= {f["name"] for f in (meta["body"] or [])}
            names |= {q["name"] for q in meta["query"]}
            names |= set(ops.UNDOCUMENTED_FIELDS.get(endpoint, {}))
        with app.app_context():
            for endpoint, names in by_endpoint.items():
                source = _view_source(app, endpoint)
                read = set(_FORM_LITERAL.findall(source)) | set(_MEMBERSHIP_LITERAL.findall(source))
                assert read <= names, (endpoint, read - names)

    def test_scope_annotation_equals_enforcement(self, admin_spec, app):
        for path, method, op in _ops(admin_spec):
            endpoint = op["operationId"].rsplit("_", 1)[0].replace("_", ".", 1)
            assert op.get("x-chancery-scope") == api_token_service.required_scope(method.upper(), endpoint), (path, method)


# --- schema <-> reality -------------------------------------------------------------------------------

@pytest.fixture
def world(auth_admin, csr_requester):
    """Objects of every documented kind, created through the real endpoints."""
    def post(path, data, status=201):
        r = auth_admin.post(path, headers=JSON, data=data)
        assert r.status_code == status, (path, r.status_code, r.get_data(as_text=True)[:300])
        return r.get_json()

    ca = post("/ca/create", {"mode": "generate", "name": "OpenAPI Root", "cn": "OpenAPI Root", "key_type": "EC",
                             "key_size": "256", "validity_days": "365", "ca_type": "root"})
    cert = post("/certificates/create", {"cn": "api.example.test", "ca_id": ca["id"], "key_type": "EC",
                                         "key_size": "256", "validity_days": "30", "san": "DNS:api.example.test"})
    renewed = post(f"/certificates/{cert['id']}/renew", {"revoke_old": "on"})
    csr = post("/csr/create", {"mode": "generate", "cn": "csr.example.test", "key_type": "EC", "key_size": "256"})
    signed = post(f"/csr/{csr['id']}/sign", {"ca_id": ca["id"], "validity_days": "30"})
    pending_csr = post("/csr/create", {"mode": "generate", "cn": "pending.example.test", "key_type": "EC", "key_size": "256"})
    reissued = post(f"/ca/{ca['id']}/reissue", {})
    profile = post("/users/profiles/new", {"name": "OpenAPI Profile", "enabled": "on", "include_ocsp_aia": "on",
                                           "default_validity_days": "90", "ku_digital_signature": "on",
                                           "eku_serverAuth": "on", "kt_EC": "on", "san_dns": "on"})
    token = post("/users/api-tokens", {"name": "openapi-world", "expires_in_days": "5", "scopes": "read"})
    eab = post(f"/ca/{ca['id']}/acme/eab", {"name": "lego"})
    return {"ca": ca, "cert": cert, "renewed": renewed, "csr": csr, "signed": signed, "pending_csr": pending_csr,
            "reissued": reissued, "profile": profile, "token": token, "eab": eab,
            "alt": reissued["alternate_certificates"][0], "requester": csr_requester}


def _operation_for(app, spec, method, path):
    adapter = app.url_map.bind("localhost")
    endpoint, _ = adapter.match(path.split("?")[0], method=method)
    rule = next(r for r in app.url_map.iter_rules() if r.endpoint == endpoint and method in r.methods)
    return spec["paths"][openapi_path(rule.rule)][method.lower()]


def _documented_response(spec, operation, status):
    response = operation["responses"].get(str(status))
    assert response is not None, (operation["operationId"], status, "undocumented status")
    if "$ref" in response:
        response = spec["components"]["responses"][response["$ref"].rsplit("/", 1)[1]]
    return response


def _check_contract(app, spec, client, method, path, data, status):
    r = client.open(path, method=method, headers=JSON, data=data)
    assert r.status_code == status, (method, path, r.status_code, r.get_data(as_text=True)[:300])
    operation = _operation_for(app, spec, method, path)
    response = _documented_response(spec, operation, status)
    content = response.get("content")
    if content is None:
        assert not r.data or status in (302,), (method, path)
        return r
    media = r.content_type.split(";")[0]
    assert media in content, (method, path, media, list(content))
    if media in ("application/json", "application/problem+json") and "schema" in content[media]:
        _validate(spec, content[media]["schema"], r.get_json())
    return r


class TestSchemasMatchReality:
    def test_serializers(self, app, world, admin_spec):
        from app.models.ca import CertificateAuthority
        from app.models.certificate import Certificate
        from app.models.csr import CertificateSigningRequest
        from app.models.audit_log import AuditLog
        from app.models.certificate_profile import CertificateProfile
        from app.models.api_token import ApiToken
        from app.models.ca_certificate import CaCertificate
        from app.models.acme import AcmeEabKey
        with app.app_context():
            objects = {
                "ca": _db.session.get(CertificateAuthority, world["ca"]["id"]),
                "certificate": _db.session.get(Certificate, world["renewed"]["id"]),
                "csr": _db.session.get(CertificateSigningRequest, world["csr"]["id"]),
                "user": _db.session.get(User, world["requester"].id),
                "api_token": _db.session.get(ApiToken, world["token"]["id"]),
                "profile": _db.session.get(CertificateProfile, world["profile"]["id"]),
                "audit": AuditLog.query.order_by(AuditLog.id.desc()).first(),
                "ca_certificate": _db.session.get(CaCertificate, world["alt"]["id"]),
                "eab_key": _db.session.get(AcmeEabKey, world["eab"]["id"]),
            }
            for schema_name, (kind, kwargs) in sch.SERIALIZER_SCHEMAS.items():
                payload = json.loads(json.dumps(objects[kind].to_dict(**kwargs)))
                _validate(admin_spec, _schema_ref(schema_name), payload)
            # the predecessor carries the renewal link and the revocation
            old = _db.session.get(Certificate, world["cert"]["id"]).to_dict(detail=True)
            assert old["superseded_by_id"] == world["renewed"]["id"] and old["is_revoked"]
            _validate(admin_spec, _schema_ref("CertificateDetail"), json.loads(json.dumps(old)))

    def test_creation_payloads(self, world, admin_spec):
        _validate(admin_spec, _schema_ref("CertificateAuthorityDetail"), world["ca"])
        _validate(admin_spec, _schema_ref("CertificateDetail"), world["cert"])
        _validate(admin_spec, _schema_ref("CertificateRenewed"), world["renewed"])
        assert world["renewed"]["old_id"] == world["cert"]["id"]
        _validate(admin_spec, _schema_ref("CsrCreated"), world["csr"])
        assert world["csr"]["private_key_pem"].startswith("-----BEGIN PRIVATE KEY-----")
        _validate(admin_spec, _schema_ref("CertificateDetail"), world["signed"])
        _validate(admin_spec, _schema_ref("CertificateAuthorityResult"), world["reissued"])
        _validate(admin_spec, _schema_ref("CertificateProfile"), world["profile"])
        _validate(admin_spec, _schema_ref("ApiTokenCreated"), world["token"])
        _validate(admin_spec, _schema_ref("AcmeEabKeyCreated"), world["eab"])

    def test_exercised_responses_match_the_document(self, app, world, admin_spec, auth_admin, requester_client):
        ca, cert, signed, csr, pending = (world["ca"]["id"], world["cert"]["id"], world["signed"]["id"],
                                          world["csr"]["id"], world["pending_csr"]["id"])
        alt, profile, token, eab, requester = (world["alt"]["id"], world["profile"]["id"], world["token"]["id"],
                                               world["eab"]["id"], world["requester"].id)
        calls = [
            ("GET", "/", None, 200),
            ("GET", "/ca/", None, 200),
            ("GET", "/ca/?page=1&per_page=5", None, 200),
            ("GET", "/ca/?status=bogus", None, 400),
            ("GET", f"/ca/{ca}", None, 200),
            ("GET", "/ca/999999", None, 404),
            ("POST", "/ca/detect-parent", {"cert_pem": ""}, 200),
            ("POST", "/ca/detect-parent", {"cert_pem": world["ca"]["certificate_pem"]}, 200),
            ("POST", f"/ca/{ca}/crl", {}, 200),
            ("POST", f"/ca/{ca}/profiles", {}, 200),
            ("POST", f"/ca/{ca}/profiles", {"restrict_profiles": "on"}, 400),
            ("POST", f"/ca/{ca}/approve", {}, 409),
            ("POST", f"/ca/{ca}/acme", {"acme_enabled": "on", "acme_profile": "custom"}, 200),
            ("POST", f"/ca/{ca}/acme/eab/{eab}/revoke", {}, 200),
            ("POST", f"/ca/{ca}/cross-sign", {"issuer_ca_id": ca}, 400),
            ("POST", f"/ca/{ca}/certificates/import", {"cert_pem": "not a pem"}, 400),
            ("POST", f"/ca/{ca}/certificates/{alt}/approve", {}, 409),
            ("GET", f"/ca/{ca}/download?format=pem", None, 200),
            ("GET", f"/ca/{ca}/download?format=chain", None, 200),
            ("POST", f"/ca/{ca}/download", {"format": "key"}, 200),
            ("POST", f"/ca/{ca}/download", {"format": "pkcs12", "password": "export-pw"}, 200),
            ("GET", "/certificates/", None, 200),
            ("GET", "/certificates/?status=active&per_page=2", None, 200),
            ("GET", "/certificates/?status=bogus", None, 400),
            ("GET", f"/certificates/{cert}", None, 200),
            ("GET", "/certificates/999999", None, 404),
            ("POST", "/certificates/create", {"cn": "", "ca_id": ca}, 400),
            ("POST", f"/certificates/{cert}/revoke", {}, 409),
            ("POST", f"/certificates/{signed}/renew", {}, 201),
            ("POST", f"/certificates/{signed}/renew", {}, 409),
            ("POST", f"/certificates/{signed}/revoke", {"reason": "superseded"}, 200),
            ("POST", f"/certificates/{signed}/revoke", {"reason": "bogus"}, 400),
            ("GET", f"/certificates/{cert}/download?format=pem", None, 200),
            ("GET", f"/certificates/{cert}/download?format=der", None, 200),
            ("GET", f"/certificates/{cert}/download?format=fullchain", None, 200),
            ("GET", f"/certificates/{cert}/download?format=chain&via=999999", None, 404),
            ("POST", f"/certificates/{cert}/download", {"format": "pkcs12", "password": "pw"}, 200),
            ("POST", f"/certificates/{cert}/download-key", {}, 200),
            ("GET", "/csr/", None, 200),
            ("GET", "/csr/?status=pending&page=1", None, 200),
            ("GET", f"/csr/{csr}", None, 200),
            ("POST", f"/csr/{csr}/reject", {}, 409),
            ("POST", f"/csr/{csr}/sign", {"ca_id": ca}, 409),
            ("POST", f"/csr/{pending}/sign", {"ca_id": "x"}, 400),
            ("POST", f"/csr/{pending}/reject", {}, 200),
            ("POST", "/csr/create", {"mode": "upload", "csr_pem": ""}, 400),
            ("GET", "/users/", None, 200),
            ("POST", f"/users/{requester}/approve", {}, 409),
            ("POST", f"/users/{requester}/reset-2fa", {}, 409),
            ("GET", "/users/profiles", None, 200),
            ("POST", "/users/profiles/new", {"name": ""}, 400),
            ("POST", f"/users/profiles/{profile}/edit", {"name": "OpenAPI Profile 2", "enabled": "on",
                                                        "default_validity_days": "90",
                                                        "ku_digital_signature": "on"}, 200),
            ("POST", f"/users/profiles/{profile}/toggle", {}, 200),
            ("POST", f"/users/profiles/{profile}/delete", {}, 200),
            ("GET", "/users/audit-log?per_page=5", None, 200),
            ("GET", "/users/audit-log?from=nope", None, 400),
            ("GET", "/users/audit-log/export?format=json", None, 200),
            ("GET", "/users/audit-log/export?format=csv", None, 200),
            ("GET", "/users/audit-log/export?format=bogus", None, 400),
            ("GET", "/users/api-tokens", None, 200),
            ("POST", "/users/api-tokens", {"name": "", "scopes": "read"}, 400),
            ("POST", f"/users/api-tokens/{token}/revoke", {}, 200),
            ("GET", "/health", None, 200),
            ("GET", f"/public/ca/{ca}.crt", None, 200),
            ("GET", f"/public/ca/{ca}/alt/{alt}.crt", None, 200),
            ("GET", f"/public/crl/{ca}.crl", None, 200),
            ("GET", f"/public/crl/{ca}.pem", None, 200),
            ("GET", "/public/ca/999999.crt", None, 404),
            ("GET", f"/acme/{ca}/directory", None, 404),
            ("GET", SPEC, None, 200),
            ("POST", f"/ca/{ca}/certificates/{alt}/delete", {}, 200),
            ("POST", f"/ca/{ca}/revoke", {"reason": "cessation_of_operation"}, 200),
            ("POST", f"/ca/{ca}/revoke", {"reason": "cessation_of_operation"}, 409),
        ]
        for method, path, data, status in calls:
            _check_contract(app, admin_spec, auth_admin, method, path, data, status)
        # the requester's view of the same world
        requester_spec = requester_client.get(SPEC).get_json()
        for method, path, data, status in [
            ("GET", "/", None, 200),
            ("GET", "/csr/", None, 200),
            ("GET", "/certificates/", None, 200),
            ("GET", "/users/api-tokens", None, 200),
        ]:
            _check_contract(app, requester_spec, requester_client, method, path, data, status)
        r = requester_client.get(f"/certificates/{cert}", headers=JSON)
        assert r.status_code == 403
        _validate(admin_spec, _schema_ref("Error"), r.get_json())

    def test_requester_dashboard_shape(self, requester_client, requester_spec):
        r = requester_client.get("/", headers=JSON)
        _validate(requester_spec, _schema_ref("DashboardRequester"), r.get_json())


# --- the page -----------------------------------------------------------------------------------------------

def _csp(resp):
    return re.sub(r"'nonce-[^']+'", "'nonce-X'", resp.headers["Content-Security-Policy"])


class TestPage:
    def test_csp_is_unchanged_and_nonce_covers_the_init_script(self, auth_admin):
        page = auth_admin.get(DOCS)
        assert page.status_code == 200
        assert _csp(page) == _csp(auth_admin.get("/"))
        assert "'unsafe-eval'" not in page.headers["Content-Security-Policy"]
        nonce = re.search(r"'nonce-([^']+)'", page.headers["Content-Security-Policy"]).group(1)
        html = page.get_data(as_text=True)
        inline_scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", html)
        assert inline_scripts and all(f'nonce="{nonce}"' in tag for tag in inline_scripts)
        assert "unsafe-eval" not in html

    def test_swagger_assets_are_pinned_with_sri_from_the_constants(self, auth_admin):
        html = auth_admin.get(DOCS).get_data(as_text=True)
        css = re.search(r'<link href="(https://[^"]+swagger-ui\.css)"[^>]*>', html)
        js = re.search(r'<script src="(https://[^"]+swagger-ui-bundle\.js)"[^>]*></script>', html)
        assert css and js
        for tag, sri in ((css.group(0), apidocs.SWAGGER_UI_CSS_SRI), (js.group(0), apidocs.SWAGGER_UI_JS_SRI)):
            assert f'integrity="{sri}"' in tag and 'crossorigin="anonymous"' in tag
            assert f"swagger-ui-dist@{apidocs.SWAGGER_UI_VERSION}/" in tag
            assert tag.count("https://cdn.jsdelivr.net/") == 1
        assert "standalone-preset" not in html
        for sri in (apidocs.SWAGGER_UI_CSS_SRI, apidocs.SWAGGER_UI_JS_SRI):
            assert re.fullmatch(r"sha384-[A-Za-z0-9+/]{64}", sri)

    def test_every_external_resource_in_every_template_has_sri(self):
        tags = []
        for template in (ROOT / "app" / "templates").rglob("*.html"):
            text = template.read_text(encoding="utf-8")
            tags += [(template.name, t) for t in re.findall(r"<script[^>]+\bsrc=\"https?://[^\"]+\"[^>]*>", text)]
            tags += [(template.name, t) for t in re.findall(r"<link[^>]+\bhref=\"https?://[^\"]+\"[^>]*>", text)]
            tags += [(template.name, t) for t in re.findall(r"<(?:script|link)[^>]+\b(?:src|href)=\"{{[^}]+}}[^\"]*\"[^>]*>", text)
                     if "swagger_ui.cdn" in t]
        assert tags
        for name, tag in tags:
            assert 'integrity="' in tag and 'crossorigin="anonymous"' in tag, (name, tag)

    def test_hardening_switches_in_the_init_script(self, auth_admin):
        html = auth_admin.get(DOCS).get_data(as_text=True)
        for needle in ("queryConfigEnabled: false", "persistAuthorization: false", "validatorUrl: null",
                       "deepLinking: false", "tryItOutEnabled: false", "layout: 'BaseLayout'",
                       "req.credentials = 'omit'", "'application/json'", 'url: "/api/openapi.json"'):
            assert needle in html, needle
        assert "withCredentials" not in html and "localStorage" not in html.split("SwaggerUIBundle(")[1]
        assert 'supportedSubmitMethods: ["get", "put", "post", "delete", "options", "head", "patch", "trace"]' in html

    @pytest.mark.parametrize("mode, methods", [("read", '["get"]'), ("off", "[]")])
    def test_try_it_out_modes(self, mode, methods):
        class Mode(TestConfig):
            API_DOCS_TRY_IT_OUT = mode
        app = create_app(Mode)
        with app.app_context():
            _db.create_all()
            user = User(username=f"mode-{mode}", role="admin")
            user.set_password("adminpass-mode")
            _db.session.add(user)
            _db.session.commit()
            c = app.test_client()
            c.post("/auth/login", data={"username": f"mode-{mode}", "password": "adminpass-mode"})
            html = c.get(DOCS).get_data(as_text=True)
            assert f"supportedSubmitMethods: {methods}" in html
            assert f"API_DOCS_TRY_IT_OUT={mode}" in html
            _db.session.remove()
            _db.drop_all()

    def test_unknown_try_it_out_mode_refuses_startup(self):
        class Bad(TestConfig):
            API_DOCS_TRY_IT_OUT = "bogus"
        with pytest.raises(SystemExit):
            create_app(Bad)

    def test_page_uses_adaptive_classes(self, auth_admin):
        html = auth_admin.get(DOCS).data
        assert b"bg-light" not in html and b"text-muted" not in html
        assert b"returns private-key material" in html
        assert b'href="/users/api-tokens"' in html


# --- excluded endpoints are what they claim to be ---------------------------------------------------------

def test_excluded_form_only_writes_have_no_json_branch(app):
    """The user-management writes are excluded as 'form-only'; if someone gives one a
    JSON branch, it belongs in the document instead."""
    with app.app_context():
        for key, reason in ops.EXCLUDED.items():
            if "no JSON contract" not in reason:
                continue
            source = _view_source(app, key.split(":")[0])
            branches = source.count("wants_json()")
            assert branches <= 1, (key, "has JSON branches — document it")
