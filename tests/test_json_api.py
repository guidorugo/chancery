"""JSON content negotiation: the same routes serve JSON to API clients
(Basic Auth or Accept: application/json) and HTML to browsers."""

import base64

import pytest

from app.models.ca import CertificateAuthority

JSON = {"Accept": "application/json"}
HTML = {"Accept": "text/html"}


def _basic(username, password):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


# ---- read endpoints -------------------------------------------------------

def test_list_cas_json_via_accept(auth_admin):
    r = auth_admin.get("/ca/", headers=JSON)
    assert r.status_code == 200
    assert r.is_json
    assert isinstance(r.get_json(), list)


def test_list_cas_html_for_browser(auth_admin):
    r = auth_admin.get("/ca/", headers=HTML)
    assert r.status_code == 200
    assert "text/html" in r.content_type


def test_no_accept_header_defaults_to_html(auth_admin):
    r = auth_admin.get("/ca/")
    assert "text/html" in r.content_type


def test_basic_auth_gets_json_automatically(client, admin_user):
    r = client.get("/ca/", headers=_basic("testadmin", "adminpass"))
    assert r.status_code == 200
    assert r.is_json


def test_lists_json(auth_admin):
    for path in ("/ca/", "/certificates/", "/csr/", "/users/"):
        r = auth_admin.get(path, headers=JSON)
        assert r.status_code == 200 and r.is_json, path
        assert isinstance(r.get_json(), list)


def test_audit_log_json_is_paginated(auth_admin):
    r = auth_admin.get("/users/audit-log", headers=JSON)
    assert r.status_code == 200 and r.is_json
    body = r.get_json()
    assert set(body) >= {"items", "page", "total", "pages"}


def test_dashboard_json(auth_admin):
    r = auth_admin.get("/", headers=JSON)
    assert r.status_code == 200 and r.is_json
    assert "stats" in r.get_json()


def test_dashboard_recent_certs_capped_at_10_in_json(app, auth_admin, db):
    # The route fetches a larger pool so the client-side fit script can fill a
    # tall panel, but the JSON API stays capped at 10 recent.
    from app.services import ca_service, cert_service
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="RecentCap CA", subject_attrs={"CN": "RecentCap CA"},
            key_type="RSA", key_size=2048, validity_days=3650,
            passphrase="test-passphrase")
        for i in range(12):
            cert_service.create_certificate(
                ca=ca, subject_attrs={"CN": f"r{i}.example"}, san_list=[],
                validity_days=365, passphrase="test-passphrase")
    body = auth_admin.get("/", headers=JSON).get_json()
    assert len(body["recent_certs"]) == 10


def test_dashboard_html_includes_fit_script(auth_admin):
    r = auth_admin.get("/", headers=HTML)
    assert r.status_code == 200 and b"js/dashboard.js" in r.data


def test_dashboard_fit_script_served(client):
    r = client.get("/static/js/dashboard.js")
    assert r.status_code == 200 and b"fitTable" in r.data


def test_missing_resource_json_404(auth_admin):
    r = auth_admin.get("/ca/9999", headers=JSON)
    assert r.status_code == 404
    assert r.get_json()["error"]


# ---- write endpoints ------------------------------------------------------

def test_create_ca_via_json(auth_admin):
    r = auth_admin.post("/ca/create", headers=JSON, data={
        "mode": "generate", "name": "apitest", "cn": "API Test CA",
        "key_type": "EC", "key_size": "256", "validity_days": "365",
        "ca_type": "root",
    })
    assert r.status_code == 201
    body = r.get_json()
    assert body["name"] == "apitest"
    assert body["common_name"] == "API Test CA"
    assert isinstance(body["id"], int)
    # secrets never leak
    assert "private_key_enc" not in body


def test_create_ca_validation_error_json(auth_admin):
    r = auth_admin.post("/ca/create", headers=JSON, data={
        "mode": "generate", "name": "", "cn": "",
    })
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_generate_crl_via_json(auth_admin, app):
    auth_admin.post("/ca/create", headers=JSON, data={
        "mode": "generate", "name": "crlca", "cn": "CRL CA",
        "key_type": "EC", "key_size": "256", "validity_days": "365",
        "ca_type": "root",
    })
    with app.app_context():
        ca_id = CertificateAuthority.query.filter_by(name="crlca").first().id
    r = auth_admin.post(f"/ca/{ca_id}/crl", headers=JSON)
    assert r.status_code == 200 and r.is_json
    assert r.get_json()["id"] == ca_id


# ---- serializers do not leak secrets --------------------------------------

def test_user_json_omits_password_hash(auth_admin):
    users = auth_admin.get("/users/", headers=JSON).get_json()
    assert users
    # META-2: assert the WHOLE key set stays within an allowlist, so ANY new
    # (possibly secret) field added to to_dict() fails the test — not just the
    # two names we currently know to be sensitive.
    allowed = {"id", "username", "role", "is_active", "auth_source",
               "must_change_password", "created_at"}
    for u in users:
        assert "password_hash" not in u
        assert set(u) <= allowed
        assert {"id", "username", "role"} <= set(u)


def test_ca_detail_json_has_no_key_material(auth_admin):
    auth_admin.post("/ca/create", headers=JSON, data={
        "mode": "generate", "name": "leakcheck", "cn": "Leak Check",
        "key_type": "EC", "key_size": "256", "validity_days": "365",
        "ca_type": "root",
    })
    cas = auth_admin.get("/ca/", headers=JSON).get_json()
    ca_id = next(c["id"] for c in cas if c["name"] == "leakcheck")
    detail = auth_admin.get(f"/ca/{ca_id}", headers=JSON).get_json()
    ca_allowed = {
        "id", "name", "common_name", "serial_number", "key_type", "key_size",
        "key_backend", "is_root", "parent_id", "not_before", "not_after",
        "days_until_expiry", "expiry_status", "is_revoked", "has_private_key",
        "has_signing_key", "is_exportable", "created_at", "path_length",
        "crl_number", "revoked_at", "revocation_reason", "certificate_pem",
        "approval_status", "created_by", "approved_by", "approved_at",
    }
    assert "private_key_enc" not in detail
    assert "key_label" not in detail
    assert set(detail) <= ca_allowed          # META-2: nothing outside the allowlist
    assert detail["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")


# ---- META-1: JSON authz negative paths (ownership) ------------------------

def test_csr_requester_cross_user_cert_json_403(app, client, admin_user, csr_requester):
    """A csr_requester requesting a cert they don't own, via JSON, gets a
    403 JSON body (not an HTML redirect)."""
    from app.services import ca_service, cert_service
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="OwnCA", subject_attrs={"CN": "Own CA"}, key_type="RSA",
            key_size=2048, validity_days=3650, passphrase="test-passphrase")
        cert = cert_service.create_certificate(
            ca=ca, subject_attrs={"CN": "notyours.example.com"}, san_list=[],
            validity_days=365, passphrase="test-passphrase")   # requested_by=None
        cid = cert.id
    client.post("/auth/login", data={"username": "testrequester", "password": "requesterpass"})
    r = client.get(f"/certificates/{cid}", headers=JSON)
    assert r.status_code == 403 and r.is_json
