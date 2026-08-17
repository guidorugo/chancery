"""Prometheus /metrics endpoint: opt-in gate, dedicated-token auth, minimal
default exposure (opaque ca_id, no CA names), and well-formed output."""

import base64
import re
from datetime import datetime, timedelta, timezone

import pytest

from app.services import (ca_service, cert_service, crl_service,
                          metrics_service, metrics_token_service)

PASSPHRASE = "test-passphrase"


@pytest.fixture(autouse=True)
def _reset_crl_cache():
    # The CRL-nextUpdate cache is keyed on (ca_id, crl_number) — correct in
    # production, but fresh test DBs reuse id=1, so clear it between tests.
    metrics_service._CRL_CACHE.clear()
    yield
    metrics_service._CRL_CACHE.clear()


def _enable(app, monkeypatch, **overrides):
    monkeypatch.setitem(app.config, "METRICS_ENABLED", True)
    for k, v in overrides.items():
        monkeypatch.setitem(app.config, k, v)


def _exp(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(tzinfo=None)


def _token(name="prom", days=30):
    return metrics_token_service.create(name, _exp(days))  # -> (plaintext, row)


def _ca(name="MetricsCA"):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name, "O": "T"},
        key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE)


def _cert(ca, cn="leaf.metrics", days=365):
    return cert_service.create_certificate(
        ca=ca, subject_attrs={"CN": cn}, san_list=[],
        validity_days=days, passphrase=PASSPHRASE)


# ---- gate -----------------------------------------------------------------

def test_metrics_disabled_returns_404(client):
    r = client.get("/metrics")
    assert r.status_code == 404
    assert "text/plain" in r.content_type


def test_metrics_enabled_requires_token(app, client, monkeypatch):
    _enable(app, monkeypatch)
    r = client.get("/metrics")
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate", "").startswith("Bearer")


def test_metrics_valid_token_ok(app, client, db, monkeypatch):
    _enable(app, monkeypatch)
    with app.app_context():
        pt, _ = _token()
    r = client.get("/metrics", headers={"Authorization": f"Bearer {pt}"})
    assert r.status_code == 200
    # The exposition-format version tracks the installed prometheus_client
    # (0.0.4 pre-0.22, 1.0.0 after), so compare against the library constant.
    from prometheus_client import CONTENT_TYPE_LATEST

    assert r.content_type == CONTENT_TYPE_LATEST
    assert b"chancery_build_info" in r.data


def test_metrics_wrong_token_rejected(app, client, db, monkeypatch):
    _enable(app, monkeypatch)
    with app.app_context():
        pt, _ = _token()
    bad = pt[:-1] + ("0" if pt[-1] != "0" else "1")
    assert client.get("/metrics", headers={"Authorization": f"Bearer {bad}"}).status_code == 401


def test_metrics_expired_token_rejected(app, client, db, monkeypatch):
    _enable(app, monkeypatch)
    with app.app_context():
        pt, _ = _token(name="old", days=-1)
    assert client.get("/metrics", headers={"Authorization": f"Bearer {pt}"}).status_code == 401


def test_metrics_revoked_token_rejected(app, client, db, monkeypatch):
    _enable(app, monkeypatch)
    with app.app_context():
        pt, row = _token(name="rev")
        metrics_token_service.revoke(row.id)
    assert client.get("/metrics", headers={"Authorization": f"Bearer {pt}"}).status_code == 401


def test_metrics_rejects_valid_admin_basic_auth(app, client, admin_user, monkeypatch):
    """Least privilege: a real user credential grants NO metrics access."""
    _enable(app, monkeypatch)
    creds = base64.b64encode(b"testadmin:adminpass").decode()
    r = client.get("/metrics", headers={"Authorization": f"Basic {creds}"})
    assert r.status_code == 401


def test_metrics_allow_unauthenticated(app, client, monkeypatch):
    _enable(app, monkeypatch, METRICS_ALLOW_UNAUTHENTICATED=True)
    r = client.get("/metrics")
    assert r.status_code == 200
    assert b"chancery_build_info" in r.data


# ---- output ---------------------------------------------------------------

def test_metrics_wellformed_and_parses(app, client, monkeypatch):
    _enable(app, monkeypatch, METRICS_ALLOW_UNAUTHENTICATED=True)
    body = client.get("/metrics").get_data(as_text=True)
    from prometheus_client.parser import text_string_to_metric_families
    fams = {f.name for f in text_string_to_metric_families(body)}
    assert "chancery_build_info" in fams
    assert "chancery_scrape_duration_seconds" in fams
    assert body.endswith("\n")


def test_metrics_reflects_seeded_ca_cert(app, client, db, monkeypatch):
    _enable(app, monkeypatch, METRICS_ALLOW_UNAUTHENTICATED=True)
    with app.app_context():
        ca = _ca()
        _cert(ca, cn="reflected.example.com")
        cid = ca.id
    body = client.get("/metrics").get_data(as_text=True)
    assert 'chancery_certificates{state="valid"} 1.0' in body
    assert 'chancery_certificate_authorities_signing_capable 1.0' in body
    assert f'chancery_ca_certificates{{ca_id="{cid}",state="valid"}} 1.0' in body


def test_metrics_no_ca_names_by_default(app, client, db, monkeypatch):
    _enable(app, monkeypatch, METRICS_ALLOW_UNAUTHENTICATED=True)
    with app.app_context():
        _ca(name="SecretCAName")
    body = client.get("/metrics").get_data(as_text=True)
    assert "SecretCAName" not in body            # names never leak by default
    assert "chancery_ca_info" not in body


def test_metrics_ca_details_opt_in(app, client, db, monkeypatch):
    _enable(app, monkeypatch, METRICS_ALLOW_UNAUTHENTICATED=True,
            METRICS_INCLUDE_CA_DETAILS=True)
    with app.app_context():
        _ca(name="VisibleCAName")
    body = client.get("/metrics").get_data(as_text=True)
    assert "chancery_ca_info{" in body
    assert 'name="VisibleCAName"' in body


def test_metrics_crl_next_update_parsed(app, client, db, monkeypatch):
    _enable(app, monkeypatch, METRICS_ALLOW_UNAUTHENTICATED=True)
    from cryptography import x509
    with app.app_context():
        ca = _ca()
        crl_service.generate_crl(ca, PASSPHRASE)
        expected = x509.load_pem_x509_crl(ca.crl_pem.encode()).next_update_utc.timestamp()
        cid = ca.id
    body = client.get("/metrics").get_data(as_text=True)
    m = re.search(
        rf'chancery_ca_crl_next_update_timestamp_seconds{{ca_id="{cid}"}} ([0-9.e+]+)',
        body)
    assert m, body
    assert abs(float(m.group(1)) - expected) < 1.0


def test_metrics_empty_db_wellformed(app, client, monkeypatch):
    _enable(app, monkeypatch, METRICS_ALLOW_UNAUTHENTICATED=True)
    body = client.get("/metrics").get_data(as_text=True)
    # Closed-label families still emit every label at zero.
    assert 'chancery_csrs{status="pending"} 0.0' in body
    assert "chancery_build_info" in body


def test_metrics_reachable_under_password_change_guard(app, client, db, monkeypatch):
    _enable(app, monkeypatch, METRICS_ALLOW_UNAUTHENTICATED=True)
    from app.models.user import User
    with app.app_context():
        u = User(username="mc", role="admin")
        u.set_password("changeme123456")
        u.must_change_password = True
        db.session.add(u)
        db.session.commit()
    client.post("/auth/login", data={"username": "mc", "password": "changeme123456"})
    assert client.get("/", follow_redirects=False).status_code == 302   # normal page redirects
    assert client.get("/metrics", follow_redirects=False).status_code == 200  # metrics exempt
