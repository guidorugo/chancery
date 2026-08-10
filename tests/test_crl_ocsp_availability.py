"""PKI-1 (configurable CRL validity + `flask crl refresh`) and PKI-2 (OCSP
response cache that never serves a revoked cert GOOD)."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from app.services import ca_service, cert_service, crl_service, ocsp_service
from app.models.ca import CertificateAuthority


def _ca(name="Avail CA"):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name}, key_type="RSA", key_size=2048,
        validity_days=3650, passphrase="test-passphrase")


def _ocsp_request_der(cert_pem, issuer_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    issuer = x509.load_pem_x509_certificate(issuer_pem.encode())
    req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA256()).build()
    return req.public_bytes(serialization.Encoding.DER)


# ---- PKI-1 ----------------------------------------------------------------

def test_crl_validity_is_configurable(app, db):
    with app.app_context():
        app.config["CRL_VALIDITY_DAYS"] = 30
        try:
            crl = crl_service.generate_crl(_ca("CRLValidity"), "test-passphrase")
            span = (crl.next_update_utc - crl.last_update_utc).days
            assert 29 <= span <= 30
        finally:
            app.config["CRL_VALIDITY_DAYS"] = 7


def test_crl_refresh_cli_all_regenerates(app, db):
    with app.app_context():
        ca = _ca("CRLRefreshAll")
        before = ca.crl_number
        cid = ca.id
    result = app.test_cli_runner().invoke(args=["crl", "refresh", "--all"])
    assert result.exit_code == 0
    with app.app_context():
        assert db.session.get(CertificateAuthority, cid).crl_number > before


def test_crl_refresh_cli_skips_fresh(app, db):
    with app.app_context():
        ca = _ca("CRLFresh")               # initial CRL, nextUpdate ~7d out (fresh)
        before = ca.crl_number
        cid = ca.id
    result = app.test_cli_runner().invoke(args=["crl", "refresh"])   # stale-only
    assert result.exit_code == 0
    with app.app_context():
        assert db.session.get(CertificateAuthority, cid).crl_number == before


# ---- PKI-2 ----------------------------------------------------------------

def test_ocsp_response_is_cached(app, db):
    with app.app_context():
        app.config["OCSP_RESPONSE_CACHE_TTL_SECONDS"] = 60
        ocsp_service._response_cache.clear()
        try:
            ca = _ca("OcspCache")
            cert = cert_service.create_certificate(
                ca=ca, subject_attrs={"CN": "ocsp.example.com"}, san_list=[],
                validity_days=365, passphrase="test-passphrase")
            req = _ocsp_request_der(cert.certificate_pem, ca.certificate_pem)
            ocsp_service.build_ocsp_response(req, ca, "test-passphrase")
            assert len(ocsp_service._response_cache._entries) >= 1
        finally:
            app.config["OCSP_RESPONSE_CACHE_TTL_SECONDS"] = 0
            ocsp_service._response_cache.clear()


def test_ocsp_cache_disabled_when_ttl_zero(app, db):
    with app.app_context():
        app.config["OCSP_RESPONSE_CACHE_TTL_SECONDS"] = 0
        ocsp_service._response_cache.clear()
        try:
            ca = _ca("OcspNoCache")
            cert = cert_service.create_certificate(
                ca=ca, subject_attrs={"CN": "nocache.example.com"}, san_list=[],
                validity_days=365, passphrase="test-passphrase")
            req = _ocsp_request_der(cert.certificate_pem, ca.certificate_pem)
            ocsp_service.build_ocsp_response(req, ca, "test-passphrase")
            assert len(ocsp_service._response_cache._entries) == 0
        finally:
            app.config["OCSP_RESPONSE_CACHE_TTL_SECONDS"] = 0


def test_ocsp_cache_never_serves_revoked_as_good(app, db):
    with app.app_context():
        app.config["OCSP_RESPONSE_CACHE_TTL_SECONDS"] = 60
        ocsp_service._response_cache.clear()
        try:
            ca = _ca("OcspRevoke")
            cert = cert_service.create_certificate(
                ca=ca, subject_attrs={"CN": "revoke-ocsp.example.com"}, san_list=[],
                validity_days=365, passphrase="test-passphrase")
            req = _ocsp_request_der(cert.certificate_pem, ca.certificate_pem)

            r1 = ocsp.load_der_ocsp_response(
                ocsp_service.build_ocsp_response(req, ca, "test-passphrase"))
            assert r1.certificate_status == ocsp.OCSPCertStatus.GOOD  # cached GOOD

            crl_service.revoke_certificate(cert.id, "key_compromise", passphrase="test-passphrase")

            r2 = ocsp.load_der_ocsp_response(
                ocsp_service.build_ocsp_response(req, ca, "test-passphrase"))
            assert r2.certificate_status == ocsp.OCSPCertStatus.REVOKED  # fresh, not stale GOOD
        finally:
            app.config["OCSP_RESPONSE_CACHE_TTL_SECONDS"] = 0
            ocsp_service._response_cache.clear()
