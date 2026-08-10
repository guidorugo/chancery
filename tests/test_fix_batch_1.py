"""Batch 1 assessment fixes: PKI-7, PKI-4, HSM-1, CORE-2, CORE-4, API-5."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.services import ca_service, cert_service, csr_service
from app.models.ca import CertificateAuthority
from app.models.csr import CertificateSigningRequest


# ---- PKI-7: CA import enforces the key-strength floor ---------------------

def _weak_ca_cert_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Weak CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_pki7_import_rejects_weak_ca(app, db):
    with app.app_context():
        with pytest.raises(ValueError):
            ca_service.import_ca("WeakImport", _weak_ca_cert_pem(), None, "test-passphrase")


# ---- PKI-4: issuance from an expired CA is rejected -----------------------

def test_pki4_expired_ca_rejected(app, db):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="ExpiredCA", subject_attrs={"CN": "Expired CA"},
            key_type="RSA", key_size=2048, validity_days=3650, passphrase="test-passphrase")
        ca.not_after = (datetime.now(timezone.utc) - timedelta(days=1)).replace(tzinfo=None)
        db.session.commit()

        with pytest.raises(ValueError, match="expired"):
            cert_service.create_certificate(
                ca=ca, subject_attrs={"CN": "x.example.com"}, san_list=[],
                validity_days=30, passphrase="test-passphrase")

        csr_model, _, _ = csr_service.create_csr(
            subject_attrs={"CN": "y.example.com"}, san_list=[], key_type="RSA", key_size=2048)
        with pytest.raises(ValueError, match="expired"):
            cert_service.sign_csr(csr_model=csr_model, ca=ca, validity_days=30,
                                  passphrase="test-passphrase")


# ---- HSM-1: unsupported EC curve fails cleanly, not with a KeyError -------

def test_hsm1_unsupported_curve_raises_valueerror():
    pytest.importorskip("pkcs11")
    from app.services.keybackend import get_backend
    backend = get_backend("softhsm")
    bad = CertificateAuthority(key_type="EC", key_size=224)   # not P-256/384/521
    with pytest.raises(ValueError):
        backend._ca_key_info(bad)
    good = CertificateAuthority(key_type="EC", key_size=256)
    assert backend._ca_key_info(good)[0] == "EC"


# ---- CORE-2: empty/blank secrets are rejected at startup ------------------

class _FakeApp:
    def __init__(self, config):
        self.config = config
        self.debug = False


def test_core2_blank_secret_key_rejected():
    from app import _check_security
    with pytest.raises(SystemExit):
        _check_security(_FakeApp(
            {"TESTING": False, "SECRET_KEY": "   ", "MASTER_PASSPHRASE": "a" * 24}))


def test_core2_blank_master_passphrase_rejected():
    from app import _check_security
    with pytest.raises(SystemExit):
        _check_security(_FakeApp(
            {"TESTING": False, "SECRET_KEY": "a-strong-secret-key", "MASTER_PASSPHRASE": ""}))


def test_core2_strong_secrets_pass():
    from app import _check_security
    # No exception for non-blank, non-default secrets.
    _check_security(_FakeApp(
        {"TESTING": False, "SECRET_KEY": "a-strong-secret-key", "MASTER_PASSPHRASE": "a" * 24}))


# ---- CORE-4: the update-check refresh never leaves `refreshing` stuck -----

def test_core4_refresh_resets_flag_on_unexpected_error(monkeypatch):
    from app.services import update_service as us
    us._reset_cache_for_tests()
    us._STATE["refreshing"] = True

    def boom(repo, timeout):
        raise AttributeError("non-dict JSON body")  # not in the old except tuple

    monkeypatch.setattr(us, "_fetch_latest_tag", boom)
    us._refresh("owner/repo", 1)          # must not raise
    assert us._STATE["refreshing"] is False
    us._reset_cache_for_tests()


# ---- API-5: reject only applies to a pending CSR --------------------------

def test_api5_reject_guarded_on_pending(app, auth_admin, db):
    with app.app_context():
        csr_model, _, _ = csr_service.create_csr(
            subject_attrs={"CN": "reject-me.example.com"}, san_list=[],
            key_type="RSA", key_size=2048)
        csr_model.status = "approved"      # already processed
        db.session.commit()
        cid = csr_model.id
    resp = auth_admin.post(f"/csr/{cid}/reject", follow_redirects=False)
    assert resp.status_code == 302         # redirected away, not rejected
    with app.app_context():
        assert db.session.get(CertificateSigningRequest, cid).status == "approved"
