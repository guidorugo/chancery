"""F6: signature digest matched to the key under SIGNATURE_HASH_POLICY
(legacy = SHA-256 everywhere, the default; match-curve = SHA-256/384/512 by
curve and RSA_SIGNATURE_HASH for RSA), on certificates, CRLs, OCSP responses
and generated CSRs; startup refuses unknown values. G5-3."""
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import SignatureAlgorithmOID

from app import create_app
from app.config import Config
from app.services import ca_service, cert_service, crl_service, crypto_utils, csr_service, ocsp_service

PASSPHRASE = "test-passphrase"


def _root(name, key_type, key_size):
    return ca_service.create_root_ca(name=name, subject_attrs={"CN": name}, key_type=key_type,
                                     key_size=key_size, validity_days=3650, passphrase=PASSPHRASE)


def _x(model):
    return x509.load_pem_x509_certificate(model.certificate_pem.encode())


def _ocsp(ca, cert):
    req = ocsp.OCSPRequestBuilder().add_certificate(_x(cert), _x(ca), hashes.SHA1()).build()
    return ocsp.load_der_ocsp_response(ocsp_service.build_ocsp_response(
        req.public_bytes(serialization.Encoding.DER), ca, PASSPHRASE))


class TestHelpers:
    def test_legacy_is_sha256_for_rsa_and_ec(self, app):
        with app.app_context():
            app.config["SIGNATURE_HASH_POLICY"] = "legacy"
            for kt, ks in (("RSA", 2048), ("EC", 256), ("EC", 384), ("EC", 521)):
                assert crypto_utils.signature_hash_name(kt, ks) == "sha256"
            assert crypto_utils.signature_hash_name("ED25519", 256) is None
            assert isinstance(crypto_utils.hash_for_key_params("EC", 521), hashes.SHA256)

    def test_match_curve_mapping(self, app, monkeypatch):
        with app.app_context():
            monkeypatch.setitem(app.config, "SIGNATURE_HASH_POLICY", "match-curve")
            monkeypatch.setitem(app.config, "RSA_SIGNATURE_HASH", "sha384")
            assert crypto_utils.signature_hash_name("EC", 256) == "sha256"
            assert crypto_utils.signature_hash_name("EC", 384) == "sha384"
            assert crypto_utils.signature_hash_name("EC", 521) == "sha512"
            assert crypto_utils.signature_hash_name("RSA", 4096) == "sha384"
            assert crypto_utils.signature_hash_name("ED448", 456) is None
            assert isinstance(crypto_utils.hash_for_key(crypto_utils.generate_key("EC", 521)), hashes.SHA512)

    def test_outside_an_app_context_is_legacy(self):
        assert crypto_utils.signature_hash_name("EC", 521) == "sha256"

    @pytest.mark.parametrize("bad", [{"SIGNATURE_HASH_POLICY": "sha1"}, {"RSA_SIGNATURE_HASH": "md5"}])
    def test_startup_refuses_unknown_values(self, bad):
        class BadConfig(Config):
            TESTING = True
            SQLALCHEMY_DATABASE_URI = "sqlite://"
            SECRET_KEY = "strong-secret-key-for-tests-xxxxxxxx"
            MASTER_PASSPHRASE = "strong-passphrase-for-tests"
            WTF_CSRF_ENABLED = False
        for k, v in bad.items():
            setattr(BadConfig, k, v)
        with pytest.raises(SystemExit):
            create_app(BadConfig)


class TestSignatures:
    @pytest.mark.parametrize("key_type,key_size,oid,digest", [
        ("EC", 256, SignatureAlgorithmOID.ECDSA_WITH_SHA256, hashes.SHA256),
        ("EC", 384, SignatureAlgorithmOID.ECDSA_WITH_SHA384, hashes.SHA384),
        ("EC", 521, SignatureAlgorithmOID.ECDSA_WITH_SHA512, hashes.SHA512),
        ("RSA", 2048, SignatureAlgorithmOID.RSA_WITH_SHA384, hashes.SHA384),
    ])
    def test_match_curve_on_cert_crl_ocsp_and_csr(self, app, db, monkeypatch, key_type, key_size, oid, digest):
        with app.app_context():
            monkeypatch.setitem(app.config, "SIGNATURE_HASH_POLICY", "match-curve")
            monkeypatch.setitem(app.config, "RSA_SIGNATURE_HASH", "sha384")
            ocsp_service._response_cache.clear()
            root = _root(f"MC {key_type} {key_size}", key_type, key_size)
            rc = _x(root)
            assert rc.signature_algorithm_oid == oid and isinstance(rc.signature_hash_algorithm, digest)
            rc.verify_directly_issued_by(rc)
            cert = cert_service.create_certificate(root, {"CN": "l.example"}, ["l.example"], 30, PASSPHRASE,
                                                   key_type="EC", key_size=256)
            lc = _x(cert)
            assert lc.signature_algorithm_oid == oid
            lc.verify_directly_issued_by(rc)
            crl = x509.load_pem_x509_crl(root.crl_pem.encode())
            assert crl.signature_algorithm_oid == oid and crl.is_signature_valid(rc.public_key())
            resp = _ocsp(root, cert)
            assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
            assert resp.signature_algorithm_oid == oid
            assert resp.hash_algorithm.name == "sha1"   # the CertID digest still mirrors the request
            # generated CSRs self-sign with the same rule
            csr_model, _k, _ = csr_service.create_csr({"CN": "c.example"}, ["c.example"], key_type, key_size, None)
            db.session.commit()
            csr = x509.load_pem_x509_csr(csr_model.csr_pem.encode())
            assert csr.signature_algorithm_oid == oid and csr.is_signature_valid

    def test_legacy_default_keeps_sha256_and_existing_objects_are_untouched(self, app, db, monkeypatch):
        with app.app_context():
            assert app.config.get("SIGNATURE_HASH_POLICY", "legacy") == "legacy"
            root = _root("Legacy P-521", "EC", 521)
            assert _x(root).signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256
            cert = cert_service.create_certificate(root, {"CN": "l.example"}, ["l.example"], 30, PASSPHRASE,
                                                   key_type="EC", key_size=384)
            assert _x(cert).signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256
            assert x509.load_pem_x509_crl(root.crl_pem.encode()).signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256
            # flipping the policy changes only NEW signatures
            monkeypatch.setitem(app.config, "SIGNATURE_HASH_POLICY", "match-curve")
            crl_service.generate_crl(root, PASSPHRASE)
            assert x509.load_pem_x509_crl(root.crl_pem.encode()).signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA512
            assert _x(cert).signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256   # the old cert is what it was
            renewed = cert_service.renew_certificate(cert, PASSPHRASE)
            db.session.commit()
            assert _x(renewed).signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA512

    def test_ed_keys_ignore_the_policy(self, app, db, monkeypatch):
        with app.app_context():
            monkeypatch.setitem(app.config, "SIGNATURE_HASH_POLICY", "match-curve")
            root = _root("MC Ed", "ED25519", 0)
            assert _x(root).signature_hash_algorithm is None
            assert _x(root).signature_algorithm_oid == SignatureAlgorithmOID.ED25519
