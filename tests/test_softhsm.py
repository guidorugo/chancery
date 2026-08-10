"""SoftHSM backend tests (finding A1, Phase 2).

The correctness anchor: sign the *same* pinned certificate two ways —
SoftwareBackend with an RSA key, and Pkcs11Backend with the same key imported
into a SoftHSM token — and assert the DER is byte-identical. RSA PKCS#1 v1.5 is
deterministic, so any divergence in the TBS bytes, algorithm identifiers, or
signature encoding fails the test. EC is randomized, so there we assert the TBS
is identical and the certificate verifies.

Skips entirely where python-pkcs11 / SoftHSM are not installed; CI installs
softhsm2 so this runs in the pipeline and gates the published image.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("pkcs11")  # skip whole module if the library is absent

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from app.services import ca_service, cert_service, crl_service, ocsp_service
from app.services.crypto_utils import decrypt_private_key
from app.services.keybackend import get_backend, pkcs11_session, hsm_available
from app.services.keybackend.softhsm import Pkcs11Backend
from app.services.keybackend.base import OcspResponseSpec


PASSPHRASE = "test-passphrase"


@pytest.fixture
def hsm_config(app, softhsm_token):
    """Point app config at the session SoftHSM token; reset session caches."""
    keys = ("KEY_BACKEND", "PKCS11_MODULE", "PKCS11_TOKEN_LABEL", "PKCS11_USER_PIN")
    prev = {k: app.config.get(k) for k in keys}
    app.config["PKCS11_MODULE"] = softhsm_token["module"]
    app.config["PKCS11_TOKEN_LABEL"] = softhsm_token["label"]
    app.config["PKCS11_USER_PIN"] = softhsm_token["user_pin"]
    pkcs11_session.reset()
    yield softhsm_token
    for k, v in prev.items():
        app.config[k] = v
    pkcs11_session.reset()


def _leaf_builder(ca):
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(0x0BADC0DE)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )


def _hsm_ca(ca, label):
    """A stand-in CA object that reads as HSM-backed for the backend."""
    return SimpleNamespace(
        certificate_pem=ca.certificate_pem,
        key_label=label,
        key_backend="softhsm",
        private_key_enc=b"",
        has_signing_key=True,
        key_type=ca.key_type,
        key_size=ca.key_size,
    )


# --- the differential parity gate -------------------------------------------

def test_rsa_leaf_der_is_byte_identical(app, db, hsm_config):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="Diff Root RSA", subject_attrs={"CN": "Diff Root RSA"},
            key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE,
        )
        ca_key = decrypt_private_key(ca.private_key_enc, PASSPHRASE)
        Pkcs11Backend().import_ca_key(ca_key, label="diff-rsa")

        builder = _leaf_builder(ca)
        soft_der = get_backend("software").sign_certificate(builder, ca, secret=PASSPHRASE)
        hsm_der = Pkcs11Backend().sign_certificate(builder, _hsm_ca(ca, "diff-rsa"))

        assert hsm_der == soft_der  # RSA is deterministic -> exact byte parity
        leaf = x509.load_der_x509_certificate(hsm_der)
        leaf.verify_directly_issued_by(x509.load_pem_x509_certificate(ca.certificate_pem.encode()))


def test_ec_leaf_tbs_identical_and_verifies(app, db, hsm_config):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="Diff Root EC", subject_attrs={"CN": "Diff Root EC"},
            key_type="EC", key_size=256, validity_days=3650, passphrase=PASSPHRASE,
        )
        ca_key = decrypt_private_key(ca.private_key_enc, PASSPHRASE)
        Pkcs11Backend().import_ca_key(ca_key, label="diff-ec")

        builder = _leaf_builder(ca)
        soft_der = get_backend("software").sign_certificate(builder, ca, secret=PASSPHRASE)
        hsm_der = Pkcs11Backend().sign_certificate(builder, _hsm_ca(ca, "diff-ec"))

        # ECDSA is randomized: the signature differs, but the TBS must match...
        soft = x509.load_der_x509_certificate(soft_der)
        hsm = x509.load_der_x509_certificate(hsm_der)
        assert hsm.tbs_certificate_bytes == soft.tbs_certificate_bytes
        # ...and the token's signature must verify against the CA public key.
        hsm.verify_directly_issued_by(x509.load_pem_x509_certificate(ca.certificate_pem.encode()))


# --- key generation ---------------------------------------------------------

def test_generate_rsa_key_in_token(app, db, hsm_config):
    with app.app_context():
        pub, label = Pkcs11Backend().generate_ca_key("RSA", 2048, label="gen-rsa")
        assert isinstance(pub, rsa.RSAPublicKey)
        assert pub.key_size == 2048
        # The token holds a matching, usable private key (never left the token).
        from pkcs11 import ObjectClass, Mechanism
        data = b"to-be-signed"
        with pkcs11_session.session_scope() as s:
            priv = s.get_key(object_class=ObjectClass.PRIVATE_KEY, label=label)
            sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())


def test_generate_ec_key_in_token(app, db, hsm_config):
    with app.app_context():
        pub, label = Pkcs11Backend().generate_ca_key("EC", 256, label="gen-ec")
        assert isinstance(pub, ec.EllipticCurvePublicKey)
        assert pub.curve.name == "secp256r1"
        import hashlib
        from pkcs11 import ObjectClass, Mechanism
        from pkcs11.util.ec import encode_ecdsa_signature
        data = b"to-be-signed"
        with pkcs11_session.session_scope() as s:
            priv = s.get_key(object_class=ObjectClass.PRIVATE_KEY, label=label)
            raw = priv.sign(hashlib.sha256(data).digest(), mechanism=Mechanism.ECDSA)
        pub.verify(encode_ecdsa_signature(raw), data, ec.ECDSA(hashes.SHA256()))


def test_can_export_false(app, db, hsm_config):
    with app.app_context():
        assert Pkcs11Backend().can_export() is False


# --- Phase 3: CRL (byte-identical) ------------------------------------------

def test_rsa_crl_der_is_byte_identical(app, db, hsm_config):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="CRL Root RSA", subject_attrs={"CN": "CRL Root RSA"},
            key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE,
        )
        ca_key = decrypt_private_key(ca.private_key_enc, PASSPHRASE)
        Pkcs11Backend().import_ca_key(ca_key, label="crl-rsa")

        ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now)
            .next_update(now + timedelta(days=7))
            .add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(0x1234)
                .revocation_date(now)
                .build()
            )
        )
        soft = get_backend("software").sign_crl(builder, ca, secret=PASSPHRASE)
        hsm = Pkcs11Backend().sign_crl(builder, _hsm_ca(ca, "crl-rsa"))
        assert soft == hsm  # RSA deterministic -> exact byte parity
        crl = x509.load_der_x509_crl(hsm)
        assert crl.is_signature_valid(ca_cert.public_key())


# --- Phase 3: OCSP (semantic parity + verifies) -----------------------------

def _ocsp_spec(ca, leaf_der, status, algorithm, revocation_time=None, reason=None):
    ca_cert_der = x509.load_pem_x509_certificate(
        ca.certificate_pem.encode()).public_bytes(serialization.Encoding.DER)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return OcspResponseSpec(
        subject_cert_der=leaf_der, issuer_cert_der=ca_cert_der,
        cert_status=status, this_update=now, next_update=now + timedelta(days=1),
        revocation_time=revocation_time, revocation_reason=reason, algorithm=algorithm,
    )


def test_ocsp_hsm_matches_software(app, db, hsm_config):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="OCSP Root RSA", subject_attrs={"CN": "OCSP Root RSA"},
            key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE,
        )
        ca_key = decrypt_private_key(ca.private_key_enc, PASSPHRASE)
        Pkcs11Backend().import_ca_key(ca_key, label="ocsp-rsa")
        ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
        leaf_der = get_backend("software").sign_certificate(
            _leaf_builder(ca), ca, secret=PASSPHRASE)

        for status, rtime, reason in [
            (ocsp.OCSPCertStatus.GOOD, None, None),
            (ocsp.OCSPCertStatus.REVOKED,
             datetime(2026, 1, 2, tzinfo=timezone.utc), x509.ReasonFlags.key_compromise),
        ]:
            spec = _ocsp_spec(ca, leaf_der, status, hashes.SHA1(), rtime, reason)
            soft = get_backend("software").sign_ocsp(spec, ca, secret=PASSPHRASE)
            hsm = Pkcs11Backend().sign_ocsp(spec, _hsm_ca(ca, "ocsp-rsa"))
            rs = ocsp.load_der_ocsp_response(soft)
            rh = ocsp.load_der_ocsp_response(hsm)
            assert rh.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
            assert rh.certificate_status == rs.certificate_status
            assert rh.serial_number == rs.serial_number
            assert rh.issuer_key_hash == rs.issuer_key_hash
            assert rh.issuer_name_hash == rs.issuer_name_hash
            assert rh.responder_key_hash == rs.responder_key_hash
            assert rh.hash_algorithm.name == rs.hash_algorithm.name
            # the token's signature verifies against the CA public key
            ca_cert.public_key().verify(
                rh.signature, rh.tbs_response_bytes,
                padding.PKCS1v15(), rh.signature_hash_algorithm)


# --- Phase 3: full HSM CA lifecycle via the services ------------------------

def test_hsm_ca_end_to_end(app, db, hsm_config):
    with app.app_context():
        app.config["KEY_BACKEND"] = "softhsm"
        ca = ca_service.create_root_ca(
            name="E2E HSM Root", subject_attrs={"CN": "E2E HSM Root"},
            key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE,
        )
        # keyless in the DB; key lives in the token
        assert ca.key_backend == "softhsm"
        assert ca.private_key_enc == b"" and ca.key_label
        assert ca.has_signing_key and not ca.is_exportable
        # initial CRL was published at creation
        assert ca.crl_pem
        ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
        x509.load_pem_x509_crl(ca.crl_pem.encode()).is_signature_valid(ca_cert.public_key())

        # issue a leaf certificate (signed by the token)
        cert = cert_service.create_certificate(
            ca, {"CN": "leaf.example"}, [], 90, PASSPHRASE,
            key_type="RSA", key_size=2048)
        leaf = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        leaf.verify_directly_issued_by(ca_cert)

        # OCSP GOOD for that leaf, through the public responder path
        req = ocsp.OCSPRequestBuilder().add_certificate(
            leaf, ca_cert, hashes.SHA1()).build()
        resp = ocsp.load_der_ocsp_response(
            ocsp_service.build_ocsp_response(
                req.public_bytes(serialization.Encoding.DER), ca, PASSPHRASE))
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD

        # revoke and confirm the refreshed CRL lists it (token-signed)
        crl_service.revoke_certificate(cert.id, passphrase=PASSPHRASE)
        crl = x509.load_pem_x509_crl(ca.crl_pem.encode())
        assert crl.is_signature_valid(ca_cert.public_key())
        assert crl.get_revoked_certificate_by_serial_number(
            int(cert.serial_number, 16)) is not None


# --- Phase 3: cross-backend intermediates -----------------------------------

def test_software_root_signs_hsm_intermediate(app, db, hsm_config):
    with app.app_context():
        root = ca_service.create_root_ca(
            name="XB SW Root", subject_attrs={"CN": "XB SW Root"},
            key_type="RSA", key_size=2048, validity_days=3650,
            passphrase=PASSPHRASE, backend="software")
        inter = ca_service.create_intermediate_ca(
            "XB HSM Inter", root, {"CN": "XB HSM Inter"},
            "RSA", 2048, 1825, PASSPHRASE, backend="softhsm")
        assert inter.key_backend == "softhsm" and inter.private_key_enc == b""
        root_cert = x509.load_pem_x509_certificate(root.certificate_pem.encode())
        inter_cert = x509.load_pem_x509_certificate(inter.certificate_pem.encode())
        inter_cert.verify_directly_issued_by(root_cert)
        # the HSM intermediate can itself issue a leaf
        cert = cert_service.create_certificate(
            inter, {"CN": "leaf2"}, [], 90, PASSPHRASE, key_type="RSA", key_size=2048)
        x509.load_pem_x509_certificate(cert.certificate_pem.encode()).verify_directly_issued_by(inter_cert)


def test_hsm_root_signs_software_intermediate(app, db, hsm_config):
    with app.app_context():
        root = ca_service.create_root_ca(
            name="XB HSM Root", subject_attrs={"CN": "XB HSM Root"},
            key_type="RSA", key_size=2048, validity_days=3650,
            passphrase=PASSPHRASE, backend="softhsm")
        inter = ca_service.create_intermediate_ca(
            "XB SW Inter", root, {"CN": "XB SW Inter"},
            "RSA", 2048, 1825, PASSPHRASE, backend="software")
        assert inter.key_backend == "software" and inter.private_key_enc != b""
        root_cert = x509.load_pem_x509_certificate(root.certificate_pem.encode())
        inter_cert = x509.load_pem_x509_certificate(inter.certificate_pem.encode())
        inter_cert.verify_directly_issued_by(root_cert)


# --- Phase 4: availability, export refusal, migration CLI, route ------------

def test_hsm_available(app, db, hsm_config):
    with app.app_context():
        assert hsm_available() is True


def test_export_refused_for_hsm_ca(app, db, hsm_config):
    with app.app_context():
        app.config["KEY_BACKEND"] = "softhsm"
        ca = ca_service.create_root_ca(
            name="NoExport HSM", subject_attrs={"CN": "NoExport HSM"},
            key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE)
        assert ca.is_exportable is False
        with pytest.raises(ValueError, match="held in the HSM"):
            ca_service.export_ca_key_pem(ca, PASSPHRASE)
        with pytest.raises(ValueError, match="held in the HSM"):
            ca_service.export_ca_pkcs12(ca, PASSPHRASE, "p12pass")


def test_migrate_to_hsm_cli(app, db, hsm_config):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="Migrate Me", subject_attrs={"CN": "Migrate Me"},
            key_type="RSA", key_size=2048, validity_days=3650,
            passphrase=PASSPHRASE, backend="software")
        assert ca.key_backend == "software" and ca.private_key_enc != b""
        ca_id = ca.id

        result = app.test_cli_runner().invoke(args=["keys", "migrate-to-hsm", "--yes"])
        assert result.exit_code == 0, result.output

        migrated = db.session.get(ca_service.CertificateAuthority, ca_id)
        assert migrated.key_backend == "softhsm"
        assert migrated.private_key_enc == b"" and migrated.key_label
        # still fully functional after migration: issues a verifiable leaf
        cert = cert_service.create_certificate(
            migrated, {"CN": "post-migrate"}, [], 90, PASSPHRASE,
            key_type="RSA", key_size=2048)
        ca_cert = x509.load_pem_x509_certificate(migrated.certificate_pem.encode())
        x509.load_pem_x509_certificate(cert.certificate_pem.encode()).verify_directly_issued_by(ca_cert)
        # and export is now refused
        assert migrated.is_exportable is False


def test_create_ca_route_selects_hsm_backend(client, admin_user, app, db, hsm_config):
    client.post("/auth/login", data={"username": "testadmin", "password": "adminpass"})
    resp = client.post("/ca/create", data={
        "mode": "generate", "name": "UI HSM Root", "cn": "UI HSM Root",
        "key_type": "RSA", "key_size": "2048", "validity_days": "3650",
        "ca_type": "root", "key_backend": "softhsm",
    }, follow_redirects=False)
    assert resp.status_code in (302, 303)
    with app.app_context():
        ca = ca_service.CertificateAuthority.query.filter_by(name="UI HSM Root").first()
        assert ca is not None and ca.key_backend == "softhsm"
        assert ca.private_key_enc == b"" and ca.has_signing_key


# --- HSM-3 / CORE-3 robustness ----------------------------------------------

def test_core3_verify_signing_key_rsa_ok(app, db, hsm_config):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="Verify RSA", subject_attrs={"CN": "Verify RSA"},
            key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE)
        Pkcs11Backend().import_ca_key(
            decrypt_private_key(ca.private_key_enc, PASSPHRASE), label="verify-rsa")
        # CORE-3: a correctly-imported key signs-and-verifies (no exception).
        Pkcs11Backend().verify_signing_key(_hsm_ca(ca, "verify-rsa"))


def test_core3_verify_signing_key_ec_ok(app, db, hsm_config):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="Verify EC", subject_attrs={"CN": "Verify EC"},
            key_type="EC", key_size=256, validity_days=3650, passphrase=PASSPHRASE)
        Pkcs11Backend().import_ca_key(
            decrypt_private_key(ca.private_key_enc, PASSPHRASE), label="verify-ec")
        Pkcs11Backend().verify_signing_key(_hsm_ca(ca, "verify-ec"))


def test_core3_verify_signing_key_raises_when_token_key_missing(app, db, hsm_config):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="Verify Missing", subject_attrs={"CN": "Verify Missing"},
            key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE)
        # No key imported under this label -> verification must fail (so
        # migrate-to-hsm would NOT scrub the software copy).
        with pytest.raises(Exception):
            Pkcs11Backend().verify_signing_key(_hsm_ca(ca, "no-such-label"))


def test_hsm3_session_cleared_on_error_and_reopens(app, db, hsm_config):
    with app.app_context():
        # Force an error inside session_scope: the dead handle must be dropped.
        with pytest.raises(RuntimeError):
            with pkcs11_session.session_scope() as s:
                assert s is not None and pkcs11_session._session is not None
                raise RuntimeError("boom")
        assert pkcs11_session._session is None          # HSM-3: cleared
        # A subsequent scope re-opens cleanly instead of failing forever.
        with pkcs11_session.session_scope() as s2:
            assert s2 is not None
        assert pkcs11_session._session is not None
