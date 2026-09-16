"""F5: Ed25519 / Ed448 keys end to end (software backend) and the explicit
key-algorithm allow-list (G4-3). SoftHSM parity lives in test_softhsm.py."""
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID

from app.extensions import db as _db
from app.models.ca import CertificateAuthority
from app.services import (ca_service, cert_service, crl_service, crypto_utils, csr_service,
                          ocsp_service, policy, profile_service)

PASSPHRASE = "test-passphrase"
JSON = {"Accept": "application/json"}


@pytest.fixture(autouse=True)
def _seed_profiles(app, db):
    with app.app_context():
        profile_service.ensure_builtins()


def _root(name, key_type, key_size=0, **kw):
    return ca_service.create_root_ca(name=name, subject_attrs={"CN": name}, key_type=key_type,
                                     key_size=key_size, validity_days=3650, passphrase=PASSPHRASE, **kw)


def _x(model):
    return x509.load_pem_x509_certificate(model.certificate_pem.encode())


# ---------------------------------------------------------------------------
# helpers / policy
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_generate_key_and_key_info(self, app):
        with app.app_context():
            for key_type, cls, size in (("ED25519", ed25519.Ed25519PrivateKey, 256), ("ED448", ed448.Ed448PrivateKey, 456),
                                        ("RSA", rsa.RSAPrivateKey, 2048), ("EC", ec.EllipticCurvePrivateKey, 384)):
                key = crypto_utils.generate_key(key_type, size)
                assert isinstance(key, cls)
                assert crypto_utils.key_info(key) == (key_type, size)
                assert crypto_utils.key_info(key.public_key()) == (key_type, size)
            assert crypto_utils.generate_key("ED25519", 4096).public_key().public_bytes_raw()  # size is ignored
            assert crypto_utils.hash_for_key(crypto_utils.generate_key("ED25519")) is None
            assert crypto_utils.hash_for_key(crypto_utils.generate_key("ED448")) is None
            assert isinstance(crypto_utils.hash_for_key(crypto_utils.generate_key("RSA", 2048)), hashes.SHA256)
            with pytest.raises(ValueError, match="Unsupported key type"):
                crypto_utils.generate_key("DSA", 2048)

    def test_public_key_policy_is_an_allow_list(self, app):
        with app.app_context():
            policy.enforce_public_key_strength(ed25519.Ed25519PrivateKey.generate().public_key())
            policy.enforce_public_key_strength(ed448.Ed448PrivateKey.generate().public_key())
            with pytest.raises(ValueError, match="Unsupported key algorithm"):
                policy.enforce_public_key_strength(dsa.generate_private_key(2048).public_key())
            with pytest.raises(ValueError, match="Unsupported EC curve"):
                policy.enforce_public_key_strength(ec.generate_private_key(ec.SECP256K1()).public_key())
            with pytest.raises(ValueError, match="Unsupported key algorithm"):
                crypto_utils.key_info(dsa.generate_private_key(2048).public_key())
            policy.enforce_key_strength("ED448", None)  # nothing to choose

    def test_profiles_know_the_new_types(self, app, db):
        with app.app_context():
            assert "ED25519" in profile_service.KEY_TYPES and "ED448" in profile_service.KEY_TYPES
            client = profile_service.lookup("client_auth")
            client.allowed_key_types_json = '["ED25519"]'
            db.session.commit()
            root = _root("Prof Root", "RSA", 2048)
            cert = cert_service.create_certificate(root, {"CN": "ed.example"}, ["ed.example"], 30, PASSPHRASE,
                                                   key_type="ED25519", profile=client)
            assert cert.key_type == "ED25519"
            with pytest.raises(ValueError, match="does not allow RSA"):
                cert_service.create_certificate(root, {"CN": "r.example"}, ["r.example"], 30, PASSPHRASE,
                                                key_type="RSA", key_size=2048, profile=client)
            client.allowed_key_types_json = None
            db.session.commit()


# ---------------------------------------------------------------------------
# CA / certificate / CSR lifecycle
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_ed25519_root_ed448_intermediate_mixed_leaves(self, app, db):
        with app.app_context():
            root = _root("Ed Root", "ED25519")
            assert (root.key_type, root.key_size) == ("ED25519", 256)
            rc = _x(root)
            assert rc.signature_algorithm_oid == SignatureAlgorithmOID.ED25519 and rc.signature_hash_algorithm is None
            rc.verify_directly_issued_by(rc)
            assert root.crl_pem and x509.load_pem_x509_crl(root.crl_pem.encode()).is_signature_valid(rc.public_key())

            inter = ca_service.create_intermediate_ca("Ed448 Inter", root, {"CN": "Ed448 Inter"}, "ED448", 0, 1825, PASSPHRASE)
            assert (inter.key_type, inter.key_size) == ("ED448", 456)
            ic = _x(inter)
            assert ic.signature_algorithm_oid == SignatureAlgorithmOID.ED25519   # signed by the Ed25519 root
            ic.verify_directly_issued_by(rc)

            rsa_leaf = cert_service.create_certificate(inter, {"CN": "rsa.example"}, ["rsa.example"], 90, PASSPHRASE,
                                                       key_type="RSA", key_size=2048)
            ed_leaf = cert_service.create_certificate(inter, {"CN": "ed.example"}, ["ed.example"], 90, PASSPHRASE,
                                                      key_type="ED25519")
            for leaf in (rsa_leaf, ed_leaf):
                lc = _x(leaf)
                assert lc.signature_algorithm_oid == SignatureAlgorithmOID.ED448
                lc.verify_directly_issued_by(ic)
            assert (ed_leaf.key_type, ed_leaf.key_size) == ("ED25519", 256)
            assert isinstance(crypto_utils.decrypt_private_key(ed_leaf.private_key_enc, PASSPHRASE), ed25519.Ed25519PrivateKey)

            # the software CA chain is accepted by OpenSSL too, when available
            if shutil.which("openssl"):
                import tempfile, os
                with tempfile.TemporaryDirectory() as d:
                    open(os.path.join(d, "root.pem"), "w").write(root.certificate_pem)
                    open(os.path.join(d, "inter.pem"), "w").write(inter.certificate_pem)
                    open(os.path.join(d, "leaf.pem"), "w").write(ed_leaf.certificate_pem)
                    r = subprocess.run(["openssl", "verify", "-CAfile", os.path.join(d, "root.pem"),
                                        "-untrusted", os.path.join(d, "inter.pem"), os.path.join(d, "leaf.pem")],
                                       capture_output=True, text=True)
                    assert r.returncode == 0, r.stdout + r.stderr

    def test_ed25519_leaf_from_rsa_ca_and_exports(self, app, db):
        with app.app_context():
            root = _root("RSA Root", "RSA", 2048)
            cert = cert_service.create_certificate(root, {"CN": "ed.example"}, ["ed.example"], 90, PASSPHRASE,
                                                   key_type="ED448")
            lc = _x(cert)
            assert isinstance(lc.public_key(), ed448.Ed448PublicKey)
            assert lc.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA256
            p12 = cert_service.export_pkcs12(cert, PASSPHRASE, "export-pw")
            from cryptography.hazmat.primitives.serialization import pkcs12
            key, c, _chain = pkcs12.load_key_and_certificates(p12, b"export-pw")
            assert isinstance(key, ed448.Ed448PrivateKey) and c == lc
            # renewal with a fresh key keeps the algorithm
            new = cert_service.renew_certificate(cert, PASSPHRASE, rekey=True, validity_days=30)
            db.session.commit()
            assert new.key_type == "ED448" and isinstance(_x(new).public_key(), ed448.Ed448PublicKey)

    def test_csr_generate_and_sign(self, app, db):
        with app.app_context():
            root = _root("CSR Root", "ED448")
            csr_model, key_pem, _ = csr_service.create_csr({"CN": "csr.example"}, ["csr.example"], "ED25519", 0, None)
            db.session.commit()
            csr = x509.load_pem_x509_csr(csr_model.csr_pem.encode())
            assert csr.is_signature_valid and csr.signature_hash_algorithm is None
            assert isinstance(serialization.load_pem_private_key(key_pem, None), ed25519.Ed25519PrivateKey)
            cert = cert_service.sign_csr(csr_model, root, 90, PASSPHRASE)
            assert (cert.key_type, cert.key_size) == ("ED25519", 256)
            _x(cert).verify_directly_issued_by(_x(root))

    def test_dsa_csr_is_refused_on_import_and_signing(self, app, db, auth_admin):
        with app.app_context():
            key = dsa.generate_private_key(2048)
            csr = (x509.CertificateSigningRequestBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dsa.example")]))
                   .sign(key, hashes.SHA256()))
            pem = csr.public_bytes(serialization.Encoding.PEM).decode()
            with pytest.raises(ValueError, match="Unsupported key algorithm"):
                csr_service.import_csr(pem)
            r = auth_admin.post("/csr/create", headers=JSON, data={"mode": "upload", "csr_pem": pem})
            assert r.status_code == 400 and "Unsupported key algorithm" in r.get_json()["error"]

    def test_crl_and_ocsp_from_an_ed_ca(self, app, db):
        with app.app_context():
            root = _root("OCSP Ed Root", "ED25519")
            rc = _x(root)
            cert = cert_service.create_certificate(root, {"CN": "o.example"}, ["o.example"], 90, PASSPHRASE,
                                                   key_type="EC", key_size=256)
            crl_service.revoke_certificate(cert.id, "superseded", passphrase=PASSPHRASE)
            crl = x509.load_pem_x509_crl(root.crl_pem.encode())
            assert crl.signature_algorithm_oid == SignatureAlgorithmOID.ED25519
            assert crl.is_signature_valid(rc.public_key())
            assert crl.get_revoked_certificate_by_serial_number(int(cert.serial_number, 16)) is not None
            req = ocsp.OCSPRequestBuilder().add_certificate(_x(cert), rc, hashes.SHA1()).build()
            resp = ocsp.load_der_ocsp_response(ocsp_service.build_ocsp_response(
                req.public_bytes(serialization.Encoding.DER), root, PASSPHRASE))
            assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
            assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
            assert resp.signature_algorithm_oid == SignatureAlgorithmOID.ED25519
            rc.public_key().verify(resp.signature, resp.tbs_response_bytes)

    def test_import_and_export_of_an_ed_ca(self, app, db):
        with app.app_context():
            key = ed25519.Ed25519PrivateKey.generate()
            from datetime import datetime, timedelta, timezone
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Imported Ed Root")])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=365))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                    .sign(key, None))
            ca = ca_service.import_ca("Imported Ed Root", cert.public_bytes(serialization.Encoding.PEM).decode(),
                                      key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()).decode(), PASSPHRASE)
            assert (ca.key_type, ca.key_size) == ("ED25519", 256) and ca.has_signing_key
            leaf = cert_service.create_certificate(ca, {"CN": "l.example"}, ["l.example"], 30, PASSPHRASE, key_type="ED25519")
            _x(leaf).verify_directly_issued_by(cert)


# ---------------------------------------------------------------------------
# routes / UI
# ---------------------------------------------------------------------------

class TestRoutes:
    def test_forms_offer_the_new_types(self, auth_admin, app, db):
        with app.app_context():
            for path in ("/ca/create", "/certificates/create", "/csr/create"):
                page = auth_admin.get(path).get_data(as_text=True)
                assert 'value="ED25519"' in page and 'value="ED448"' in page and 'id="ed_note"' in page
                assert "not accept them for TLS server certificates" in page

    def test_api_creates_ed_ca_and_certificate(self, auth_admin, app, db):
        with app.app_context():
            r = auth_admin.post("/ca/create", headers=JSON, data={
                "mode": "generate", "name": "API Ed CA", "cn": "API Ed CA", "key_type": "ED25519",
                "key_size": "2048",  # ignored for Edwards keys (a disabled selector may still post something)
                "validity_days": "365", "ca_type": "root"})
            assert r.status_code == 201, r.data
            body = r.get_json()
            assert body["key_type"] == "ED25519" and body["key_size"] == 256
            r = auth_admin.post("/certificates/create", headers=JSON, data={
                "ca_id": str(body["id"]), "cn": "api-ed.example", "san": "api-ed.example",
                "key_type": "ED448", "validity_days": "30"})
            assert r.status_code == 201, r.data
            cert = r.get_json()
            assert cert["key_type"] == "ED448" and cert["key_size"] == 456
            r = auth_admin.post("/certificates/create", headers=JSON, data={
                "ca_id": str(body["id"]), "cn": "bad.example", "key_type": "DSA", "key_size": "2048", "validity_days": "30"})
            assert r.status_code == 400
