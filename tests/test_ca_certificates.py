"""F11: CA certificate re-issue and cross-signing — same-key re-issue keeps
issued certificates valid (SKI/AKI), cross-certificates give a second trust
path, chains can be built via either, alternates are served publicly,
imported cross-certs attach to the key, dual control gates both, and openssl
verifies a leaf through both chains."""
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from app import create_app
from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.models.ca_certificate import CaCertificate
from app.models.user import User
from app.services import ca_service, cert_service, crl_service, ocsp_service, profile_service
from tests.conftest import TestConfig

PASSPHRASE = "test-passphrase"
JSON = {"Accept": "application/json"}


@pytest.fixture(autouse=True)
def _seed_profiles(app, db):
    with app.app_context():
        profile_service.ensure_builtins()


def _root(name="Alt Root", **kw):
    return ca_service.create_root_ca(name=name, subject_attrs={"CN": name}, key_type="EC", key_size=256,
                                     validity_days=3650, passphrase=PASSPHRASE, **kw)


def _inter(root, name="Alt Inter", **kw):
    return ca_service.create_intermediate_ca(name, root, {"CN": name}, "EC", 256, 1825, PASSPHRASE, **kw)


def _leaf(ca, cn="leaf.example"):
    return cert_service.create_certificate(ca, {"CN": cn}, [cn], 30, PASSPHRASE, key_type="EC", key_size=256)


def _x(pem_or_model):
    pem = pem_or_model if isinstance(pem_or_model, str) else pem_or_model.certificate_pem
    return x509.load_pem_x509_certificate(pem.encode())


def _ski(cert):
    return cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest


def _aki(cert):
    return cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier


def _openssl_verify(leaf_pem, chain_pems, root_pem):
    if not shutil.which("openssl"):
        return None
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "leaf.pem"), "w").write(leaf_pem)
        open(os.path.join(d, "untrusted.pem"), "w").write("\n".join(chain_pems))
        open(os.path.join(d, "root.pem"), "w").write(root_pem)
        args = ["openssl", "verify", "-CAfile", os.path.join(d, "root.pem")]
        if chain_pems:
            args += ["-untrusted", os.path.join(d, "untrusted.pem")]
        r = subprocess.run(args + [os.path.join(d, "leaf.pem")], capture_output=True, text=True)
        return r.returncode == 0, r.stdout + r.stderr


class TestReissue:
    def test_reissue_keeps_key_and_leaves_valid(self, app, db):
        with app.app_context():
            root = _root()
            inter = _inter(root)
            leaf = _leaf(inter)
            old_cert = _x(inter)
            old_serial = inter.serial_number
            previous = ca_service.reissue_ca_certificate(inter, PASSPHRASE, validity_days=400)
            db.session.commit()
            new_cert = _x(inter)
            assert inter.serial_number != old_serial and new_cert.serial_number != old_cert.serial_number
            assert _ski(new_cert) == _ski(old_cert) and new_cert.public_key().public_numbers() == old_cert.public_key().public_numbers()
            assert new_cert.subject == old_cert.subject and new_cert.issuer == old_cert.issuer
            assert _aki(new_cert) == _ski(_x(root))
            assert (new_cert.not_valid_after_utc - new_cert.not_valid_before_utc).days == 400
            new_cert.verify_directly_issued_by(_x(root))
            # the old primary is kept as a "previous" alternate
            assert previous.kind == "previous" and previous.serial_number == old_serial and previous.certificate_pem == old_cert.public_bytes(serialization.Encoding.PEM).decode()
            assert [a.kind for a in inter.alternate_certificates] == ["previous"]
            # existing leaves still chain to the new certificate (AKI = unchanged SKI)
            assert _aki(_x(leaf)) == _ski(new_cert)
            _x(leaf).verify_directly_issued_by(new_cert)
            ok = _openssl_verify(leaf.certificate_pem, [inter.certificate_pem], root.certificate_pem)
            assert ok is None or ok[0], ok
            # CRL and OCSP keep working (same key)
            crl_service.refresh_crl(inter, PASSPHRASE)
            assert x509.load_pem_x509_crl(inter.crl_pem.encode()).is_signature_valid(new_cert.public_key())
            from cryptography.x509 import ocsp
            req = ocsp.OCSPRequestBuilder().add_certificate(_x(leaf), new_cert, hashes.SHA256()).build()
            resp = ocsp.load_der_ocsp_response(ocsp_service.build_ocsp_response(req.public_bytes(serialization.Encoding.DER), inter, PASSPHRASE))
            assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD
            # a root re-issues itself
            old_root = _x(root)
            ca_service.reissue_ca_certificate(root, PASSPHRASE)
            db.session.commit()
            assert _x(root).serial_number != old_root.serial_number and _ski(_x(root)) == _ski(old_root)
            _x(root).verify_directly_issued_by(_x(root))
            _x(inter).verify_directly_issued_by(_x(root))
            assert inter.expiry_notified_at is None

    def test_reissue_refusals_and_constraints_carry_over(self, app, db):
        with app.app_context():
            from app.services import name_constraints
            root = _root("NC Root", constraints=name_constraints.normalise("DNS:example.com", None))
            ca_service.reissue_ca_certificate(root, PASSPHRASE)
            db.session.commit()
            ext = _x(root).extensions.get_extension_for_class(x509.NameConstraints)
            assert ext.critical and [n.value for n in ext.value.permitted_subtrees] == ["example.com"]
            gone = _root("Gone")
            crl_service.revoke_ca(gone.id, "cessation_of_operation", passphrase=PASSPHRASE)
            with pytest.raises(ValueError, match="revoked"):
                ca_service.reissue_ca_certificate(gone, PASSPHRASE)
            from tests.test_ca_import import _self_signed_ca
            _k, cert = _self_signed_ca("Offline")
            keyless = ca_service.import_ca("Offline", cert.public_bytes(serialization.Encoding.PEM).decode(), None, PASSPHRASE)
            with pytest.raises(ValueError, match="no private key"):
                ca_service.reissue_ca_certificate(keyless, PASSPHRASE)


class TestCrossSign:
    def test_cross_certificate_gives_a_second_trust_path(self, app, db):
        with app.app_context():
            root_a = _root("Root A")
            root_b = _root("Root B")
            inter = _inter(root_a, "Inter under A")
            leaf = _leaf(inter)
            alt = ca_service.cross_sign_ca(inter, root_b, PASSPHRASE)
            db.session.commit()
            cross = _x(alt.certificate_pem)
            assert alt.kind == "cross" and alt.issuer_ca_id == root_b.id and alt.is_usable
            assert cross.subject == _x(inter).subject and _ski(cross) == _ski(_x(inter)) and _aki(cross) == _ski(_x(root_b))
            cross.verify_directly_issued_by(_x(root_b))
            assert inter.certificate_pem != alt.certificate_pem          # primary untouched
            # chain via the primary path and via the cross-certificate
            assert ca_service.chain_pems(inter) == [inter.certificate_pem, root_a.certificate_pem]
            assert ca_service.chain_pems(inter, alt) == [alt.certificate_pem, root_b.certificate_pem]
            assert cert_service.export_fullchain_pem(leaf, alt).count("BEGIN CERTIFICATE") == 3
            ok_a = _openssl_verify(leaf.certificate_pem, [inter.certificate_pem], root_a.certificate_pem)
            ok_b = _openssl_verify(leaf.certificate_pem, [alt.certificate_pem], root_b.certificate_pem)
            ok_wrong = _openssl_verify(leaf.certificate_pem, [inter.certificate_pem], root_b.certificate_pem)
            if ok_a is not None:
                assert ok_a[0] and ok_b[0] and not ok_wrong[0], (ok_a, ok_b, ok_wrong)
            # a revoked issuer makes the cross-certificate unusable for chain building
            crl_service.revoke_ca(root_b.id, "cessation_of_operation", passphrase=PASSPHRASE)
            db.session.expire_all()
            alt = db.session.get(CaCertificate, alt.id)
            assert alt.is_usable is False
            with pytest.raises(ValueError, match="not usable"):
                ca_service.chain_pems(inter, alt)

    def test_cross_sign_rules(self, app, db):
        with app.app_context():
            from app.services import name_constraints
            root_a = _root("Rules A")
            inter = _inter(root_a, "Rules Inter")
            with pytest.raises(ValueError, match="cannot cross-sign itself"):
                ca_service.cross_sign_ca(inter, inter, PASSPHRASE)
            with pytest.raises(ValueError, match="descendant"):
                ca_service.cross_sign_ca(root_a, inter, PASSPHRASE)
            narrow = _root("Narrow", constraints=name_constraints.normalise("DNS:example.com", None))
            with pytest.raises(ValueError, match="permitted name constraints"):
                ca_service.cross_sign_ca(_inter(root_a, "ca.other.org"), narrow, PASSPHRASE)
            short = ca_service.create_root_ca(name="Short Issuer", subject_attrs={"CN": "Short Issuer"}, key_type="EC",
                                              key_size=256, validity_days=20, passphrase=PASSPHRASE, path_length=1)
            alt = ca_service.cross_sign_ca(inter, short, PASSPHRASE, validity_days=3650)
            db.session.commit()
            cross = _x(alt.certificate_pem)
            assert (cross.not_valid_after_utc - datetime.now(timezone.utc)).days <= 20       # clamped to the issuer
            assert cross.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0  # PKI-6

    def test_import_external_cross_certificate(self, app, db):
        with app.app_context():
            root = _root("Imp Root")
            inter = _inter(root, "Imp Inter")
            # an external PKI cross-signs our intermediate's key
            ext_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            ext_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "External Root")])
            now = datetime.now(timezone.utc)
            inter_cert = _x(inter)
            cross = (x509.CertificateBuilder().subject_name(inter_cert.subject).issuer_name(ext_name)
                     .public_key(inter_cert.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now).not_valid_after(now + timedelta(days=365))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                     .add_extension(x509.SubjectKeyIdentifier.from_public_key(inter_cert.public_key()), critical=False)
                     .sign(ext_key, hashes.SHA256()))
            row = ca_service.import_alternate_certificate(inter, cross.public_bytes(serialization.Encoding.PEM).decode())
            db.session.commit()
            assert row.kind == "cross" and row.issuer_ca_id is None and row.is_usable
            assert ca_service.chain_pems(inter, row) == [row.certificate_pem]         # external issuer: chain ends here
            with pytest.raises(ValueError, match="already stored"):
                ca_service.import_alternate_certificate(inter, cross.public_bytes(serialization.Encoding.PEM).decode())
            with pytest.raises(ValueError, match="does not match"):
                ca_service.import_alternate_certificate(root, cross.public_bytes(serialization.Encoding.PEM).decode())
            leaf_cert = _leaf(inter)
            with pytest.raises(ValueError, match="does not match"):            # a leaf has its own key
                ca_service.import_alternate_certificate(inter, leaf_cert.certificate_pem)
            not_ca = (x509.CertificateBuilder().subject_name(inter_cert.subject).issuer_name(ext_name)
                      .public_key(inter_cert.public_key()).serial_number(x509.random_serial_number())
                      .not_valid_before(now).not_valid_after(now + timedelta(days=30))
                      .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                      .sign(ext_key, hashes.SHA256()))
            with pytest.raises(ValueError, match="not a CA certificate"):
                ca_service.import_alternate_certificate(inter, not_ca.public_bytes(serialization.Encoding.PEM).decode())


class TestRoutes:
    def test_routes_and_public_alt(self, auth_admin, client, app, db):
        with app.app_context():
            root_a = _root("R A")
            root_b = _root("R B")
            inter = _inter(root_a, "R Inter")
            leaf = _leaf(inter)
            r = auth_admin.post(f"/ca/{inter.id}/cross-sign", headers=JSON, data={"issuer_ca_id": str(root_b.id)})
            assert r.status_code == 201, r.data
            alt = r.get_json()
            assert alt["kind"] == "cross" and alt["issuer_name"] == "R B" and alt["usable"] is True
            assert client.get(f"/public/ca/{inter.id}/alt/{alt['id']}.crt").status_code == 200
            assert client.get(f"/public/ca/{inter.id}/alt/999999.crt").status_code == 404
            chain = auth_admin.get(f"/ca/{inter.id}/download?format=chain&via={alt['id']}")
            assert chain.status_code == 200 and chain.data.decode().count("BEGIN CERTIFICATE") == 2
            assert root_b.certificate_pem.strip() in chain.data.decode()
            full = auth_admin.get(f"/certificates/{leaf.id}/download?format=fullchain&via={alt['id']}")
            assert full.status_code == 200 and full.data.decode().count("BEGIN CERTIFICATE") == 3
            assert auth_admin.get(f"/certificates/{leaf.id}/download?format=chain&via=999999", headers=JSON).status_code == 404
            r = auth_admin.post(f"/ca/{inter.id}/reissue", headers=JSON, data={"validity_days": "500"})
            assert r.status_code == 201, r.data
            body = r.get_json()
            kinds = sorted(a["kind"] for a in body["alternate_certificates"])
            assert kinds == ["cross", "previous"]
            page = auth_admin.get(f"/ca/{inter.id}").get_data(as_text=True)
            assert "CA Certificates" in page and "Cross-signed" in page and "Previous" in page and "Re-issue certificate" in page
            assert AuditLog.query.filter_by(action="cross_sign_ca").count() == 1 and AuditLog.query.filter_by(action="reissue_ca_certificate").count() == 1
            prev_id = next(a["id"] for a in body["alternate_certificates"] if a["kind"] == "previous")
            r = auth_admin.post(f"/ca/{inter.id}/certificates/{prev_id}/delete", headers=JSON)
            assert r.status_code == 200 and r.get_json() == {"deleted": prev_id}
            assert auth_admin.post(f"/ca/{inter.id}/cross-sign", headers=JSON, data={"issuer_ca_id": "abc"}).status_code == 400
            assert auth_admin.post(f"/ca/{inter.id}/cross-sign", headers=JSON, data={"issuer_ca_id": str(inter.id)}).status_code == 400


class DualControlConfig(TestConfig):
    DUAL_CONTROL_ENABLED = True


@pytest.fixture(scope="module")
def dc_app():
    return create_app(DualControlConfig)


@pytest.fixture
def dc_db(dc_app):
    with dc_app.app_context():
        _db.drop_all()
        _db.create_all()
        profile_service.ensure_builtins()
        yield _db
        _db.session.remove()


def _user(username):
    u = User(username=username, role="admin")
    u.set_password("password-123456")
    _db.session.add(u)
    _db.session.commit()
    return u


def _login(dc_app, username):
    c = dc_app.test_client()
    c.post("/auth/login", data={"username": username, "password": "password-123456"})
    return c


class TestDualControl:
    def test_reissue_and_cross_sign_are_pending_until_another_admin_approves(self, dc_app, dc_db):
        with dc_app.app_context():
            _user("admin"); _user("alice"); _user("bob")
            root_a = _root("DC Root A")
            root_b = _root("DC Root B")
            inter = _inter(root_a, "DC Inter")
            old_serial = inter.serial_number
            alice = _login(dc_app, "alice")
            r = alice.post(f"/ca/{inter.id}/reissue", headers=JSON)
            assert r.status_code == 201 and r.get_json()["approval_status"] == "pending" and r.get_json()["kind"] == "reissue"
            reissue_id = r.get_json()["id"]
            assert dc_db.session.get(CertificateAuthority, inter.id).serial_number == old_serial     # not promoted yet
            r = alice.post(f"/ca/{inter.id}/cross-sign", headers=JSON, data={"issuer_ca_id": str(root_b.id)})
            assert r.status_code == 201 and r.get_json()["approval_status"] == "pending"
            cross_id = r.get_json()["id"]
            assert dc_app.test_client().get(f"/public/ca/{inter.id}/alt/{cross_id}.crt").status_code == 404   # pending: not served
            assert alice.post(f"/ca/{inter.id}/certificates/{reissue_id}/approve", headers=JSON).status_code == 403
            bob = _login(dc_app, "bob")
            r = bob.post(f"/ca/{inter.id}/certificates/{reissue_id}/approve", headers=JSON)
            assert r.status_code == 200, r.data
            dc_db.session.expire_all()
            inter = dc_db.session.get(CertificateAuthority, inter.id)
            assert inter.serial_number != old_serial and sorted(a.kind for a in inter.alternate_certificates) == ["cross", "previous"]
            r = bob.post(f"/ca/{inter.id}/certificates/{cross_id}/approve", headers=JSON)
            assert r.status_code == 200 and r.get_json()["approval_status"] == "approved"
            assert dc_app.test_client().get(f"/public/ca/{inter.id}/alt/{cross_id}.crt").status_code == 200
            assert AuditLog.query.filter_by(action="approve_ca_certificate").count() == 2
