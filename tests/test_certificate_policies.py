"""F3: Certificate Policies — parsing/validation, the extension on CA
certificates, inheritance by every issued certificate (profile override),
import, display, JSON API and migration."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import inspect as sa_inspect

from app.extensions import db as _db
from app.services import ca_service, cert_service, certificate_policies, csr_service, profile_service

PASSPHRASE = "test-passphrase"
JSON = {"Accept": "application/json"}
POL = "1.3.6.1.4.1.99999.1.1 https://pki.example/cps\n2.5.29.32.0"


@pytest.fixture(autouse=True)
def _seed_profiles(app, db):
    with app.app_context():
        profile_service.ensure_builtins()


def _root(name="Policy Root", policies=POL, **kw):
    return ca_service.create_root_ca(name=name, subject_attrs={"CN": name}, key_type="EC", key_size=256,
                                     validity_days=3650, passphrase=PASSPHRASE,
                                     policies=certificate_policies.normalise(policies), **kw)


def _x(model):
    return x509.load_pem_x509_certificate(model.certificate_pem.encode())


def _ext(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.CertificatePolicies)
    except x509.ExtensionNotFound:
        return None


class TestParsing:
    def test_entries(self):
        assert certificate_policies.parse_entries(POL) == [
            {"oid": "1.3.6.1.4.1.99999.1.1", "cps_uri": "https://pki.example/cps"},
            {"oid": "2.5.29.32.0", "cps_uri": None}]
        assert certificate_policies.parse_entries("# comment\n\n 1.2.3 \n1.2.3 https://dup.example") == [{"oid": "1.2.3", "cps_uri": None}]
        assert certificate_policies.normalise("") is None
        assert certificate_policies.parse_entries([{"oid": "1.2.3", "cps_uri": "http://x.example/c"}]) == [{"oid": "1.2.3", "cps_uri": "http://x.example/c"}]
        assert certificate_policies.to_lines(certificate_policies.parse_entries(POL)) == POL
        for bad in ("abc", "1", "3.1.2", "1.40.1", "1.2.03", "1.2.3 ftp://x", "1.2.3 not a url"):
            with pytest.raises(ValueError):
                certificate_policies.parse_entries(bad)

    def test_extension_round_trip_drops_user_notices(self):
        pols = certificate_policies.parse_entries(POL)
        ext = certificate_policies.build_extension(pols)
        notice = x509.PolicyInformation(x509.ObjectIdentifier("1.2.3.4"), [x509.UserNotice(None, "read the CPS")])
        ext = x509.CertificatePolicies(list(ext) + [notice])
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rt")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1))
                .add_extension(ext, critical=False).sign(key, hashes.SHA256()))
        assert certificate_policies.from_certificate(cert) == pols + [{"oid": "1.2.3.4", "cps_uri": None}]
        assert certificate_policies.build_extension(None) is None


class TestIssuance:
    def test_ca_carries_the_extension_and_leaves_inherit(self, app, db):
        with app.app_context():
            root = _root()
            ext = _ext(_x(root))
            assert ext is not None and not ext.critical
            assert [p.policy_identifier.dotted_string for p in ext.value] == ["1.3.6.1.4.1.99999.1.1", "2.5.29.32.0"]
            assert ext.value[0].policy_qualifiers == ["https://pki.example/cps"]
            assert root.certificate_policies == certificate_policies.parse_entries(POL)
            assert root.to_dict()["certificate_policies"] == root.certificate_policies
            cert = cert_service.create_certificate(root, {"CN": "leaf.example"}, ["leaf.example"], 30, PASSPHRASE,
                                                   key_type="EC", key_size=256)
            assert cert.certificate_policies == root.certificate_policies
            assert cert.to_dict(detail=True)["certificate_policies"] == root.certificate_policies
            assert "certificate_policies" not in cert.to_dict()
            # CSR signing and renewal inherit too
            csr_model, _k, _ = csr_service.create_csr({"CN": "csr.example"}, ["csr.example"], "EC", 256, None)
            db.session.commit()
            signed = cert_service.sign_csr(csr_model, root, 30, PASSPHRASE)
            assert signed.certificate_policies == root.certificate_policies
            renewed = cert_service.renew_certificate(cert, PASSPHRASE)
            db.session.commit()
            assert renewed.certificate_policies == root.certificate_policies
            # an intermediate gets only what it is given; its leaves then carry that
            inter = ca_service.create_intermediate_ca("Pol Inter", root, {"CN": "Pol Inter"}, "EC", 256, 365, PASSPHRASE,
                                                      policies=certificate_policies.normalise("1.3.6.1.4.1.99999.2.1"))
            assert inter.certificate_policies == [{"oid": "1.3.6.1.4.1.99999.2.1", "cps_uri": None}]
            plain_inter = ca_service.create_intermediate_ca("Plain Inter", root, {"CN": "Plain Inter"}, "EC", 256, 365, PASSPHRASE)
            assert plain_inter.certificate_policies is None and _ext(_x(plain_inter)) is None
            leaf = cert_service.create_certificate(plain_inter, {"CN": "p.example"}, ["p.example"], 30, PASSPHRASE,
                                                   key_type="EC", key_size=256)
            assert leaf.certificate_policies is None and _ext(_x(leaf)) is None

    def test_profile_policies_override_the_ca(self, app, db):
        with app.app_context():
            root = _root()
            client = profile_service.lookup("client_auth")
            profile_service.update(client, dict(client.to_dict(), certificate_policies="1.3.6.1.4.1.99999.9.9 https://cps.example/client"))
            db.session.commit()
            assert client.certificate_policies == [{"oid": "1.3.6.1.4.1.99999.9.9", "cps_uri": "https://cps.example/client"}]
            cert = cert_service.create_certificate(root, {"CN": "c.example"}, ["c.example"], 30, PASSPHRASE,
                                                   key_type="EC", key_size=256, profile=client)
            assert cert.certificate_policies == client.certificate_policies
            web = profile_service.lookup("web_server")
            assert web.certificate_policies is None
            cert2 = cert_service.create_certificate(root, {"CN": "w.example"}, ["w.example"], 30, PASSPHRASE,
                                                    key_type="EC", key_size=256, profile=web)
            assert cert2.certificate_policies == root.certificate_policies
            with pytest.raises(ValueError, match="Certificate policies"):
                profile_service.update(client, dict(client.to_dict(), certificate_policies="not-an-oid"))
            db.session.rollback()
            profile_service.update(client, dict(client.to_dict(), certificate_policies=""))
            db.session.commit()
            assert client.certificate_policies is None
            assert "certificate_policies" in profile_service.EXPORT_FIELDS

    def test_imported_ca_policies_are_stored_and_inherited(self, app, db):
        with app.app_context():
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Imported Policy Root")])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=365))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                    .add_extension(certificate_policies.build_extension(certificate_policies.parse_entries("1.2.826.0.1.1 https://cps.example/")), critical=False)
                    .sign(key, hashes.SHA256()))
            ca = ca_service.import_ca("Imported Policy Root", cert.public_bytes(serialization.Encoding.PEM).decode(),
                                      key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()).decode(), PASSPHRASE)
            assert ca.certificate_policies == [{"oid": "1.2.826.0.1.1", "cps_uri": "https://cps.example/"}]
            leaf = cert_service.create_certificate(ca, {"CN": "i.example"}, ["i.example"], 30, PASSPHRASE, key_type="EC", key_size=256)
            assert leaf.certificate_policies == ca.certificate_policies

    def test_migration_adds_the_columns(self, app, db):
        with app.app_context():
            from app import _migrate_schema
            _migrate_schema()
            insp = sa_inspect(_db.engine)
            assert "certificate_policies_json" in {c["name"] for c in insp.get_columns("certificate_authorities")}
            assert "certificate_policies_json" in {c["name"] for c in insp.get_columns("certificate_profiles")}


class TestRoutes:
    def test_form_api_and_detail_pages(self, auth_admin, app, db):
        with app.app_context():
            assert 'name="certificate_policies"' in auth_admin.get("/ca/create").get_data(as_text=True)
            assert 'name="certificate_policies"' in auth_admin.get("/users/profiles/new").get_data(as_text=True)
            r = auth_admin.post("/ca/create", headers=JSON, data={
                "mode": "generate", "name": "API Pol", "cn": "API Pol", "key_type": "EC", "key_size": "256",
                "validity_days": "365", "ca_type": "root", "certificate_policies": POL})
            assert r.status_code == 201, r.data
            body = r.get_json()
            assert body["certificate_policies"] == certificate_policies.parse_entries(POL)
            detail = auth_admin.get(f"/ca/{body['id']}").get_data(as_text=True)
            assert "Certificate Policies" in detail and "1.3.6.1.4.1.99999.1.1" in detail and 'href="https://pki.example/cps"' in detail
            r = auth_admin.post("/certificates/create", headers=JSON, data={
                "ca_id": str(body["id"]), "cn": "www.api.example", "san": "www.api.example",
                "key_type": "EC", "key_size": "256", "validity_days": "30"})
            assert r.status_code == 201, r.data
            cert = r.get_json()
            assert cert["certificate_policies"] == body["certificate_policies"]
            page = auth_admin.get(f"/certificates/{cert['id']}").get_data(as_text=True)
            assert "Certificate Policies" in page and "2.5.29.32.0" in page
            r = auth_admin.post("/ca/create", headers=JSON, data={
                "mode": "generate", "name": "Bad Pol", "cn": "Bad Pol", "key_type": "EC", "key_size": "256",
                "validity_days": "365", "ca_type": "root", "certificate_policies": "not.an.oid"})
            assert r.status_code == 400 and "policy OID" in r.get_json()["error"]

    def test_profile_form_round_trip(self, auth_admin, app, db):
        with app.app_context():
            client = profile_service.lookup("client_auth")
            page = auth_admin.get(f"/users/profiles/{client.id}/edit").get_data(as_text=True)
            assert 'name="certificate_policies"' in page
            form = {"name": client.name, "description": client.description, "enabled": "on", "include_ocsp_aia": "on",
                    "default_validity_days": "365", "certificate_policies": "1.3.6.1.4.1.99999.7.7 https://cps.example/x",
                    "ku_digital_signature": "on", "eku_clientAuth": "on"}
            r = auth_admin.post(f"/users/profiles/{client.id}/edit", data=form)
            assert r.status_code in (302, 200), r.data
            db.session.expire_all()
            assert profile_service.lookup("client_auth").certificate_policies == [{"oid": "1.3.6.1.4.1.99999.7.7", "cps_uri": "https://cps.example/x"}]
            page = auth_admin.get(f"/users/profiles/{client.id}/edit").get_data(as_text=True)
            assert "1.3.6.1.4.1.99999.7.7 https://cps.example/x" in page
