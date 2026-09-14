"""F4: URI and UPN SAN types, shared SAN syntax (services.san), and the G4-4
rule that unknown prefixes are refused instead of becoming DNS names."""
import json

import pytest
from asn1crypto import core as asn1core
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.models.certificate import Certificate
from app.models.certificate_profile import CertificateProfile
from app.services import ca_service, cert_service, csr_service, profile_service, san

JSON = {"Accept": "application/json"}
PASSPHRASE = "test-passphrase"


@pytest.fixture(autouse=True)
def _seed_profiles(app, db):
    with app.app_context():
        profile_service.ensure_builtins()


def _root(name="SAN Root"):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name}, key_type="RSA", key_size=2048,
        validity_days=3650, passphrase=PASSPHRASE)


def _san_ext(cert_model):
    cert = x509.load_pem_x509_certificate(cert_model.certificate_pem.encode())
    return cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value


class TestSyntax:
    @pytest.mark.parametrize("entry,expected", [
        ("example.com", ("dns", "example.com")),
        ("DNS:*.example.com", ("dns", "*.example.com")),
        ("dns:lower.example.com", ("dns", "lower.example.com")),
        ("IP:192.0.2.10", ("ip", "192.0.2.10")),
        ("IP:2001:db8::10", ("ip", "2001:db8::10")),
        ("EMAIL:a@b.example", ("email", "a@b.example")),
        ("URI:https://svc.example.com/id", ("uri", "https://svc.example.com/id")),
        ("uri:spiffe://trust.example/ns/default/sa/web", ("uri", "spiffe://trust.example/ns/default/sa/web")),
        ("UPN:alice@corp.example", ("upn", "alice@corp.example")),
        ("  DNS: padded.example.com ", ("dns", "padded.example.com")),
    ])
    def test_parse_entry(self, entry, expected):
        assert san.parse_entry(entry) == expected

    def test_blank_is_skipped(self):
        assert san.parse_entry("   ") is None
        assert san.build_general_names(["", " ", "a.example.com"]) and len(san.build_general_names(["", "a.example.com"])) == 1

    @pytest.mark.parametrize("entry", ["https://x.example", "bogus:thing", "::1", "IP:", "URI:", "IP:not-an-ip"])
    def test_unknown_or_empty_is_refused(self, entry):
        with pytest.raises(ValueError):
            san.build_general_names([entry])

    def test_unknown_prefix_message_points_at_the_fix(self):
        with pytest.raises(ValueError, match="URI: prefix"):
            san.parse_entry("https://x.example")
        with pytest.raises(ValueError, match="IP: prefix"):
            san.parse_entry("::1")


class TestEncoding:
    def test_uri_and_upn_round_trip(self):
        ext = san.build_extension(["URI:https://svc.example.com/id", "UPN:alice@corp.example"])
        names = list(ext)
        assert isinstance(names[0], x509.UniformResourceIdentifier)
        assert names[0].value == "https://svc.example.com/id"
        assert isinstance(names[1], x509.OtherName)
        assert names[1].type_id == san.UPN_OID
        assert asn1core.UTF8String.load(names[1].value).native == "alice@corp.example"
        assert san.extension_to_strings(ext) == ["URI:https://svc.example.com/id", "UPN:alice@corp.example"]

    def test_unknown_othername_is_dropped_on_decode(self):
        other = x509.OtherName(x509.ObjectIdentifier("1.2.3.4"), b"\x0c\x01x")
        assert san.general_name_to_string(other) is None
        assert san.extension_to_strings(x509.SubjectAlternativeName([other, x509.DNSName("a.example")])) == ["DNS:a.example"]


class TestIssuance:
    def test_certificate_carries_uri_and_upn(self, app, db):
        with app.app_context():
            root = _root()
            cert = cert_service.create_certificate(
                root, {"CN": "alice"}, ["UPN:alice@corp.example", "URI:https://svc.example.com/id",
                                       "IP:2001:db8::10"], 30, PASSPHRASE)
            strings = san.extension_to_strings(_san_ext(cert))
            assert strings == ["UPN:alice@corp.example", "URI:https://svc.example.com/id", "IP:2001:db8::10"]
            assert json.loads(cert.san_json) == ["UPN:alice@corp.example", "URI:https://svc.example.com/id",
                                                 "IP:2001:db8::10"]

    def test_url_without_prefix_is_no_longer_issued_as_dns(self, app, db):
        with app.app_context():
            root = _root()
            with pytest.raises(ValueError, match="URI: prefix"):
                cert_service.create_certificate(root, {"CN": "x"}, ["https://x.example"], 30, PASSPHRASE)
            assert Certificate.query.count() == 0

    def test_route_returns_400_for_unknown_prefix(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            r = auth_admin.post("/certificates/create", data={
                "ca_id": str(root.id), "cn": "x.example", "validity_days": "30",
                "key_type": "RSA", "key_size": "2048", "san": "x.example\nbogus:thing",
            }, headers=JSON)
            assert r.status_code == 400
            assert "Unsupported SAN entry" in r.get_json()["error"]

    def test_generated_csr_and_import_round_trip(self, app, db):
        with app.app_context():
            csr_model, _key, _ = csr_service.create_csr(
                {"CN": "dev"}, ["UPN:dev@corp.example", "URI:spiffe://trust/ns/x", "DNS:dev.example"],
                "RSA", 2048, None)
            imported = csr_service.import_csr(csr_model.csr_pem)
            assert json.loads(imported.san_json) == ["UPN:dev@corp.example", "URI:spiffe://trust/ns/x",
                                                     "DNS:dev.example"]
            root = _root()
            cert = cert_service.sign_csr(imported, root, 30, PASSPHRASE)
            assert "UPN:dev@corp.example" in san.extension_to_strings(_san_ext(cert))

    def test_foreign_csr_with_upn_is_parsed(self, app, db):
        with app.app_context():
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            csr = (x509.CertificateSigningRequestBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "foreign")]))
                   .add_extension(x509.SubjectAlternativeName([
                       x509.OtherName(san.UPN_OID, asn1core.UTF8String("bob@corp.example").dump()),
                       x509.UniformResourceIdentifier("urn:example:bob"),
                   ]), critical=False)
                   .sign(key, hashes.SHA256()))
            pem = csr.public_bytes(serialization.Encoding.PEM).decode()
            subject, sans = csr_service.parse_csr(pem)
            assert sans == ["UPN:bob@corp.example", "URI:urn:example:bob"]


class TestProfiles:
    def test_profile_can_restrict_new_types(self, app, db):
        with app.app_context():
            root = _root()
            web = CertificateProfile.query.filter_by(key="web_server").first()
            web.allowed_san_types_json = json.dumps(["dns"])
            db.session.commit()
            with pytest.raises(ValueError, match="does not allow UPN SANs"):
                cert_service.create_certificate(root, {"CN": "a.example"}, ["a.example", "UPN:a@corp"],
                                                30, PASSPHRASE, profile=web)
            web.allowed_san_types_json = json.dumps(["dns", "upn", "uri"])
            db.session.commit()
            cert = cert_service.create_certificate(root, {"CN": "a.example"},
                                                   ["a.example", "UPN:a@corp", "URI:https://a.example/x"],
                                                   30, PASSPHRASE, profile=web)
            assert cert.id

    def test_profile_form_accepts_the_new_types(self, app, auth_admin, db):
        with app.app_context():
            r = auth_admin.post("/users/profiles/new", data={
                "name": "Workload Identity", "ku_digital_signature": "on", "eku_clientAuth": "on",
                "kt_RSA": "on", "kt_EC": "on", "san_uri": "on", "san_upn": "on", "require_san": "on",
                "default_validity_days": "1", "enabled": "on", "include_ocsp_aia": "on",
            }, headers=JSON)
            assert r.status_code == 201, r.get_json()
            assert r.get_json()["allowed_san_types"] == ["uri", "upn"]
            page = auth_admin.get("/users/profiles/new")
            assert b'name="san_uri"' in page.data and b'name="san_upn"' in page.data
