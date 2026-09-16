"""F2: Name Constraints on CAs — encoding (critical extension), parsing of
imported CAs, RFC 5280 matching, chain enforcement on every issuance path,
and the create form / JSON API."""
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import inspect as sa_inspect

from app.extensions import db as _db
from app.services import ca_service, cert_service, csr_service, name_constraints, profile_service

PASSPHRASE = "test-passphrase"
JSON = {"Accept": "application/json"}


@pytest.fixture(autouse=True)
def _seed_profiles(app, db):
    with app.app_context():
        profile_service.ensure_builtins()


def _root(name="NC Root", permitted=None, excluded=None, **kw):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name}, key_type="EC", key_size=256, validity_days=3650,
        passphrase=PASSPHRASE, constraints=name_constraints.normalise(permitted, excluded), **kw)


def _cert(ca, cn, sans=None, **kw):
    return cert_service.create_certificate(ca, {"CN": cn}, sans if sans is not None else [], 30, PASSPHRASE,
                                           key_type="EC", key_size=256, **kw)


def _x(model):
    return x509.load_pem_x509_certificate(model.certificate_pem.encode())


# ---------------------------------------------------------------------------
# parsing / encoding
# ---------------------------------------------------------------------------

class TestParsing:
    def test_entries_are_validated_and_normalised(self):
        assert name_constraints.parse_entries("DNS:Example.COM.\n\n ip:10.0.0.0/8 \nEMAIL:corp.example\nURI:.example.org") == [
            "DNS:example.com", "IP:10.0.0.0/8", "EMAIL:corp.example", "URI:.example.org"]
        assert name_constraints.normalise("", "") is None
        assert name_constraints.normalise("DNS:a.example", None) == {"permitted": ["DNS:a.example"], "excluded": []}
        for bad in ("UPN:x", "10.0.0.1", "IP:10.0.0.1", "IP:10.0.0.1/8", "DNS:*.example.com", "DNS:", "URI:https://x/",
                    "EMAIL:not valid", "bogus"):
            with pytest.raises(ValueError):
                name_constraints.parse_entries(bad)

    def test_extension_round_trip(self):
        nc = {"permitted": ["DNS:example.com", "IP:10.0.0.0/8", "EMAIL:example.com", "URI:example.com"],
              "excluded": ["DNS:internal.example.com", "IP:2001:db8::/32"]}
        ext = name_constraints.build_extension(nc)
        assert isinstance(ext, x509.NameConstraints)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rt")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1))
                .add_extension(ext, critical=True).sign(key, hashes.SHA256()))
        assert name_constraints.from_certificate(cert) == nc
        assert name_constraints.build_extension(None) is None and name_constraints.from_certificate(_x_plain()) is None


def _x_plain():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "plain")])
    now = datetime.now(timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))


# ---------------------------------------------------------------------------
# matching rules
# ---------------------------------------------------------------------------

class TestMatching:
    def test_dns_rules(self):
        nc = {"permitted": ["DNS:example.com"], "excluded": []}
        for ok in ("example.com", "www.example.com", "a.b.example.com", "*.example.com", "WWW.Example.com"):
            name_constraints.check_names(nc, [("dns", ok)])
        for bad in ("example.org", "notexample.com", "example.com.evil", "*.com"):
            with pytest.raises(ValueError, match="outside"):
                name_constraints.check_names(nc, [("dns", bad)])
        # a leading dot means subdomains only
        sub = {"permitted": ["DNS:.example.com"], "excluded": []}
        name_constraints.check_names(sub, [("dns", "www.example.com")])
        with pytest.raises(ValueError):
            name_constraints.check_names(sub, [("dns", "example.com")])
        # a wildcard must fit entirely inside the constraint
        narrow = {"permitted": ["DNS:sub.example.com"], "excluded": []}
        with pytest.raises(ValueError):
            name_constraints.check_names(narrow, [("dns", "*.example.com")])

    def test_ip_email_uri_rules(self):
        nc = {"permitted": ["IP:10.0.0.0/8", "EMAIL:example.com", "URI:example.com"], "excluded": []}
        name_constraints.check_names(nc, [("ip", "10.1.2.3"), ("email", "bob@example.com"), ("uri", "https://example.com/x")])
        for bad in (("ip", "192.168.1.1"), ("ip", "2001:db8::1"), ("email", "bob@mail.example.com"),
                    ("uri", "https://www.example.com/"), ("uri", "urn:no-host")):
            with pytest.raises(ValueError, match="outside"):
                name_constraints.check_names(nc, [bad])
        mailbox = {"permitted": ["EMAIL:alice@example.com"], "excluded": []}
        name_constraints.check_names(mailbox, [("email", "Alice@Example.com")])
        with pytest.raises(ValueError):
            name_constraints.check_names(mailbox, [("email", "bob@example.com")])
        subs = {"permitted": ["EMAIL:.example.com", "URI:.example.com"], "excluded": []}
        name_constraints.check_names(subs, [("email", "x@mail.example.com"), ("uri", "http://a.example.com")])
        with pytest.raises(ValueError):
            name_constraints.check_names(subs, [("email", "x@example.com")])

    def test_excluded_wins_and_unlisted_types_are_free(self):
        nc = {"permitted": ["DNS:example.com"], "excluded": ["DNS:secret.example.com", "IP:10.0.0.0/8"]}
        name_constraints.check_names(nc, [("dns", "www.example.com"), ("ip", "192.168.0.1"), ("email", "a@b.c")])
        with pytest.raises(ValueError, match="excluded"):
            name_constraints.check_names(nc, [("dns", "db.secret.example.com")])
        with pytest.raises(ValueError, match="excluded"):
            name_constraints.check_names(nc, [("ip", "10.9.9.9")])

    def test_requested_names_include_a_hostname_like_cn(self):
        names = name_constraints.requested_names({"CN": "Web.Example.com"}, ["DNS:a.example.com", "IP:10.0.0.5", "UPN:u@d"])
        assert names == [("dns", "a.example.com"), ("ip", "10.0.0.5"), ("dns", "web.example.com")]
        assert name_constraints.requested_names({"CN": "Alice Smith"}, []) == []
        assert name_constraints.requested_names({"CN": "localhost"}, []) == []      # single label is not a hostname


# ---------------------------------------------------------------------------
# CA creation, import and enforcement through the services
# ---------------------------------------------------------------------------

class TestEnforcement:
    def test_root_carries_a_critical_extension_and_enforces(self, app, db):
        with app.app_context():
            root = _root(permitted="DNS:example.com\nIP:10.0.0.0/8", excluded="DNS:internal.example.com")
            ext = _x(root).extensions.get_extension_for_class(x509.NameConstraints)
            assert ext.critical
            assert [n.value for n in ext.value.permitted_subtrees if isinstance(n, x509.DNSName)] == ["example.com"]
            assert root.name_constraints == {"permitted": ["DNS:example.com", "IP:10.0.0.0/8"],
                                             "excluded": ["DNS:internal.example.com"]}
            assert root.to_dict()["name_constraints"] == root.name_constraints
            ok = _cert(root, "www.example.com", ["www.example.com", "IP:10.2.3.4"])
            _x(ok).verify_directly_issued_by(_x(root))
            with pytest.raises(ValueError, match="outside CA 'NC Root'"):
                _cert(root, "www.example.org", ["www.example.org"])
            with pytest.raises(ValueError, match="excluded"):
                _cert(root, "db.internal.example.com", ["db.internal.example.com"])
            with pytest.raises(ValueError, match="IP name '192.168.1.1'"):
                _cert(root, "www.example.com", ["www.example.com", "IP:192.168.1.1"])
            with pytest.raises(ValueError, match="DNS name 'evil.example.org'"):
                _cert(root, "evil.example.org")            # the CN alone is a hostname
            _cert(root, "Alice Smith", ["EMAIL:alice@anywhere.example"])  # no constraint of that type → free

    def test_constraints_apply_down_the_chain_and_to_sub_cas(self, app, db):
        with app.app_context():
            root = _root(permitted="DNS:example.com")
            inter = ca_service.create_intermediate_ca("NC Inter", root, {"CN": "NC Inter"}, "EC", 256, 365, PASSPHRASE,
                                                      constraints=name_constraints.normalise("DNS:eu.example.com", None))
            assert inter.name_constraints["permitted"] == ["DNS:eu.example.com"]
            _cert(inter, "www.eu.example.com", ["www.eu.example.com"])
            with pytest.raises(ValueError, match="CA 'NC Inter'"):
                _cert(inter, "www.example.com", ["www.example.com"])      # inside the root's, outside the intermediate's
            with pytest.raises(ValueError, match="CA 'NC Root'"):
                ca_service.create_intermediate_ca("Rogue", root, {"CN": "ca.example.org"}, "EC", 256, 365, PASSPHRASE)
            ca_service.create_intermediate_ca("Named CA", root, {"CN": "Named Issuing CA"}, "EC", 256, 365, PASSPHRASE)

    def test_csr_signing_and_renewal_are_checked(self, app, db):
        with app.app_context():
            root = _root(permitted="DNS:example.com")
            csr_model, _k, _ = csr_service.create_csr({"CN": "bad.example.org"}, ["bad.example.org"], "EC", 256, None)
            db.session.commit()
            with pytest.raises(ValueError, match="outside"):
                cert_service.sign_csr(csr_model, root, 30, PASSPHRASE)
            db.session.expire_all()
            assert csr_model.status == "pending"                          # nothing was claimed
            good_csr, _k, _ = csr_service.create_csr({"CN": "ok.example.com"}, ["ok.example.com"], "EC", 256, None)
            db.session.commit()
            cert = cert_service.sign_csr(good_csr, root, 30, PASSPHRASE)
            renewed = cert_service.renew_certificate(cert, PASSPHRASE)
            db.session.commit()
            assert renewed.renewed_from_id == cert.id

    def test_profiles_and_constraints_compose(self, app, db):
        with app.app_context():
            root = _root(permitted="DNS:example.com")
            web = profile_service.lookup("web_server")
            with pytest.raises(ValueError, match="outside"):
                _cert(root, "www.example.org", ["www.example.org"], profile=web)
            web.allowed_san_types_json = '["ip"]'
            db.session.commit()
            with pytest.raises(ValueError, match="does not allow"):
                _cert(root, "www.example.com", ["www.example.com"], profile=web)   # constraint ok, profile refuses
            web.allowed_san_types_json = None
            db.session.commit()

    def test_imported_ca_constraints_are_stored_and_enforced(self, app, db):
        with app.app_context():
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Imported NC Root")])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=365))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                    .add_extension(x509.NameConstraints(
                        permitted_subtrees=[x509.DNSName("corp.example"), x509.DirectoryName(name)],
                        excluded_subtrees=None), critical=True)
                    .sign(key, hashes.SHA256()))
            ca = ca_service.import_ca("Imported NC Root", cert.public_bytes(serialization.Encoding.PEM).decode(),
                                      key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()).decode(), PASSPHRASE)
            assert ca.name_constraints == {"permitted": ["DNS:corp.example", "other:DirectoryName"], "excluded": []}
            _cert(ca, "host.corp.example", ["host.corp.example"])
            with pytest.raises(ValueError, match="outside"):
                _cert(ca, "host.other.example", ["host.other.example"])

    def test_openssl_accepts_a_leaf_under_the_constrained_chain(self, app, db):
        if not shutil.which("openssl"):
            pytest.skip("openssl CLI not available")
        with app.app_context():
            root = _root(permitted="DNS:example.com\nIP:10.0.0.0/8")
            inter = ca_service.create_intermediate_ca("NC Inter", root, {"CN": "NC Inter"}, "EC", 256, 365, PASSPHRASE)
            leaf = _cert(inter, "www.example.com", ["www.example.com", "IP:10.0.0.7"])
            with tempfile.TemporaryDirectory() as d:
                for n, model in (("root", root), ("inter", inter), ("leaf", leaf)):
                    open(os.path.join(d, f"{n}.pem"), "w").write(model.certificate_pem)
                r = subprocess.run(["openssl", "verify", "-CAfile", os.path.join(d, "root.pem"), "-untrusted",
                                    os.path.join(d, "inter.pem"), os.path.join(d, "leaf.pem")], capture_output=True, text=True)
                assert r.returncode == 0, r.stdout + r.stderr

    def test_migration_adds_the_column(self, app, db):
        with app.app_context():
            from app import _migrate_schema
            _migrate_schema()
            assert "name_constraints_json" in {c["name"] for c in sa_inspect(_db.engine).get_columns("certificate_authorities")}


# ---------------------------------------------------------------------------
# form / API
# ---------------------------------------------------------------------------

class TestRoutes:
    def test_form_has_the_fields_and_detail_shows_them(self, auth_admin, app, db):
        with app.app_context():
            page = auth_admin.get("/ca/create").get_data(as_text=True)
            assert 'name="nc_permitted"' in page and 'name="nc_excluded"' in page
            root = _root(permitted="DNS:example.com", excluded="IP:10.0.0.0/8")
            detail = auth_admin.get(f"/ca/{root.id}").get_data(as_text=True)
            assert "Name Constraints" in detail and "DNS:example.com" in detail and "IP:10.0.0.0/8" in detail
            plain = _root("Plain Root")
            assert "<td>\n                        None" in auth_admin.get(f"/ca/{plain.id}").get_data(as_text=True) or \
                "None" in auth_admin.get(f"/ca/{plain.id}").get_data(as_text=True)

    def test_api_create_with_constraints_and_bad_entries(self, auth_admin, app, db):
        with app.app_context():
            r = auth_admin.post("/ca/create", headers=JSON, data={
                "mode": "generate", "name": "API NC", "cn": "API NC", "key_type": "EC", "key_size": "256",
                "validity_days": "365", "ca_type": "root", "nc_permitted": "DNS:api.example\nIP:10.0.0.0/8",
                "nc_excluded": "DNS:private.api.example"})
            assert r.status_code == 201, r.data
            body = r.get_json()
            assert body["name_constraints"] == {"permitted": ["DNS:api.example", "IP:10.0.0.0/8"],
                                                "excluded": ["DNS:private.api.example"]}
            r = auth_admin.post("/certificates/create", headers=JSON, data={
                "ca_id": str(body["id"]), "cn": "www.api.example", "san": "www.api.example\nIP:10.0.0.9",
                "key_type": "EC", "key_size": "256", "validity_days": "30"})
            assert r.status_code == 201, r.data
            r = auth_admin.post("/certificates/create", headers=JSON, data={
                "ca_id": str(body["id"]), "cn": "www.private.api.example", "san": "www.private.api.example",
                "key_type": "EC", "key_size": "256", "validity_days": "30"})
            assert r.status_code == 400 and "excluded" in r.get_json()["error"]
            r = auth_admin.post("/ca/create", headers=JSON, data={
                "mode": "generate", "name": "Bad NC", "cn": "Bad NC", "key_type": "EC", "key_size": "256",
                "validity_days": "365", "ca_type": "root", "nc_permitted": "IP:10.0.0.1"})
            assert r.status_code == 400 and "CIDR" in r.get_json()["error"]
