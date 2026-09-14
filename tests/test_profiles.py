"""Certificate profiles (F1, 2.13.0): seeding, admin CRUD, server-side
enforcement on both issuance paths, CA allow-lists, CSR carry-over, the
JSON API and CLI export/import, plus the G7-1 RSA size ceiling."""
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlalchemy import inspect as sa_inspect

from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.models.certificate import Certificate
from app.models.certificate_profile import CertificateProfile
from app.models.csr import CertificateSigningRequest
from app.services import ca_service, cert_service, csr_service, profile_service
from app.services.policy import enforce_key_strength, enforce_public_key_strength

JSON = {"Accept": "application/json"}
PASSPHRASE = "test-passphrase"


@pytest.fixture(autouse=True)
def _seed_profiles(app, db):
    """The per-test `db` fixture recreates every table, dropping the built-ins
    seeded at app start — re-seed so each test starts like a real boot."""
    with app.app_context():
        profile_service.ensure_builtins()


def _root(name="Profile Root"):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name}, key_type="RSA", key_size=2048,
        validity_days=3650, passphrase=PASSPHRASE)


def _profile(key):
    profile_service.ensure_builtins()
    return CertificateProfile.query.filter_by(key=key).first()


def _csr(profile_id=None, cn="csr.example.com", sans=None):
    csr_model, _key, _ = csr_service.create_csr(
        {"CN": cn}, sans if sans is not None else [cn], "RSA", 2048, None, profile_id=profile_id)
    _db.session.commit()
    return csr_model


def _cert_eku(cert_model):
    cert = x509.load_pem_x509_certificate(cert_model.certificate_pem.encode())
    return list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)


def _cert_ku(cert_model):
    cert = x509.load_pem_x509_certificate(cert_model.certificate_pem.encode())
    return cert.extensions.get_extension_for_class(x509.KeyUsage).value


def _has_aia(cert_model):
    cert = x509.load_pem_x509_certificate(cert_model.certificate_pem.encode())
    try:
        cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        return True
    except x509.ExtensionNotFound:
        return False


# ---------------------------------------------------------------------------
# seeding + schema
# ---------------------------------------------------------------------------

class TestSeeding:
    def test_builtins_seeded_and_idempotent(self, app, db):
        with app.app_context():
            first = profile_service.ensure_builtins()
            again = profile_service.ensure_builtins()
            assert again == []
            keys = {p.key for p in profile_service.list_profiles()}
            assert keys == {"web_server", "client_auth", "email", "code_signing", "custom"}
            assert all(p.is_builtin for p in profile_service.list_profiles())
            assert first == [] or set(first) <= keys

    def test_operator_edits_to_a_builtin_survive_reseeding(self, app, db):
        with app.app_context():
            web = _profile("web_server")
            web.max_validity_days = 90
            db.session.commit()
            profile_service.ensure_builtins()
            assert _profile("web_server").max_validity_days == 90

    def test_migration_added_the_columns(self, app, db):
        with app.app_context():
            from app import _migrate_schema
            _migrate_schema()
            insp = sa_inspect(_db.engine)
            assert "profile_id" in {c["name"] for c in insp.get_columns("certificates")}
            assert "profile_id" in {c["name"] for c in insp.get_columns("certificate_signing_requests")}
            assert "allowed_profiles_json" in {c["name"] for c in insp.get_columns("certificate_authorities")}


# ---------------------------------------------------------------------------
# enforcement — direct issuance
# ---------------------------------------------------------------------------

class TestEnforcementOnCreate:
    def test_legacy_request_without_profile_is_unchanged(self, app, db):
        with app.app_context():
            root = _root()
            cert = cert_service.create_certificate(
                root, {"CN": "legacy.example.com"}, [], 365, PASSPHRASE,
                key_usage={"digital_signature": True, "key_encipherment": False,
                           "content_commitment": True, "data_encipherment": False,
                           "key_agreement": False},
                extended_key_usage=["codeSigning"])
            assert cert.profile_id is None
            assert _cert_eku(cert) == [ExtendedKeyUsageOID.CODE_SIGNING]
            assert _cert_ku(cert).content_commitment is True

    def test_named_profile_overrides_posted_key_usage(self, app, db):
        with app.app_context():
            root = _root()
            client = _profile("client_auth")
            cert = cert_service.create_certificate(
                root, {"CN": "user1"}, [], 365, PASSPHRASE, profile=client,
                key_usage={"digital_signature": True, "key_encipherment": True,
                           "content_commitment": True, "data_encipherment": True,
                           "key_agreement": True},
                extended_key_usage=["serverAuth", "codeSigning"])
            assert cert.profile_id == client.id
            assert _cert_eku(cert) == [ExtendedKeyUsageOID.CLIENT_AUTH]
            ku = _cert_ku(cert)
            assert ku.digital_signature and not ku.key_encipherment and not ku.content_commitment

    def test_custom_profile_honours_posted_key_usage(self, app, db):
        with app.app_context():
            root = _root()
            cert = cert_service.create_certificate(
                root, {"CN": "custom.example.com"}, [], 365, PASSPHRASE,
                profile=_profile("custom"), extended_key_usage=["timeStamping"])
            assert cert.profile.key == "custom"
            assert _cert_eku(cert) == [ExtendedKeyUsageOID.TIME_STAMPING]

    def test_validity_above_profile_max_is_refused(self, app, db):
        with app.app_context():
            root = _root()
            web = _profile("web_server")
            web.max_validity_days = 90
            db.session.commit()
            with pytest.raises(ValueError, match="at most 90 days"):
                cert_service.create_certificate(root, {"CN": "a.example.com"}, [], 91,
                                                PASSPHRASE, profile=web)
            cert = cert_service.create_certificate(root, {"CN": "a.example.com"}, [], 90,
                                                   PASSPHRASE, profile=web)
            assert cert.id

    def test_key_type_and_size_bounds(self, app, db):
        with app.app_context():
            root = _root()
            web = _profile("web_server")
            web.allowed_key_types_json = json.dumps(["EC"])
            db.session.commit()
            with pytest.raises(ValueError, match="does not allow RSA"):
                cert_service.create_certificate(root, {"CN": "x"}, [], 30, PASSPHRASE, profile=web)
            web.allowed_key_types_json = json.dumps(["RSA"])
            web.min_rsa_bits = 4096
            db.session.commit()
            with pytest.raises(ValueError, match="at least 4096"):
                cert_service.create_certificate(root, {"CN": "x"}, [], 30, PASSPHRASE,
                                                key_type="RSA", key_size=2048, profile=web)
            web.min_rsa_bits = None
            web.allowed_key_types_json = json.dumps(["EC"])
            web.allowed_ec_sizes_json = json.dumps([384])
            db.session.commit()
            with pytest.raises(ValueError, match="EC curves of size 384"):
                cert_service.create_certificate(root, {"CN": "x"}, [], 30, PASSPHRASE,
                                                key_type="EC", key_size=256, profile=web)

    def test_san_type_restrictions(self, app, db):
        with app.app_context():
            root = _root()
            web = _profile("web_server")
            web.allowed_san_types_json = json.dumps(["dns"])
            web.require_san = True
            web.cn_in_san = True
            db.session.commit()
            with pytest.raises(ValueError, match="requires at least one"):
                cert_service.create_certificate(root, {"CN": "a.example.com"}, [], 30,
                                                PASSPHRASE, profile=web)
            with pytest.raises(ValueError, match="does not allow IP SANs"):
                cert_service.create_certificate(root, {"CN": "a.example.com"},
                                                ["a.example.com", "IP:10.0.0.1"], 30,
                                                PASSPHRASE, profile=web)
            with pytest.raises(ValueError, match="Common Name"):
                cert_service.create_certificate(root, {"CN": "a.example.com"},
                                                ["b.example.com"], 30, PASSPHRASE, profile=web)
            cert = cert_service.create_certificate(root, {"CN": "a.example.com"},
                                                   ["DNS:a.example.com"], 30, PASSPHRASE, profile=web)
            assert cert.id

    def test_profile_can_omit_the_aia_extension(self, app, db):
        with app.app_context():
            root = _root()
            web = _profile("web_server")
            with_aia = cert_service.create_certificate(
                root, {"CN": "aia.example.com"}, [], 30, PASSPHRASE, profile=web,
                ocsp_url="http://ca.example.com/public/ocsp/1")
            assert _has_aia(with_aia)
            web.include_ocsp_aia = False
            db.session.commit()
            without = cert_service.create_certificate(
                root, {"CN": "noaia.example.com"}, [], 30, PASSPHRASE, profile=web,
                ocsp_url="http://ca.example.com/public/ocsp/1")
            assert not _has_aia(without)


# ---------------------------------------------------------------------------
# resolution: CA allow-list, disabled, required
# ---------------------------------------------------------------------------

class TestResolution:
    def test_absent_profile_resolves_to_custom(self, app, db):
        with app.app_context():
            assert profile_service.resolve(None).key == "custom"
            assert profile_service.resolve("  ").key == "custom"

    def test_lookup_by_id_key_or_name(self, app, db):
        with app.app_context():
            web = _profile("web_server")
            assert profile_service.resolve(str(web.id)).id == web.id
            assert profile_service.resolve("web_server").id == web.id
            assert profile_service.resolve("Web Server").id == web.id
            with pytest.raises(ValueError, match="Unknown"):
                profile_service.resolve("nope")

    def test_disabled_profile_is_refused(self, app, db):
        with app.app_context():
            web = _profile("web_server")
            web.enabled = False
            db.session.commit()
            with pytest.raises(ValueError, match="disabled"):
                profile_service.resolve("web_server")

    def test_ca_allow_list(self, app, db):
        with app.app_context():
            root = _root()
            client = _profile("client_auth")
            root.set_allowed_profile_ids([client.id])
            db.session.commit()
            assert root.allowed_profile_ids == [client.id]
            assert profile_service.resolve("client_auth", root).id == client.id
            with pytest.raises(ValueError, match="not allowed for CA"):
                profile_service.resolve("web_server", root)
            with pytest.raises(ValueError, match="not allowed for CA"):
                profile_service.resolve(None, root)  # custom is not on the list either
            root.set_allowed_profile_ids(None)
            db.session.commit()
            assert profile_service.resolve("web_server", root).key == "web_server"

    def test_profiles_require_selection(self, app, db):
        app.config["PROFILES_REQUIRE_SELECTION"] = True
        try:
            with app.app_context():
                with pytest.raises(ValueError, match="required"):
                    profile_service.resolve(None)
                assert profile_service.resolve("custom").key == "custom"
        finally:
            app.config["PROFILES_REQUIRE_SELECTION"] = False


# ---------------------------------------------------------------------------
# routes: direct create, CSR create/sign, CA allow-list
# ---------------------------------------------------------------------------

class TestRoutes:
    def test_create_route_records_profile_and_ignores_checkboxes(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            r = auth_admin.post("/certificates/create", data={
                "ca_id": str(root.id), "cn": "web.example.com", "validity_days": "30",
                "key_type": "RSA", "key_size": "2048", "profile": "client_auth",
                "ku_key_encipherment": "on", "eku_serverAuth": "on",
            }, headers=JSON)
            assert r.status_code == 201, r.get_json()
            body = r.get_json()
            assert body["profile"] == "client_auth"
            cert = db.session.get(Certificate, body["id"])
            assert _cert_eku(cert) == [ExtendedKeyUsageOID.CLIENT_AUTH]
            row = AuditLog.query.filter_by(action="create_certificate", target_id=cert.id).first()
            assert json.loads(row.details)["profile"] == "client_auth"

    def test_create_route_refuses_disallowed_profile_for_ca(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            root.set_allowed_profile_ids([_profile("email").id])
            db.session.commit()
            r = auth_admin.post("/certificates/create", data={
                "ca_id": str(root.id), "cn": "x.example.com", "validity_days": "30",
                "key_type": "RSA", "key_size": "2048", "profile": "web_server",
            }, headers=JSON)
            assert r.status_code == 400
            assert "not allowed for CA" in r.get_json()["error"]
            assert Certificate.query.count() == 0

    def test_create_route_without_profile_uses_custom(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            r = auth_admin.post("/certificates/create", data={
                "ca_id": str(root.id), "cn": "legacy.example.com", "validity_days": "30",
                "key_type": "RSA", "key_size": "2048",
            }, headers=JSON)
            assert r.status_code == 201
            assert r.get_json()["profile"] == "custom"

    def test_csr_carries_requested_profile_to_sign_page(self, app, auth_admin, db):
        with app.app_context():
            r = auth_admin.post("/csr/create", data={
                "mode": "generate", "cn": "req.example.com", "key_type": "RSA",
                "key_size": "2048", "profile": "email",
            }, headers=JSON)
            assert r.status_code == 201
            csr_id = r.get_json()["id"]
            assert r.get_json()["profile"] == "email"
            page = auth_admin.get(f"/csr/{csr_id}/sign")
            assert b'value="email" selected' in page.data
            detail = auth_admin.get(f"/csr/{csr_id}")
            assert b"Requested Profile" in detail.data

    def test_csr_unknown_profile_is_400(self, app, auth_admin, db):
        with app.app_context():
            r = auth_admin.post("/csr/create", data={
                "mode": "generate", "cn": "x", "key_type": "RSA", "key_size": "2048",
                "profile": "nope"}, headers=JSON)
            assert r.status_code == 400
            assert CertificateSigningRequest.query.count() == 0

    def test_sign_uses_requested_profile_by_default_and_audits_changes(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            email = _profile("email")
            csr = _csr(profile_id=email.id)
            r = auth_admin.post(f"/csr/{csr.id}/sign", data={"ca_id": str(root.id),
                                                            "validity_days": "30"}, headers=JSON)
            assert r.status_code == 201, r.get_json()
            cert = db.session.get(Certificate, r.get_json()["id"])
            assert cert.profile_id == email.id
            assert _cert_eku(cert) == [ExtendedKeyUsageOID.EMAIL_PROTECTION]

            csr2 = _csr(profile_id=email.id, cn="second.example.com")
            r2 = auth_admin.post(f"/csr/{csr2.id}/sign", data={
                "ca_id": str(root.id), "validity_days": "30", "profile": "client_auth"}, headers=JSON)
            assert r2.status_code == 201
            row = AuditLog.query.filter_by(action="sign_csr", target_id=csr2.id).first()
            details = json.loads(row.details)
            assert details["profile"] == "client_auth"
            assert details["profile_changed"] == {"from": "email", "to": "client_auth"}

    def test_sign_enforces_profile_against_the_csr_key(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            web = _profile("web_server")
            web.allowed_key_types_json = json.dumps(["EC"])
            db.session.commit()
            csr = _csr()  # RSA key
            r = auth_admin.post(f"/csr/{csr.id}/sign", data={
                "ca_id": str(root.id), "validity_days": "30", "profile": "web_server"}, headers=JSON)
            assert r.status_code == 400
            assert "does not allow RSA" in r.get_json()["error"]
            db.session.refresh(csr)
            assert csr.status == "pending"

    def test_ca_allow_list_set_at_creation_and_on_detail(self, app, auth_admin, db):
        with app.app_context():
            client = _profile("client_auth")
            r = auth_admin.post("/ca/create", data={
                "mode": "generate", "name": "Restricted", "cn": "Restricted", "key_type": "RSA",
                "key_size": "2048", "validity_days": "365", "ca_type": "root",
                "restrict_profiles": "on", "allowed_profiles": str(client.id),
            }, headers=JSON)
            assert r.status_code == 201, r.get_json()
            assert r.get_json()["allowed_profiles"] == [client.id]
            ca_id = r.get_json()["id"]

            r2 = auth_admin.post(f"/ca/{ca_id}/profiles", data={}, headers=JSON)
            assert r2.status_code == 200
            assert r2.get_json()["allowed_profiles"] is None
            assert AuditLog.query.filter_by(action="update_ca_profiles", target_id=ca_id).count() == 1

            r3 = auth_admin.post(f"/ca/{ca_id}/profiles", data={"restrict_profiles": "on"}, headers=JSON)
            assert r3.status_code == 400  # restriction on but nothing ticked

    def test_create_form_renders_profiles_from_the_database(self, app, auth_admin, db):
        with app.app_context():
            _root()
            profile_service.create({"name": "VPN Client", "key_usage": {"digital_signature": True},
                                    "extended_key_usage": ["clientAuth"]})
            db.session.commit()
            r = auth_admin.get("/certificates/create")
            assert r.status_code == 200
            assert b'value="vpn_client"' in r.data
            assert b'value="web_server" selected' in r.data
            assert b"caAllowedProfiles" in r.data


# ---------------------------------------------------------------------------
# admin CRUD (Preferences → Profiles)
# ---------------------------------------------------------------------------

class TestAdminCrud:
    def test_requires_admin(self, auth_csr_requester):
        assert auth_csr_requester.get("/users/profiles", headers=JSON).status_code == 403
        assert auth_csr_requester.post("/users/profiles/new", data={"name": "x"},
                                       headers=JSON).status_code == 403

    def test_list_json(self, app, auth_admin, db):
        with app.app_context():
            r = auth_admin.get("/users/profiles", headers=JSON)
            assert r.status_code == 200
            keys = {p["key"] for p in r.get_json()}
            assert "custom" in keys and "web_server" in keys

    def test_create_edit_toggle_delete(self, app, auth_admin, db):
        with app.app_context():
            r = auth_admin.post("/users/profiles/new", data={
                "name": "IoT Device", "description": "mTLS devices",
                "ku_digital_signature": "on", "eku_clientAuth": "on",
                "kt_EC": "on", "ec_256": "on", "san_dns": "on",
                "default_validity_days": "180", "max_validity_days": "365",
                "require_san": "on", "enabled": "on", "include_ocsp_aia": "on",
            }, headers=JSON)
            assert r.status_code == 201, r.get_json()
            body = r.get_json()
            pid = body["id"]
            assert body["key"] == "iot_device"
            assert body["allowed_key_types"] == ["EC"]
            assert body["allowed_ec_sizes"] == [256]
            assert body["allowed_san_types"] == ["dns"]
            assert body["max_validity_days"] == 365
            assert AuditLog.query.filter_by(action="create_profile", target_id=pid).count() == 1

            r = auth_admin.post(f"/users/profiles/{pid}/edit", data={
                "name": "IoT Device", "ku_digital_signature": "on", "eku_clientAuth": "on",
                "kt_RSA": "on", "kt_EC": "on", "default_validity_days": "90",
                "max_validity_days": "60", "enabled": "on", "include_ocsp_aia": "on",
            }, headers=JSON)
            assert r.status_code == 400
            assert "default validity cannot exceed" in r.get_json()["error"]

            r = auth_admin.post(f"/users/profiles/{pid}/edit", data={
                "name": "IoT Device v2", "ku_digital_signature": "on", "eku_clientAuth": "on",
                "kt_RSA": "on", "kt_EC": "on", "default_validity_days": "90",
                "enabled": "on", "include_ocsp_aia": "on",
            }, headers=JSON)
            assert r.status_code == 200
            assert r.get_json()["name"] == "IoT Device v2"
            assert r.get_json()["max_validity_days"] is None

            r = auth_admin.post(f"/users/profiles/{pid}/toggle", headers=JSON)
            assert r.status_code == 200 and r.get_json()["enabled"] is False

            r = auth_admin.post(f"/users/profiles/{pid}/delete", headers=JSON)
            assert r.status_code == 200
            assert db.session.get(CertificateProfile, pid) is None

    def test_builtin_cannot_be_deleted_and_used_profile_cannot_be_deleted(self, app, auth_admin, db):
        with app.app_context():
            web = _profile("web_server")
            r = auth_admin.post(f"/users/profiles/{web.id}/delete", headers=JSON)
            assert r.status_code == 409
            new = profile_service.create({"name": "Used", "key_usage": {"digital_signature": True},
                                          "extended_key_usage": ["clientAuth"]})
            db.session.commit()
            root = _root()
            cert_service.create_certificate(root, {"CN": "u"}, [], 30, PASSPHRASE, profile=new)
            r = auth_admin.post(f"/users/profiles/{new.id}/delete", headers=JSON)
            assert r.status_code == 409
            assert "referenced by 1 certificate" in r.get_json()["error"]

    def test_validation_rejects_empty_key_usage_and_duplicate_name(self, app, auth_admin, db):
        with app.app_context():
            r = auth_admin.post("/users/profiles/new", data={"name": "Web Server", "eku_clientAuth": "on",
                                                              "enabled": "on"}, headers=JSON)
            assert r.status_code == 400
            err = r.get_json()["error"]
            assert "already exists" in err and "At least one Key Usage" in err

    def test_custom_profile_edit_keeps_it_unrestricted(self, app, auth_admin, db):
        with app.app_context():
            custom = _profile("custom")
            r = auth_admin.post(f"/users/profiles/{custom.id}/edit", data={
                "name": "Custom", "enabled": "on", "include_ocsp_aia": "on",
                "default_validity_days": "365", "ku_digital_signature": "on", "eku_clientAuth": "on",
            }, headers=JSON)
            assert r.status_code == 200
            assert r.get_json()["key_usage"] is None
            assert r.get_json()["extended_key_usage"] is None


# ---------------------------------------------------------------------------
# CLI export / import
# ---------------------------------------------------------------------------

class TestCli:
    def test_export_import_round_trip(self, app, db, tmp_path):
        with app.app_context():
            profile_service.create({"name": "Exported", "key_usage": {"digital_signature": True},
                                    "extended_key_usage": ["clientAuth"], "max_validity_days": 10})
            db.session.commit()
            result = app.test_cli_runner().invoke(args=["profiles", "export"])
            assert result.exit_code == 0, result.output
            items = json.loads(result.output)
            assert any(i["key"] == "exported" and i["max_validity_days"] == 10 for i in items)

            db.session.delete(CertificateProfile.query.filter_by(key="exported").first())
            db.session.commit()
            path = tmp_path / "profiles.json"
            path.write_text(json.dumps(items))
            result = app.test_cli_runner().invoke(args=["profiles", "import", str(path)])
            assert result.exit_code == 0, result.output
            assert "1 created" in result.output
            assert CertificateProfile.query.filter_by(key="exported").first().max_validity_days == 10
            assert AuditLog.query.filter_by(action="import_profiles").count() == 1

            result = app.test_cli_runner().invoke(args=["profiles", "list"])
            assert result.exit_code == 0 and "exported" in result.output


# ---------------------------------------------------------------------------
# G7-1 second half — RSA size ceiling
# ---------------------------------------------------------------------------

class TestRsaCeiling:
    def test_generation_ceiling(self, app):
        with app.app_context():
            with pytest.raises(ValueError, match="at most 8192"):
                enforce_key_strength("RSA", 16384)
            enforce_key_strength("RSA", 8192)

    def test_public_key_ceiling_applies_to_csr_import(self, app, db, auth_admin):
        app.config["MAX_RSA_KEY_SIZE"] = 2048
        try:
            with app.app_context():
                big = rsa.generate_private_key(public_exponent=65537, key_size=3072)
                with pytest.raises(ValueError, match="too large"):
                    enforce_public_key_strength(big.public_key())
                r = auth_admin.post("/csr/create", data={
                    "mode": "generate", "cn": "big", "key_type": "RSA", "key_size": "3072"},
                    headers=JSON)
                assert r.status_code == 400
                assert "at most 2048" in r.get_json()["error"]
        finally:
            app.config["MAX_RSA_KEY_SIZE"] = 8192
