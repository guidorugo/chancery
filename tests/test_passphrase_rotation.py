"""F18: master-passphrase rotation — the encrypted-column registry, the
rotate/check services, and the `flask keys rotate-passphrase` /
`check-passphrase` commands."""
import pytest
from cryptography.fernet import InvalidToken
from sqlalchemy import LargeBinary

from app.extensions import db as _db
from app.models import __all__ as ALL_MODELS
from app import models as models_pkg
from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.models.certificate import Certificate
from app.models.ldap_settings import LdapSettings
from app.models.webhook_settings import WebhookSettings
from app.services import ca_service, cert_service, crypto_utils, csr_service, passphrase_service

OLD = "test-passphrase"          # TestConfig.MASTER_PASSPHRASE
NEW = "a-much-longer-new-passphrase-2026"


def _seed_everything():
    """One row of every registered ciphertext kind, plus rows that must be left alone."""
    root = ca_service.create_root_ca(name="Rot Root", subject_attrs={"CN": "Rot Root"}, key_type="RSA",
                                     key_size=2048, validity_days=3650, passphrase=OLD)
    leaf = cert_service.create_certificate(root, {"CN": "leaf.example"}, [], 30, OLD)   # escrowed key
    csr_model, _k, _ = csr_service.create_csr({"CN": "signed.example"}, [], "RSA", 2048, None)
    signed = cert_service.sign_csr(csr_model, root, 30, OLD)                            # no key stored
    from tests.test_ca_import import _self_signed_ca
    _key, cert = _self_signed_ca("Offline Root")
    cert_only = ca_service.import_ca("Offline Root", cert.public_bytes(
        __import__("cryptography").hazmat.primitives.serialization.Encoding.PEM).decode(), None, OLD)
    ldap = LdapSettings(id=1, bind_password_enc=crypto_utils.encrypt_secret("bind-pw", OLD))
    hook = WebhookSettings(id=1, secret_enc=crypto_utils.encrypt_secret("hook-secret", OLD))
    _db.session.add_all([ldap, hook])
    from app.services import ocsp_service
    ocsp_service.ensure_responder(root, OLD)   # F7: the delegated responder key is a registered column too
    _db.session.commit()
    return root, leaf, signed, cert_only, ldap, hook


def _snapshot():
    return {
        "ca": {c.id: c.private_key_enc for c in CertificateAuthority.query.all()},
        "cert": {c.id: c.private_key_enc for c in Certificate.query.all()},
        "ldap": {r.id: r.bind_password_enc for r in LdapSettings.query.all()},
        "hook": {r.id: r.secret_enc for r in WebhookSettings.query.all()},
    }


class TestRegistry:
    def test_every_enc_column_is_registered(self, app):
        """Adding a `*_enc` LargeBinary column without registering it must fail here."""
        registered = {(m.__tablename__, col) for m, _a, col, _k in passphrase_service.registered()}
        found = set()
        for name in ALL_MODELS:
            model = getattr(models_pkg, name)
            for column in model.__table__.columns:
                if column.name.endswith("_enc") and isinstance(column.type, LargeBinary):
                    found.add((model.__tablename__, column.name))
        assert found == registered
        assert len(found) >= 4


class TestRewrapHelpers:
    def test_rewrap_keeps_payload_and_changes_salt(self):
        blob = crypto_utils.encrypt_secret("hello", OLD)
        new_blob = crypto_utils.rewrap(blob, OLD, NEW)
        assert new_blob[:16] != blob[:16]
        assert crypto_utils.decrypt_secret(new_blob, NEW) == "hello"
        assert not crypto_utils.can_decrypt(new_blob, OLD)
        with pytest.raises(InvalidToken):
            crypto_utils.rewrap(blob, "wrong", NEW)


class TestRotateService:
    def test_round_trip_every_column_and_untouched_sentinels(self, app, db):
        with app.app_context():
            root, leaf, signed, cert_only, ldap, hook = _seed_everything()
            before = _snapshot()
            stats = passphrase_service.rotate(OLD, NEW)
            db.session.commit()
            assert stats == {"certificate_authorities.private_key_enc": 1,
                             "certificate_authorities.ocsp_responder_key_enc": 1,
                             "certificates.private_key_enc": 1,
                             "ldap_settings.bind_password_enc": 1,
                             "webhook_settings.secret_enc": 1}
            after = _snapshot()
            # rotated blobs changed and open with NEW only
            assert after["ca"][root.id] != before["ca"][root.id]
            assert crypto_utils.decrypt_private_key(after["ca"][root.id], NEW)
            assert not crypto_utils.can_decrypt(after["ca"][root.id], OLD)
            assert crypto_utils.decrypt_private_key(after["cert"][leaf.id], NEW)
            assert crypto_utils.decrypt_secret(after["ldap"][ldap.id], NEW) == "bind-pw"
            assert crypto_utils.decrypt_secret(after["hook"][hook.id], NEW) == "hook-secret"
            assert crypto_utils.decrypt_private_key(db.session.get(CertificateAuthority, root.id).ocsp_responder_key_enc, NEW)
            # sentinels / NULLs untouched
            assert after["ca"][cert_only.id] == b""
            assert after["cert"][signed.id] is None
            # the CA still signs with the new passphrase
            cert = cert_service.create_certificate(root, {"CN": "post.example"}, [], 30, NEW)
            assert cert.id

    def test_wrong_current_passphrase_writes_nothing(self, app, db):
        with app.app_context():
            _seed_everything()
            before = _snapshot()
            with pytest.raises(passphrase_service.PassphraseError, match="does not decrypt"):
                passphrase_service.rotate("not-the-passphrase", NEW)
            db.session.rollback()
            assert _snapshot() == before

    def test_midway_failure_rolls_everything_back(self, app, db, monkeypatch):
        with app.app_context():
            _seed_everything()
            before = _snapshot()
            real = crypto_utils.rewrap
            calls = {"n": 0}

            def flaky(blob, old, new):
                calls["n"] += 1
                if calls["n"] == 3:
                    raise RuntimeError("disk on fire")
                return real(blob, old, new)

            monkeypatch.setattr(crypto_utils, "rewrap", flaky)
            with pytest.raises(RuntimeError, match="disk on fire"):
                passphrase_service.rotate(OLD, NEW)
            db.session.rollback()
            assert _snapshot() == before
            assert all(crypto_utils.can_decrypt(b, OLD) for b in before["ca"].values() if b)

    def test_check_reports_per_column(self, app, db):
        with app.app_context():
            _seed_everything()
            report = {f"{e['table']}.{e['column']}": e for e in passphrase_service.check(OLD)}
            assert report["certificate_authorities.private_key_enc"]["rows"] == 1  # cert-only excluded
            assert all(e["ok"] is True for e in report.values())
            bad = passphrase_service.check("wrong")
            assert all(e["ok"] is False for e in bad)
            empty = passphrase_service.check(OLD)
            assert empty  # no exception on an empty table set either

    @pytest.mark.parametrize("value,msg", [
        ("", "empty"), ("short", "at least 12"), ("dev-passphrase", "insecure"), (OLD, "identical"),
    ])
    def test_new_passphrase_validation(self, value, msg):
        with pytest.raises(passphrase_service.PassphraseError, match=msg):
            passphrase_service.validate_new_passphrase(value, OLD)


class TestCli:
    def test_check_passphrase_ok_and_fail(self, app, db):
        with app.app_context():
            _seed_everything()
            r = app.test_cli_runner().invoke(args=["keys", "check-passphrase"])
            assert r.exit_code == 0, r.output
            assert "OK: the running passphrase" in r.output
            app.config["MASTER_PASSPHRASE"] = "wrong-passphrase"
            try:
                r = app.test_cli_runner().invoke(args=["keys", "check-passphrase"])
                assert r.exit_code != 0
                assert "FAIL" in r.output
            finally:
                app.config["MASTER_PASSPHRASE"] = OLD

    def test_rotate_via_file_then_check_flags_the_unswapped_secret(self, app, db, tmp_path):
        with app.app_context():
            root, *_ = _seed_everything()
            path = tmp_path / "new.txt"
            path.write_text(NEW + "\n")
            r = app.test_cli_runner().invoke(args=["keys", "rotate-passphrase", "--new-file", str(path), "--yes"])
            assert r.exit_code == 0, r.output
            assert "Rotated:" in r.output and "force-recreate" in r.output
            row = AuditLog.query.filter_by(action="rotate_passphrase").first()
            assert row is not None and row.username == "cli"
            db.session.expire_all()
            assert crypto_utils.decrypt_private_key(db.session.get(CertificateAuthority, root.id).private_key_enc, NEW)
            # the running config still holds OLD → check must now fail (the documented swap step)
            r = app.test_cli_runner().invoke(args=["keys", "check-passphrase"])
            assert r.exit_code != 0

    def test_rotate_via_stdin_and_dry_run(self, app, db):
        with app.app_context():
            _seed_everything()
            before = _snapshot()
            r = app.test_cli_runner().invoke(args=["keys", "rotate-passphrase", "--new-file", "-", "--dry-run"],
                                             input=NEW + "\n")
            assert r.exit_code == 0, r.output
            assert "nothing written" in r.output
            db.session.expire_all()
            assert _snapshot() == before
            assert AuditLog.query.filter_by(action="rotate_passphrase").count() == 0

    def test_rotate_refuses_bad_new_values(self, app, db):
        with app.app_context():
            _seed_everything()
            r = app.test_cli_runner().invoke(args=["keys", "rotate-passphrase", "--new-file", "-", "--yes"],
                                             input="short\n")
            assert r.exit_code != 0 and "at least 12" in r.output
            r = app.test_cli_runner().invoke(args=["keys", "rotate-passphrase", "--new-file", "-", "--yes"],
                                             input=OLD + "\n")
            assert r.exit_code != 0 and "identical" in r.output

    def test_rotate_refuses_when_current_passphrase_is_wrong(self, app, db):
        with app.app_context():
            _seed_everything()
            before = _snapshot()
            app.config["MASTER_PASSPHRASE"] = "wrong-passphrase"
            try:
                r = app.test_cli_runner().invoke(args=["keys", "rotate-passphrase", "--new-file", "-", "--yes"],
                                                 input=NEW + "\n")
                assert r.exit_code != 0 and "does not decrypt" in r.output
            finally:
                app.config["MASTER_PASSPHRASE"] = OLD
            db.session.expire_all()
            assert _snapshot() == before
