"""2.27.1: a revoked CA's name can be reused; an active CA's cannot (friendly
400, DB-enforced by a partial unique index); a raced duplicate is a 409 and
never a 500 (the form re-render used to hit PendingRollbackError); the legacy
table-level UNIQUE(name) is removed by a one-time table rebuild on upgrade;
the demo seeder's --remove takes a demo CA's dependants with it."""
import importlib.util
import pathlib
import re

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.schema import CreateTable

from app import _migrate_schema
from app.extensions import db as _db
from app.models.ca import CertificateAuthority
from app.models.certificate import Certificate
from app.models.csr import CertificateSigningRequest
from app.services import ca_service, cert_service, crl_service, csr_service

PASSPHRASE = "test-passphrase"
JSON = {"Accept": "application/json"}


def _root(name, key_type="EC", key_size=256):
    return ca_service.create_root_ca(name=name, subject_attrs={"CN": name}, key_type=key_type,
                                     key_size=key_size, validity_days=3650, passphrase=PASSPHRASE)


def _revoke(ca):
    crl_service.revoke_ca(ca.id, "cessation_of_operation", passphrase=PASSPHRASE)
    _db.session.commit()


def _indexes(table="certificate_authorities"):
    rows = _db.session.execute(text(f"PRAGMA index_list({table})")).fetchall()
    return {r[1]: {"unique": bool(r[2]), "origin": r[3],
                   "cols": [c[2] for c in _db.session.execute(text(f"PRAGMA index_info({r[1]})")).fetchall()]}
            for r in rows}


class TestService:
    def test_revoked_name_can_be_reused_active_cannot(self, app, db):
        old = _root("Kigen Prod")
        with pytest.raises(ValueError, match=r"already exists \(#%d\)" % old.id):
            _root("Kigen Prod")
        with pytest.raises(ValueError, match="already exists"):
            ca_service.create_intermediate_ca("Kigen Prod", old, {"CN": "x"}, "EC", 256, 365, PASSPHRASE)
        _revoke(old)
        new = _root("Kigen Prod")
        assert new.id != old.id and new.name == old.name and not new.is_revoked
        assert CertificateAuthority.query.filter_by(name="Kigen Prod").count() == 2
        # and a second active one is refused again
        with pytest.raises(ValueError, match=r"#%d" % new.id):
            _root("Kigen Prod")

    def test_import_paths_use_the_same_rule(self, app, db):
        from tests.test_ca_import import _self_signed_ca
        from cryptography.hazmat.primitives import serialization
        old = _root("Offline")
        _key, cert = _self_signed_ca("Offline")
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        with pytest.raises(ValueError, match="already exists"):
            ca_service.import_ca("Offline", pem, None, PASSPHRASE)
        _revoke(old)
        imported = ca_service.import_ca("Offline", pem, None, PASSPHRASE)
        assert imported.name == "Offline" and imported.id != old.id

    def test_database_enforces_it_too(self, app, db):
        """Bypassing the pre-check must still fail on the partial unique index."""
        a = _root("Dup")
        row = CertificateAuthority(name="Dup", common_name="Dup", serial_number="ff01", certificate_pem=a.certificate_pem,
                                   private_key_enc=b"", key_type="EC", key_size=256, not_before=a.not_before,
                                   not_after=a.not_after, is_root=True, is_revoked=False)
        db.session.add(row)
        with pytest.raises(IntegrityError):
            db.session.flush()
        db.session.rollback()
        # revoked + active with the same name is fine at the DB level as well
        row = CertificateAuthority(name="Dup", common_name="Dup", serial_number="ff02", certificate_pem=a.certificate_pem,
                                   private_key_enc=b"", key_type="EC", key_size=256, not_before=a.not_before,
                                   not_after=a.not_after, is_root=True, is_revoked=True)
        db.session.add(row)
        db.session.commit()
        assert CertificateAuthority.query.filter_by(name="Dup").count() == 2

    def test_fresh_schema_has_partial_index_and_no_table_unique(self, app, db):
        idx = _indexes()
        assert idx["ux_certificate_authorities_name_active"]["unique"] and idx["ux_certificate_authorities_name_active"]["cols"] == ["name"]
        assert not [n for n, i in idx.items() if i["origin"] == "u" and i["cols"] == ["name"]]


class TestRoute:
    FORM = {"cn": "Route CA", "key_type": "EC", "key_size": "256", "validity_days": "3650", "ca_type": "root"}

    def test_duplicate_active_name_is_400_and_revoked_name_creates(self, app, auth_admin, db):
        old = _root("Route CA")
        r = auth_admin.post("/ca/create", data={"name": "Route CA", **self.FORM}, headers=JSON)
        assert r.status_code == 400 and "already exists" in r.get_json()["error"]
        r = auth_admin.post("/ca/create", data={"name": "Route CA", **self.FORM})
        assert r.status_code == 200 and b"already exists" in r.data   # form re-rendered, no 500
        _revoke(old)
        r = auth_admin.post("/ca/create", data={"name": "Route CA", **self.FORM}, headers=JSON)
        assert r.status_code == 201 and r.get_json()["name"] == "Route CA" and r.get_json()["id"] != old.id

    def test_raced_duplicate_is_409_not_500(self, app, auth_admin, db, monkeypatch):
        """With the pre-check out of the way the INSERT hits the index; the
        route must answer 409 and the HTML form must still render (the
        session is rolled back before the re-render queries the CA list)."""
        _root("Raced")
        monkeypatch.setattr(ca_service, "ensure_name_available", lambda name: None)
        r = auth_admin.post("/ca/create", data={"name": "Raced", **self.FORM}, headers=JSON)
        assert r.status_code == 409 and "concurrently" in r.get_json()["error"]
        r = auth_admin.post("/ca/create", data={"name": "Raced", **self.FORM})
        assert r.status_code == 200 and b"concurrently" in r.data
        assert CertificateAuthority.query.filter_by(name="Raced").count() == 1
        assert auth_admin.get("/ca/", headers=JSON).status_code == 200   # session healthy afterwards


class TestMigration:
    def _make_legacy(self, db):
        """Rebuild the CA table the way pre-2.27.1 databases have it: a
        table-level UNIQUE(name) and no partial index."""
        ddl = str(CreateTable(CertificateAuthority.__table__).compile(db.engine)).strip()
        legacy = re.sub(r"name VARCHAR\(200\) NOT NULL,", "name VARCHAR(200) NOT NULL UNIQUE,", ddl, count=1)
        assert legacy != ddl
        legacy = legacy.replace("CREATE TABLE certificate_authorities (", "CREATE TABLE ca_legacy (", 1)
        cols = ", ".join(c.name for c in CertificateAuthority.__table__.columns)
        db.session.execute(text("DROP INDEX IF EXISTS ux_certificate_authorities_name_active"))
        db.session.execute(text("DROP INDEX IF EXISTS ux_certificate_authorities_serial"))
        db.session.execute(text(legacy))
        db.session.execute(text(f"INSERT INTO ca_legacy ({cols}) SELECT {cols} FROM certificate_authorities"))
        db.session.execute(text("DROP TABLE certificate_authorities"))
        db.session.execute(text("ALTER TABLE ca_legacy RENAME TO certificate_authorities"))
        db.session.commit()
        idx = _indexes()
        assert [n for n, i in idx.items() if i["origin"] == "u" and i["cols"] == ["name"]]
        assert "ux_certificate_authorities_name_active" not in idx

    def test_rebuild_drops_table_unique_and_keeps_everything(self, app, db, admin_user):
        root = _root("Legacy Root", "RSA", 2048)
        inter = ca_service.create_intermediate_ca("Legacy Inter", root, {"CN": "Legacy Inter"}, "EC", 256, 365, PASSPHRASE,
                                                  created_by=admin_user.id)
        leaf = cert_service.create_certificate(inter, {"CN": "leaf.example"}, [], 30, PASSPHRASE)
        csr_model, _k, _ = csr_service.create_csr({"CN": "csr.example"}, [], "EC", 256, None)
        signed = cert_service.sign_csr(csr_model, inter, 30, PASSPHRASE)
        gone = _root("Reused")
        _revoke(gone)
        db.session.commit()
        before = db.session.execute(text("SELECT * FROM certificate_authorities ORDER BY id")).fetchall()
        assert len(before) == 3
        self._make_legacy(db)
        db.session.expire_all()
        with pytest.raises(ValueError):          # the friendly check
            _root("Legacy Root")
        # the legacy constraint refuses the reuse even though the app allows it
        db.session.add(CertificateAuthority(name="Reused", common_name="Reused", serial_number="ee01", certificate_pem=root.certificate_pem,
                                            private_key_enc=b"", key_type="EC", key_size=256, not_before=root.not_before,
                                            not_after=root.not_after, is_root=True, is_revoked=False))
        with pytest.raises(IntegrityError):
            db.session.flush()
        db.session.rollback()

        _migrate_schema()
        db.session.expire_all()

        idx = _indexes()
        assert not [n for n, i in idx.items() if i["origin"] == "u" and i["cols"] == ["name"]]
        assert idx["ux_certificate_authorities_name_active"]["unique"]
        assert idx["ux_certificate_authorities_serial"]["unique"]
        after = db.session.execute(text("SELECT * FROM certificate_authorities ORDER BY id")).fetchall()
        assert [tuple(r) for r in after] == [tuple(r) for r in before]      # every column, row and id
        assert db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%rebuild%'")).fetchall() == []
        # relationships across the rebuilt table still resolve
        inter = db.session.get(CertificateAuthority, inter.id)
        assert inter.parent.id == root.id and inter.creator.username == "testadmin"
        assert db.session.get(Certificate, leaf.id).ca.id == inter.id
        assert db.session.get(Certificate, signed.id).ca.id == inter.id
        assert db.session.get(CertificateSigningRequest, csr_model.id).ca.id == inter.id
        assert db.session.get(CertificateAuthority, inter.id).certificates.count() == 2
        # and the reason for all this: the revoked name is reusable now
        again = _root("Reused")
        assert again.id != gone.id and CertificateAuthority.query.filter_by(name="Reused").count() == 2
        # idempotent: a second run finds nothing to do
        _migrate_schema()
        assert [tuple(r) for r in db.session.execute(text("SELECT id, name FROM certificate_authorities ORDER BY id")).fetchall()] == \
            [(root.id, "Legacy Root"), (inter.id, "Legacy Inter"), (gone.id, "Reused"), (again.id, "Reused")]

    def test_rebuild_failure_leaves_table_untouched(self, app, db, monkeypatch):
        _root("Keep Me")
        self._make_legacy(db)
        before = db.session.execute(text("SELECT * FROM certificate_authorities")).fetchall()
        import app as app_pkg
        real = _db.session.execute
        def boom(stmt, *a, **kw):
            if "INSERT INTO certificate_authorities__rebuild" in str(stmt):
                raise RuntimeError("disk on fire")
            return real(stmt, *a, **kw)
        monkeypatch.setattr(_db.session, "execute", boom)
        app_pkg._drop_ca_name_unique_constraint()
        monkeypatch.undo()
        assert db.session.execute(text("SELECT * FROM certificate_authorities")).fetchall() == before
        assert [n for n, i in _indexes().items() if i["origin"] == "u" and i["cols"] == ["name"]]
        assert db.session.execute(text("SELECT name FROM sqlite_master WHERE name LIKE '%rebuild%'")).fetchall() == []


class TestSeedRemove:
    @pytest.fixture
    def seeder(self):
        path = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "seed_demo.py"
        spec = importlib.util.spec_from_file_location("seed_demo", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_remove_takes_dependants_and_refuses_foreign_sub_cas(self, app, db, seeder, capsys):
        demo_root = _root("Demo Root CA")
        demo_inter = ca_service.create_intermediate_ca("Demo Issuing CA", demo_root, {"CN": "Demo Issuing CA"}, "EC", 256, 365, PASSPHRASE)
        real_root = _root("Real Root")
        # a hand-made certificate (non-demo CN) issued by a demo CA — the case that crashed
        mine = cert_service.create_certificate(demo_inter, {"CN": "mine.example.org"}, [], 30, PASSPHRASE)
        csr_model, _k, _ = csr_service.create_csr({"CN": "mine-csr.example.org"}, [], "EC", 256, None)
        cert_service.sign_csr(csr_model, demo_inter, 30, PASSPHRASE)
        keep = cert_service.create_certificate(real_root, {"CN": "keep.example.org"}, [], 30, PASSPHRASE)
        db.session.commit()
        # a real CA chained under the demo root is refused without --force
        foreign = ca_service.create_intermediate_ca("Real Inter", demo_root, {"CN": "Real Inter"}, "EC", 256, 365, PASSPHRASE)
        db.session.commit()
        with pytest.raises(SystemExit, match="Real Inter"):
            seeder.reset_demo()
        assert db.session.get(CertificateAuthority, demo_root.id) is not None
        seeder.reset_demo(force=True)
        out = capsys.readouterr().out
        assert "mine.example.org" in out and "Real Inter" in out
        assert CertificateAuthority.query.filter(CertificateAuthority.name.like("Demo %")).count() == 0
        assert db.session.get(CertificateAuthority, foreign.id) is None
        assert db.session.get(Certificate, mine.id) is None and db.session.get(CertificateSigningRequest, csr_model.id) is None
        assert db.session.get(Certificate, keep.id) is not None and db.session.get(CertificateAuthority, real_root.id) is not None
