"""F16 (3.3.0): audit-log hash chain, sealing rules, verification (edited /
deleted / unsealed rows), daily anchor, retention pruning with checkpoint and
archive file, filtered page/JSON/export, CLI, scheduler wiring, migration."""
import csv
import io
import json
from datetime import timedelta

import pytest
from sqlalchemy import text

from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.services import audit_chain, audit_service, scheduler_service

JSON = {"Accept": "application/json"}


@pytest.fixture(autouse=True)
def _cfg(app, tmp_path):
    saved = {k: app.config.get(k) for k in ("AUDIT_RETENTION_DAYS", "AUDIT_ARCHIVE_DIR", "AUDIT_SEAL_GRACE_SECONDS")}
    app.config.update(AUDIT_RETENTION_DAYS=0, AUDIT_ARCHIVE_DIR=str(tmp_path / "archive"), AUDIT_SEAL_GRACE_SECONDS=0)
    yield
    app.config.update(saved)


def _rows(n, action="test_event", age_days=0):
    out = []
    for i in range(n):
        audit_service.log_action(action, target_type="thing", target_id=i, details={"i": i}, actor="cli")
        _db.session.flush()
        row = AuditLog.query.order_by(AuditLog.id.desc()).first()
        if age_days:
            row.timestamp = audit_chain.utcnow() - timedelta(days=age_days)
        out.append(row)
    _db.session.commit()
    return out


def _seal():
    return audit_chain.seal(now=audit_chain.utcnow() + timedelta(seconds=1))


class TestChain:
    def test_seal_and_verify(self, app, db):
        rows = _rows(5)
        assert all(r.entry_hash is None for r in rows)
        s = _seal()
        assert s["sealed"] == 5 and s["unsealed"] == 0 and s["head_id"] == rows[-1].id and s["stopped"] is None
        db.session.expire_all()
        first = db.session.get(AuditLog, rows[0].id)
        assert first.prev_hash == "" and len(first.entry_hash) == 64
        assert db.session.get(AuditLog, rows[1].id).prev_hash == first.entry_hash
        report = audit_chain.verify()
        assert report["ok"] and report["checked"] == 5 and report["start"] == "genesis" and report["head_hash"] == s["head_hash"]
        assert _seal()["sealed"] == 0                       # idempotent
        assert audit_chain.verify()["ok"]
        # a later batch continues the chain
        more = _rows(2)
        assert _seal()["sealed"] == 2
        db.session.expire_all()
        assert db.session.get(AuditLog, more[0].id).prev_hash == s["head_hash"]
        assert audit_chain.verify()["checked"] == 7

    def test_hash_is_deterministic_over_stored_fields(self, app, db):
        row = _rows(1)[0]
        h1 = audit_chain.compute_hash(row, "")
        assert h1 == audit_chain.compute_hash(row, "") and len(h1) == 64
        assert audit_chain.compute_hash(row, "abc") != h1

    def test_grace_period_and_gap_stop_sealing(self, app, db):
        app.config["AUDIT_SEAL_GRACE_SECONDS"] = 300
        rows = _rows(3)
        s = audit_chain.seal()
        assert s["sealed"] == 0 and "grace" in s["stopped"]
        app.config["AUDIT_SEAL_GRACE_SECONDS"] = 0
        assert _seal()["sealed"] == 3
        # a gap (an insert whose transaction has not committed yet) stops the sealer
        db.session.execute(text("INSERT INTO audit_logs (id, timestamp, username, action, ip_address) "
                                "VALUES (:id, :ts, 'cli', 'late', 'local')"),
                           {"id": rows[-1].id + 2, "ts": (audit_chain.utcnow() - timedelta(minutes=5)).isoformat(sep=" ")})
        db.session.commit()
        s = _seal()
        assert s["sealed"] == 0 and s["stopped"].startswith("gap") and s["unsealed"] == 1
        db.session.execute(text("INSERT INTO audit_logs (id, timestamp, username, action, ip_address) "
                                "VALUES (:id, :ts, 'cli', 'filler', 'local')"),
                           {"id": rows[-1].id + 1, "ts": (audit_chain.utcnow() - timedelta(minutes=5)).isoformat(sep=" ")})
        db.session.commit()
        s = _seal()
        assert s["sealed"] == 2 and s["stopped"] is None and audit_chain.verify()["ok"]

    def test_edited_row_is_detected(self, app, db):
        rows = _rows(4); _seal()
        victim = db.session.get(AuditLog, rows[2].id)
        victim.details = json.dumps({"i": 99}); db.session.commit()
        report = audit_chain.verify()
        assert not report["ok"] and report["first_bad_id"] == victim.id and "contents" in report["reason"]
        # verify from a later id skips the damage (the caller vouches for the start)
        assert audit_chain.verify(from_id=rows[3].id)["ok"]

    def test_deleted_row_is_detected(self, app, db):
        rows = _rows(4); _seal()
        db.session.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": rows[1].id}); db.session.commit()
        report = audit_chain.verify()
        assert not report["ok"] and report["first_bad_id"] == rows[2].id and "missing" in report["reason"]
        # deleting the newest row leaves a shorter but valid chain (the anchor is what catches that)
        db.session.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": rows[3].id}); db.session.commit()
        assert audit_chain.verify()["first_bad_id"] == rows[2].id

    def test_rewired_prev_hash_is_detected(self, app, db):
        rows = _rows(3); _seal()
        db.session.get(AuditLog, rows[2].id).prev_hash = "0" * 64; db.session.commit()
        report = audit_chain.verify()
        assert not report["ok"] and report["first_bad_id"] == rows[2].id and "prev_hash" in report["reason"]

    def test_unsealed_rows_reported_and_status(self, app, db):
        rows = _rows(3); _seal(); _rows(2)
        report = audit_chain.verify()
        assert report["ok"] and report["checked"] == 3 and report["unsealed"] == 2
        st = audit_chain.status()
        assert st["head_id"] == rows[2].id and st["unsealed"] == 2 and st["total"] == 5 and st["last_anchor"] is None
        assert audit_chain.verify()["start"] == "genesis"
        assert audit_chain.verify(from_id=10**6)["start"] == "empty"


class TestAnchorAndScheduler:
    def test_anchor_row_and_catalog(self, app, db):
        from app.services import webhook_service
        _rows(3); _seal()
        details = audit_chain.anchor(actor="scheduler")
        row = AuditLog.query.filter_by(action="audit_anchor").one()
        assert json.loads(row.details) == details and details["sealed_rows"] == 3 and details["head_hash"]
        assert row.username == "scheduler" and row.target_id == details["head_id"]
        assert _seal()["sealed"] == 1 and audit_chain.verify()["checked"] == 4     # the anchor joins the chain
        assert any(k == "audit_anchor" for k, _ in webhook_service.EVENT_CATALOG["Audit integrity"])

    def test_scheduler_jobs_wired(self, app, db):
        names = [j[0] for j in scheduler_service.JOBS]
        assert names[-3:] == ["audit_seal", "audit_anchor", "audit_prune"]
        assert dict((j[0], j[2]) for j in scheduler_service.JOBS)["audit_seal"] == 0
        scheduler_service._state.update({"lease_held": False, "last_tick": None, "last_summary": None})
        _rows(2)
        summary = scheduler_service.tick(now=audit_chain.utcnow() + timedelta(seconds=5), force=True)
        assert summary["jobs"]["audit_seal"]["sealed"] >= 2 and summary["jobs"]["audit_prune"] == {"disabled": True}
        assert summary["jobs"]["audit_anchor"]["sealed_rows"] >= 2
        assert AuditLog.query.filter_by(action="audit_anchor").count() == 1


class TestRetention:
    def test_prune_archives_deletes_and_checkpoints(self, app, db, tmp_path):
        old = _rows(4, action="old_event", age_days=40)
        old_ids, old_last = [r.id for r in old], old[-1].id
        fresh = _rows(2, action="new_event")
        _seal()
        assert audit_chain.prune() == {"disabled": True}
        app.config["AUDIT_RETENTION_DAYS"] = 30
        dry = audit_chain.prune(dry_run=True)
        assert dry["pruned"] == 4 and dry["from_id"] == old_ids[0] and dry["through_id"] == old_last and AuditLog.query.count() == 6
        result = audit_chain.prune(actor="scheduler")
        assert result["pruned"] == 4 and result["file"].startswith(str(tmp_path / "archive"))
        lines = [json.loads(l) for l in open(result["file"], encoding="utf-8")]
        assert [l["id"] for l in lines] == old_ids and all(len(l["entry_hash"]) == 64 for l in lines)
        assert AuditLog.query.filter_by(action="old_event").count() == 0
        cp = AuditLog.query.filter_by(action="audit_checkpoint").one()
        details = json.loads(cp.details)
        assert details["pruned_through_id"] == old_last and details["pruned_through_hash"] == lines[-1]["entry_hash"]
        assert details["rows"] == 4 and details["file"] == result["file"].rsplit("/", 1)[1]
        _seal()
        report = audit_chain.verify()
        assert report["ok"] and report["start"].startswith("checkpoint #") and report["checked"] == 3   # 2 fresh + checkpoint
        assert audit_chain.status()["last_checkpoint"]["id"] == cp.id
        # a second prune with nothing old is a no-op
        assert audit_chain.prune()["pruned"] == 0

    def test_prune_never_removes_unsealed_or_non_prefix_rows(self, app, db):
        app.config["AUDIT_RETENTION_DAYS"] = 1
        _rows(2, age_days=5)                # unsealed and old
        assert audit_chain.prune()["pruned"] == 0
        _seal()
        _rows(1, age_days=5)                # old but AFTER a fresh sealed... make the prefix rule matter
        fresh = _rows(1)
        _seal()
        # rows: old,old,old(unsealed->now sealed),fresh — the prefix of old sealed rows is 3
        assert audit_chain.prune()["pruned"] == 3
        assert audit_chain.verify()["ok"]

    def test_checkpoint_is_required_after_pruning(self, app, db):
        app.config["AUDIT_RETENTION_DAYS"] = 1
        _rows(3, age_days=3); _rows(1); _seal()
        audit_chain.prune()
        cp = AuditLog.query.filter_by(action="audit_checkpoint").one()
        db.session.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": cp.id}); db.session.commit()
        report = audit_chain.verify()
        assert not report["ok"] and report["start"] == "unverifiable"


class TestPageExportAndCli:
    def test_filters_page_json_and_export(self, app, auth_admin, db):
        _rows(3, action="alpha_one"); _rows(2, action="beta_two")
        old = _rows(1, action="ancient", age_days=400)
        _seal()
        r = auth_admin.get("/users/audit-log?action=alpha_one", headers=JSON)
        body = r.get_json()
        assert r.status_code == 200 and body["total"] == 3 and body["filters"] == {"action": "alpha_one"}
        assert body["integrity"]["head_id"] and body["items"][0]["entry_hash"]
        assert auth_admin.get("/users/audit-log?action=alpha_*", headers=JSON).get_json()["total"] == 3
        assert auth_admin.get("/users/audit-log?user=CLI&q=%22i%22:%201", headers=JSON).get_json()["total"] >= 2
        to = (audit_chain.utcnow() - timedelta(days=300)).strftime("%Y-%m-%d")
        assert auth_admin.get(f"/users/audit-log?to={to}", headers=JSON).get_json()["total"] == 1
        frm = (audit_chain.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
        assert auth_admin.get(f"/users/audit-log?from={frm}&target_type=thing", headers=JSON).get_json()["total"] == 5
        assert auth_admin.get("/users/audit-log?from=yesterday", headers=JSON).status_code == 400
        assert auth_admin.get("/users/audit-log?target_id=abc", headers=JSON).status_code == 400
        page = auth_admin.get("/users/audit-log?action=beta_two").data
        assert b"Chain sealed through" in page and b"Export CSV" in page and b"beta_two" in page and b"alpha_one" not in page
        assert b'href="/users/audit-log/export?format=csv&amp;action=beta_two"' in page or b"format=csv" in page
        # export: csv rows == filtered rows, hashes present; json is a list; jsonl one per line
        r = auth_admin.get("/users/audit-log/export?format=csv&action=beta_two")
        assert r.status_code == 200 and r.mimetype == "text/csv" and "attachment" in r.headers["Content-Disposition"]
        rows = list(csv.reader(io.StringIO(r.get_data(as_text=True))))
        assert rows[0][0] == "id" and len(rows) == 3 and all(len(x[-1]) == 64 for x in rows[1:])
        r = auth_admin.get("/users/audit-log/export?format=json&action=beta_two")
        assert r.mimetype == "application/json" and len(r.get_json()) == 2
        r = auth_admin.get("/users/audit-log/export?format=jsonl")
        lines = r.get_data(as_text=True).strip().splitlines()
        assert len(lines) >= 7 and all(json.loads(l)["id"] for l in lines)
        assert auth_admin.get("/users/audit-log/export?format=xml").status_code == 400
        assert AuditLog.query.filter_by(action="export_audit_log").count() == 3
        assert json.loads(AuditLog.query.filter_by(action="export_audit_log").first().details)["filters"] == {"action": "beta_two"}

    def test_requester_cannot_read_or_export(self, app, auth_csr_requester, db):
        assert auth_csr_requester.get("/users/audit-log", headers=JSON).status_code == 403
        assert auth_csr_requester.get("/users/audit-log/export?format=csv", headers=JSON).status_code == 403

    def test_cli(self, app, db, tmp_path):
        runner = app.test_cli_runner()
        rows = _rows(3)
        r = runner.invoke(args=["audit", "seal"])
        assert r.exit_code == 0 and json.loads(r.output)["sealed"] == 3
        r = runner.invoke(args=["audit", "verify"])
        assert r.exit_code == 0 and r.output.startswith("OK: 3 sealed rows")
        r = runner.invoke(args=["audit", "anchor"])
        assert r.exit_code == 0 and json.loads(r.output)["sealed_rows"] == 3
        assert AuditLog.query.filter_by(action="audit_anchor").one().username == "cli"
        out = tmp_path / "export.csv"
        r = runner.invoke(args=["audit", "export", "--format", "csv", "--action", "test_event", "--out", str(out)])
        assert r.exit_code == 0 and len(out.read_text().strip().splitlines()) == 4
        r = runner.invoke(args=["audit", "export", "--format", "jsonl", "--since", "2000-01-01"])
        assert r.exit_code == 0 and len(r.output.strip().splitlines()) == 4
        assert runner.invoke(args=["audit", "export", "--since", "nope"]).exit_code != 0
        r = runner.invoke(args=["audit", "prune", "--dry-run"])
        assert r.exit_code == 0 and json.loads(r.output) == {"disabled": True}
        db.session.get(AuditLog, rows[1].id).username = "mallory"; db.session.commit()
        r = runner.invoke(args=["audit", "verify", "--json"])
        assert r.exit_code == 1 and json.loads(r.output)["first_bad_id"] == rows[1].id
        r = runner.invoke(args=["audit", "verify", "--from-id", str(rows[2].id)])
        assert r.exit_code == 0


class TestSchema:
    def test_migration_adds_columns(self, app, db):
        from app import _migrate_schema
        for col in ("prev_hash", "entry_hash"):
            db.session.execute(text(f"ALTER TABLE audit_logs DROP COLUMN {col}"))
        db.session.commit()
        _migrate_schema(); _migrate_schema()
        cols = {r[1] for r in db.session.execute(text("PRAGMA table_info(audit_logs)"))}
        assert {"prev_hash", "entry_hash"} <= cols
        _rows(1); assert _seal()["sealed"] == 1
