"""F10: time-based webhook events — the daily `expiry_events` scheduler job
audits certificate_expiring / certificate_expired / ca_expiring / ca_expired
once per object (the audit row is what feeds the webhook), the per-job
interval bookkeeping in `scheduler_jobs`, and `scheduler_error` on change."""
import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import inspect as sa_inspect

from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.models.certificate import Certificate
from app.models.scheduler_lease import SchedulerJob, SchedulerLease
from app.services import ca_service, cert_service, crl_service, scheduler_service, webhook_service

PASSPHRASE = "test-passphrase"
NOW = datetime(2026, 9, 15, 12, 0, 0)   # naive UTC, like every stored datetime
DAY = timedelta(days=1)


@pytest.fixture(autouse=True)
def _reset_local_state():
    scheduler_service._state.update({"lease_held": False, "last_tick": None, "last_summary": None})
    yield
    scheduler_service._state.update({"lease_held": False, "last_tick": None, "last_summary": None})


def _root(name="Expiry Root", not_after=None):
    ca = ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name}, key_type="RSA", key_size=2048,
        validity_days=3650, passphrase=PASSPHRASE)
    if not_after is not None:
        ca.not_after = not_after
        _db.session.commit()
    return ca


def _cert(ca, cn, not_after):
    cert = cert_service.create_certificate(ca, {"CN": cn}, [cn], 365, PASSPHRASE)
    cert.not_after = not_after
    _db.session.commit()
    return cert


def _events(action, target_id=None):
    q = AuditLog.query.filter_by(action=action)
    if target_id is not None:
        q = q.filter_by(target_id=target_id)
    return q.order_by(AuditLog.id).all()


def _run(now):
    return scheduler_service.tick(now=now, force=True)["jobs"]["expiry_events"]


# ---------------------------------------------------------------------------
# certificate events
# ---------------------------------------------------------------------------

class TestCertificateEvents:
    def test_expiring_fires_once_then_expired_fires_once(self, app, db):
        with app.app_context():
            root = _root()
            cert = _cert(root, "soon.example", NOW + 5 * DAY)

            job = _run(NOW)
            assert job["certificate_expiring"] == [cert.id] and job["certificate_expired"] == []
            rows = _events("certificate_expiring", cert.id)
            assert len(rows) == 1
            row = rows[0]
            assert (row.username, row.user_id, row.ip_address, row.target_type) == ("scheduler", None, "local", "certificate")
            details = json.loads(row.details)
            assert details["common_name"] == "soon.example" and details["days_left"] == 5
            assert details["serial_number"] == cert.serial_number and details["ca_id"] == root.id
            db.session.expire_all()
            assert db.session.get(Certificate, cert.id).expiry_notified_at == NOW

            # next day: nothing new while it is still only "expiring"
            job = _run(NOW + DAY)
            assert job["certificate_expiring"] == [] and job["certificate_expired"] == []
            assert len(_events("certificate_expiring", cert.id)) == 1

            # it expires: exactly one "expired" event, then silence
            job = _run(NOW + 6 * DAY)
            assert job["certificate_expired"] == [cert.id]
            assert json.loads(_events("certificate_expired", cert.id)[0].details)["days_left"] == -1
            job = _run(NOW + 7 * DAY)
            assert job["certificate_expired"] == [] and len(_events("certificate_expired", cert.id)) == 1
            db.session.expire_all()
            assert db.session.get(Certificate, cert.id).expiry_notified_at == NOW + 6 * DAY

    def test_already_expired_and_never_notified_gets_only_expired(self, app, db):
        with app.app_context():
            root = _root()
            old = _cert(root, "old.example", NOW - 3 * DAY)
            job = _run(NOW)
            assert job["certificate_expired"] == [old.id]
            assert _events("certificate_expiring", old.id) == []

    def test_revoked_far_future_and_already_reported_are_ignored(self, app, db):
        with app.app_context():
            root = _root()
            revoked = _cert(root, "revoked.example", NOW + 2 * DAY)
            crl_service.revoke_certificate(revoked.id, "superseded", passphrase=PASSPHRASE)
            _cert(root, "far.example", NOW + 200 * DAY)
            done = _cert(root, "done.example", NOW - DAY)
            done.expiry_notified_at = NOW - DAY + timedelta(hours=1)   # "expired" already went out
            db.session.commit()
            job = _run(NOW)
            assert job == {"certificate_expiring": [], "certificate_expired": [], "ca_expiring": [],
                           "ca_expired": [], "failed": []}
            assert AuditLog.query.filter(AuditLog.action.like("certificate_exp%")).count() == 0

    def test_warning_window_follows_config(self, app, db, monkeypatch):
        with app.app_context():
            monkeypatch.setitem(app.config, "CERT_EXPIRY_WARNING_DAYS", 7)
            root = _root()
            inside = _cert(root, "in.example", NOW + 7 * DAY)
            _cert(root, "out.example", NOW + 8 * DAY)
            job = _run(NOW)
            assert job["certificate_expiring"] == [inside.id]

    def test_new_certificate_starts_unreported_and_json_exposes_it(self, app, auth_admin, db):
        with app.app_context():
            root = _root()
            cert = _cert(root, "fresh.example", NOW + 5 * DAY)
            assert cert.expiry_notified_at is None
            body = auth_admin.get(f"/certificates/{cert.id}", headers={"Accept": "application/json"}).get_json()
            assert body["expiry_notified_at"] is None
            _run(NOW)
            body = auth_admin.get(f"/certificates/{cert.id}", headers={"Accept": "application/json"}).get_json()
            assert body["expiry_notified_at"] == NOW.isoformat()
            ca_body = auth_admin.get(f"/ca/{root.id}", headers={"Accept": "application/json"}).get_json()
            assert "expiry_notified_at" in ca_body


# ---------------------------------------------------------------------------
# CA events
# ---------------------------------------------------------------------------

class TestCaEvents:
    def test_ca_expiring_and_expired(self, app, db):
        with app.app_context():
            soon = _root("Soon CA", not_after=NOW + 10 * DAY)
            gone = _root("Gone CA", not_after=NOW - DAY)
            fine = _root("Fine CA")
            revoked = _root("Revoked CA", not_after=NOW + DAY)
            crl_service.revoke_ca(revoked.id, "cessation_of_operation", passphrase=PASSPHRASE)

            job = _run(NOW)
            assert job["ca_expiring"] == [soon.id] and job["ca_expired"] == [gone.id]
            row = _events("ca_expiring", soon.id)[0]
            details = json.loads(row.details)
            assert details["name"] == "Soon CA" and details["days_left"] == 10 and details["is_root"] is True
            assert row.target_type == "ca" and row.username == "scheduler"
            assert _events("ca_expired", fine.id) == [] and _events("ca_expiring", fine.id) == []
            assert AuditLog.query.filter(AuditLog.action.like("ca_exp%"), AuditLog.target_id == revoked.id).count() == 0

            job = _run(NOW + DAY)
            assert job["ca_expiring"] == [] and job["ca_expired"] == []
            job = _run(NOW + 11 * DAY)
            assert job["ca_expired"] == [soon.id]
            db.session.expire_all()
            assert db.session.get(CertificateAuthority, soon.id).expiry_notified_at == NOW + 11 * DAY

    def test_certificate_only_ca_is_covered(self, app, db):
        with app.app_context():
            from cryptography.hazmat.primitives import serialization
            from tests.test_ca_import import _self_signed_ca
            _k, cert = _self_signed_ca("Offline Root")
            ca = ca_service.import_ca("Offline Root", cert.public_bytes(serialization.Encoding.PEM).decode(),
                                      None, PASSPHRASE)
            ca.not_after = NOW + 3 * DAY
            db.session.commit()
            assert _run(NOW)["ca_expiring"] == [ca.id]


# ---------------------------------------------------------------------------
# job cadence, isolation, webhook stream
# ---------------------------------------------------------------------------

class TestCadence:
    def test_daily_job_runs_once_a_day_unless_forced(self, app, db):
        with app.app_context():
            _root()
            first = scheduler_service.tick(now=NOW)              # lease acquired, both jobs run
            assert first["lease"] is True
            assert set(first["jobs"]) == {"crl_refresh", "expiry_events", "ocsp_responders"} and first["skipped"] == []
            row = db.session.get(SchedulerJob, "expiry_events")
            assert row.last_run_at == NOW and row.last_error is None

            later = scheduler_service.tick(now=NOW + timedelta(minutes=1))
            assert later["skipped"] == ["expiry_events", "ocsp_responders"] and "crl_refresh" in later["jobs"]
            assert db.session.get(SchedulerJob, "expiry_events").last_run_at == NOW

            forced = scheduler_service.tick(now=NOW + timedelta(minutes=2), force=True)
            assert forced["skipped"] == [] and "expiry_events" in forced["jobs"]

            next_day = scheduler_service.tick(now=NOW + DAY + timedelta(minutes=3))
            assert "expiry_events" in next_day["jobs"] and next_day["skipped"] == []
            assert db.session.get(SchedulerJob, "expiry_events").last_run_at == NOW + DAY + timedelta(minutes=3)

    def test_failed_job_is_retried_and_scheduler_error_audited_once(self, app, db, monkeypatch):
        with app.app_context():
            calls = []

            def flaky(now):
                calls.append(now)
                raise RuntimeError("directory offline")

            monkeypatch.setattr(scheduler_service, "JOBS",
                                (("flaky", flaky, scheduler_service.DAILY), ("ok", lambda n: {"ran": True}, 0)))
            s1 = scheduler_service.tick(now=NOW)
            assert s1["jobs"]["flaky"] == {"error": "RuntimeError"} and s1["jobs"]["ok"] == {"ran": True}
            job = db.session.get(SchedulerJob, "flaky")
            assert job.last_run_at is None and "directory offline" in job.last_error
            errs = _events("scheduler_error")
            assert len(errs) == 1 and errs[0].username == "scheduler"
            assert "flaky: RuntimeError: directory offline" in json.loads(errs[0].details)["errors"][0]

            # same failure next tick: retried (interval ignored while it never succeeded), not re-audited
            s2 = scheduler_service.tick(now=NOW + timedelta(minutes=1))
            assert s2["jobs"]["flaky"] == {"error": "RuntimeError"} and len(calls) == 2
            assert len(_events("scheduler_error")) == 1
            assert "directory offline" in db.session.get(SchedulerLease, "main").last_error

            # recovery clears the error; a NEW error is audited again
            monkeypatch.setattr(scheduler_service, "JOBS", (("flaky", lambda n: {"fixed": True}, 0),))
            s3 = scheduler_service.tick(now=NOW + timedelta(minutes=2))
            assert s3["jobs"]["flaky"] == {"fixed": True}
            assert db.session.get(SchedulerJob, "flaky").last_error is None
            assert db.session.get(SchedulerLease, "main").last_error is None
            monkeypatch.setattr(scheduler_service, "JOBS", (("flaky", flaky, 0),))
            scheduler_service.tick(now=NOW + timedelta(minutes=3))
            assert len(_events("scheduler_error")) == 2

    def test_expiry_events_reach_the_webhook_stream(self, app, db, monkeypatch):
        with app.app_context():
            root = _root("Hook CA", not_after=NOW + 2 * DAY)
            cert = _cert(root, "hook.example", NOW - DAY)
            seen = []
            monkeypatch.setattr(webhook_service, "notify",
                                lambda action, **kw: seen.append((action, kw.get("target_id"), kw.get("actor_username"),
                                                                  kw.get("details", {}).get("days_left"))))
            _run(NOW)
            assert ("certificate_expired", cert.id, "scheduler", -1) in seen
            assert ("ca_expiring", root.id, "scheduler", 2) in seen

    def test_one_failing_item_does_not_block_the_others(self, app, db, monkeypatch):
        with app.app_context():
            root = _root()
            a = _cert(root, "a.example", NOW + DAY)
            b = _cert(root, "b.example", NOW + 2 * DAY)
            from app.services import audit_service
            real = audit_service.log_action

            def flaky(action, **kw):
                if kw.get("target_id") == a.id:
                    raise RuntimeError("audit write failed")
                return real(action, **kw)

            monkeypatch.setattr(audit_service, "log_action", flaky)
            job = _run(NOW)
            assert job["certificate_expiring"] == [b.id] and job["failed"] == [f"certificate:{a.id}"]
            db.session.expire_all()
            assert db.session.get(Certificate, a.id).expiry_notified_at is None   # retried tomorrow
            assert db.session.get(Certificate, b.id).expiry_notified_at == NOW


# ---------------------------------------------------------------------------
# catalog, settings page, status, metrics, migration
# ---------------------------------------------------------------------------

class TestSurface:
    def test_catalog_and_settings_page_offer_the_events(self, app, auth_admin, db):
        with app.app_context():
            scheduled = dict(webhook_service.EVENT_CATALOG["Scheduled"])
            for action in ("certificate_expiring", "certificate_expired", "ca_expiring", "ca_expired", "scheduler_error"):
                assert action in scheduled
            page = auth_admin.get("/users/webhooks").get_data(as_text=True)
            assert 'name="event_certificate_expiring"' in page and 'name="event_scheduler_error"' in page

    def test_status_and_cli_report_jobs(self, app, db):
        with app.app_context():
            _root()
            r = app.test_cli_runner().invoke(args=["scheduler", "tick", "--force"])
            assert r.exit_code == 0, r.output
            out = json.loads(r.output)
            assert set(out["jobs"]) == {"crl_refresh", "expiry_events", "ocsp_responders"} and out["skipped"] == []
            r = app.test_cli_runner().invoke(args=["scheduler", "status"])
            assert r.exit_code == 0, r.output
            status = json.loads(r.output)
            assert status["jobs"]["expiry_events"]["interval_seconds"] == 86400
            assert status["jobs"]["expiry_events"]["last_run_at"] is not None
            assert status["jobs"]["crl_refresh"]["interval_seconds"] == 0
            assert status["config"]["cert_expiry_warning_days"] == app.config["CERT_EXPIRY_WARNING_DAYS"]

    def test_metrics_expose_job_cadence(self, app, client, db, monkeypatch):
        with app.app_context():
            monkeypatch.setitem(app.config, "METRICS_ENABLED", True)
            monkeypatch.setitem(app.config, "METRICS_ALLOW_UNAUTHENTICATED", True)
            scheduler_service.tick(now=NOW, force=True)
            body = client.get("/metrics").get_data(as_text=True)
            assert 'chancery_scheduler_job_last_run_timestamp_seconds{job="expiry_events"}' in body
            assert 'chancery_scheduler_job_failed{job="expiry_events"} 0.0' in body
            assert 'chancery_scheduler_job_failed{job="crl_refresh"} 0.0' in body

    def test_migration_adds_the_columns(self, app, db):
        with app.app_context():
            from app import _migrate_schema
            _migrate_schema()
            insp = sa_inspect(_db.engine)
            assert "expiry_notified_at" in {c["name"] for c in insp.get_columns("certificates")}
            assert "expiry_notified_at" in {c["name"] for c in insp.get_columns("certificate_authorities")}
            assert "scheduler_jobs" in insp.get_table_names()
