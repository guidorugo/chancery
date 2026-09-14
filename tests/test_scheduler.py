"""F8: in-app scheduler — lease contention, the CRL refresh job, isolation of
job failures, the system-actor audit path, lazy refresh + cache headers on the
public CRL routes, metrics, and CLI auditing (G10-2)."""
import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.extensions import db as _db
from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.models.scheduler_lease import SchedulerLease
from app.services import (audit_service, ca_service, cert_service, crl_service, crypto_utils,
                          metrics_service, metrics_token_service, scheduler_service, webhook_service)
from app.services.keybackend import pkcs11_session  # noqa: F401  (import parity with other suites)
from tests.test_ca_import import _self_signed_ca

PASSPHRASE = "test-passphrase"
JSON = {"Accept": "application/json"}


def _root(name="Sched Root", **kw):
    return ca_service.create_root_ca(
        name=name, subject_attrs={"CN": name}, key_type="RSA", key_size=2048,
        validity_days=3650, passphrase=PASSPHRASE, **kw)


def _next_update(ca):
    return x509.load_pem_x509_crl(ca.crl_pem.encode()).next_update_utc


def _make_expired_crl(ca):
    """Replace the CA's cached CRL with one whose nextUpdate is in the past
    (signed with the real key, so validators would call it 'expired')."""
    key = crypto_utils.decrypt_private_key(ca.private_key_enc, PASSPHRASE)
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    now = datetime.now(timezone.utc)
    crl = (x509.CertificateRevocationListBuilder()
           .issuer_name(ca_cert.subject)
           .last_update(now - timedelta(days=9))
           .next_update(now - timedelta(days=2))
           .add_extension(x509.CRLNumber(ca.crl_number), critical=False)
           .sign(key, hashes.SHA256()))
    ca.crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode()
    _db.session.commit()


@pytest.fixture(autouse=True)
def _reset_local_state():
    scheduler_service._state.update({"lease_held": False, "last_tick": None, "last_summary": None})
    metrics_service._CRL_CACHE.clear()
    yield
    scheduler_service._state.update({"lease_held": False, "last_tick": None, "last_summary": None})


# ---------------------------------------------------------------------------
# lease
# ---------------------------------------------------------------------------

class TestLease:
    def test_one_holder_at_a_time_until_expiry(self, app, db):
        with app.app_context():
            now = datetime(2026, 9, 14, 12, 0, 0)
            assert scheduler_service.acquire_lease(now, ttl_seconds=180, holder="worker-a") is True
            assert scheduler_service.acquire_lease(now + timedelta(seconds=60), ttl_seconds=180, holder="worker-b") is False
            # the holder renews freely
            assert scheduler_service.acquire_lease(now + timedelta(seconds=60), ttl_seconds=180, holder="worker-a") is True
            row = db.session.get(SchedulerLease, "main")
            assert row.holder == "worker-a"
            assert row.expires_at == now + timedelta(seconds=240)
            # after the lease lapses another worker takes over
            assert scheduler_service.acquire_lease(now + timedelta(seconds=300), ttl_seconds=180, holder="worker-b") is True
            assert db.session.get(SchedulerLease, "main").holder == "worker-b"

    def test_tick_without_lease_runs_no_jobs(self, app, db, monkeypatch):
        with app.app_context():
            now = datetime(2026, 9, 14, 12, 0, 0)
            assert scheduler_service.acquire_lease(now, ttl_seconds=600, holder="someone-else")
            calls = []
            monkeypatch.setattr(scheduler_service, "JOBS", (("probe", lambda n: calls.append(n), 0),))
            summary = scheduler_service.tick(now=now + timedelta(seconds=1))
            assert summary["lease"] is False and calls == []
            forced = scheduler_service.tick(now=now + timedelta(seconds=1), force=True)
            assert forced["lease"] is True and len(calls) == 1


# ---------------------------------------------------------------------------
# CRL refresh job
# ---------------------------------------------------------------------------

class TestCrlRefreshJob:
    def test_stale_crls_are_refreshed_fresh_ones_untouched(self, app, db):
        with app.app_context():
            fresh = _root("Fresh")                                   # 7-day CRL
            due = _root("Due")
            crl_service.generate_crl(due, PASSPHRASE, validity_days=1)  # expires within 2 days → due
            pending = _root("Pending", approval_status="pending")
            revoked = _root("Revoked")
            crl_service.revoke_ca(revoked.id, "cessation_of_operation", passphrase=PASSPHRASE)
            _k, cert = _self_signed_ca("Offline")
            cert_only = ca_service.import_ca("Offline", cert.public_bytes(serialization.Encoding.PEM).decode(),
                                             None, PASSPHRASE)
            fresh_n, due_n, revoked_n = fresh.crl_number, due.crl_number, revoked.crl_number

            summary = scheduler_service.tick(force=True)
            job = summary["jobs"]["crl_refresh"]
            assert job["refreshed"] == [due.id]
            assert job["failed"] == []
            assert job["fresh"] == 1
            db.session.expire_all()
            assert db.session.get(CertificateAuthority, due.id).crl_number == due_n + 1
            assert db.session.get(CertificateAuthority, fresh.id).crl_number == fresh_n
            assert db.session.get(CertificateAuthority, revoked.id).crl_number == revoked_n
            assert db.session.get(CertificateAuthority, pending.id).crl_pem is None
            assert db.session.get(CertificateAuthority, cert_only.id).crl_pem is None
            row = AuditLog.query.filter_by(action="crl_refreshed", target_id=due.id).one()
            assert row.username == "scheduler" and row.user_id is None and row.ip_address == "local"
            assert json.loads(row.details)["trigger"] == "scheduler"

    def test_missing_crl_counts_as_due(self, app, db):
        with app.app_context():
            ca = _root("NoCrl")
            ca.crl_pem = None
            db.session.commit()
            summary = scheduler_service.tick(force=True)
            assert summary["jobs"]["crl_refresh"]["refreshed"] == [ca.id]
            assert db.session.get(CertificateAuthority, ca.id).crl_pem

    def test_one_failing_ca_does_not_stop_the_others(self, app, db, monkeypatch):
        with app.app_context():
            bad = _root("Bad")
            good = _root("Good")
            for ca in (bad, good):
                crl_service.generate_crl(ca, PASSPHRASE, validity_days=1)
            good_n = good.crl_number
            real = crl_service.generate_crl

            def flaky(ca, passphrase, **kw):
                if ca.name == "Bad":
                    raise RuntimeError("token unreachable")
                return real(ca, passphrase, **kw)

            monkeypatch.setattr(crl_service, "generate_crl", flaky)
            summary = scheduler_service.tick(force=True)
            job = summary["jobs"]["crl_refresh"]
            assert job["failed"] == [bad.id] and job["refreshed"] == [good.id]
            db.session.expire_all()
            assert db.session.get(CertificateAuthority, good.id).crl_number == good_n + 1
            fail = AuditLog.query.filter_by(action="crl_refresh_failed", target_id=bad.id).one()
            assert "token unreachable" in json.loads(fail.details)["error"]
            assert db.session.get(SchedulerLease, "main").last_error is None  # per-CA errors are handled inside the job

    def test_job_exception_is_isolated_and_recorded(self, app, db, monkeypatch):
        with app.app_context():
            def boom(now):
                raise RuntimeError("job exploded")

            monkeypatch.setattr(scheduler_service, "JOBS", (("boom", boom, 0), ("ok", lambda n: {"ran": True}, 0)))
            summary = scheduler_service.tick(force=True)
            assert summary["jobs"]["boom"] == {"error": "RuntimeError"}
            assert summary["jobs"]["ok"] == {"ran": True}
            assert "job exploded" in db.session.get(SchedulerLease, "main").last_error

    def test_webhook_stream_sees_scheduler_events(self, app, db, monkeypatch):
        with app.app_context():
            ca = _root("Hooked")
            crl_service.generate_crl(ca, PASSPHRASE, validity_days=1)
            seen = []
            monkeypatch.setattr(webhook_service, "notify",
                                lambda action, **kw: seen.append((action, kw.get("actor_username"))))
            scheduler_service.tick(force=True)
            assert ("crl_refreshed", "scheduler") in seen


# ---------------------------------------------------------------------------
# start() gating
# ---------------------------------------------------------------------------

class TestStartGating:
    def test_only_a_flagged_non_test_process_starts(self, app):
        cfg = {"SCHEDULER_ENABLED": True, "TESTING": False}
        assert scheduler_service.should_start(cfg, {"CHANCERY_RUN_SCHEDULER": "1"}) is True
        assert scheduler_service.should_start(cfg, {}) is False
        assert scheduler_service.should_start({**cfg, "SCHEDULER_ENABLED": False}, {"CHANCERY_RUN_SCHEDULER": "1"}) is False
        assert scheduler_service.should_start({**cfg, "TESTING": True}, {"CHANCERY_RUN_SCHEDULER": "1"}) is False
        assert scheduler_service.start(app, environ={"CHANCERY_RUN_SCHEDULER": "1"}) is False  # app is TESTING
        assert scheduler_service.local_state()["thread_alive"] is False

    def test_entrypoint_sets_the_flag_only_on_the_gunicorn_exec(self):
        text = open("entrypoint-app.sh", encoding="utf-8").read()
        assert "CHANCERY_RUN_SCHEDULER=1 exec gunicorn" in text
        assert text.count("CHANCERY_RUN_SCHEDULER") == 2  # the comment and the exec line only


# ---------------------------------------------------------------------------
# public CRL route: lazy refresh + cache headers
# ---------------------------------------------------------------------------

class TestPublicCrl:
    def test_expired_cached_crl_is_regenerated_on_download(self, app, client, db):
        with app.app_context():
            ca = _root("Lazy")
            _make_expired_crl(ca)
            before = ca.crl_number
            r = client.get(f"/public/crl/{ca.id}.crl")
            assert r.status_code == 200
            served = x509.load_der_x509_crl(r.data)
            assert served.next_update_utc > datetime.now(timezone.utc)
            db.session.expire_all()
            assert db.session.get(CertificateAuthority, ca.id).crl_number == before + 1
            row = AuditLog.query.filter_by(action="crl_refreshed", target_id=ca.id).one()
            assert row.username == "system" and json.loads(row.details)["trigger"] == "lazy"
            # PEM route serves the refreshed one too
            pem = client.get(f"/public/crl/{ca.id}.pem")
            assert x509.load_pem_x509_crl(pem.data).next_update_utc == served.next_update_utc

    def test_revoked_ca_keeps_its_final_crl(self, app, client, db):
        with app.app_context():
            ca = _root("Final")
            crl_service.revoke_ca(ca.id, "cessation_of_operation", passphrase=PASSPHRASE)
            _make_expired_crl(ca)
            n = ca.crl_number
            r = client.get(f"/public/crl/{ca.id}.crl")
            assert r.status_code == 200
            db.session.expire_all()
            assert db.session.get(CertificateAuthority, ca.id).crl_number == n  # not regenerated

    def test_refresh_failure_serves_the_stale_crl(self, app, client, db, monkeypatch):
        with app.app_context():
            ca = _root("StaleOk")
            _make_expired_crl(ca)
            monkeypatch.setattr(crl_service, "generate_crl",
                                lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no token")))
            r = client.get(f"/public/crl/{ca.id}.crl")
            assert r.status_code == 200
            assert x509.load_der_x509_crl(r.data).next_update_utc < datetime.now(timezone.utc)
            assert r.headers["Cache-Control"] == "public, max-age=0"

    def test_cache_headers_follow_the_crl_window(self, app, client, db):
        with app.app_context():
            ca = _root("Cached")
            r = client.get(f"/public/crl/{ca.id}.crl")
            assert r.status_code == 200
            assert "Last-Modified" in r.headers and "Expires" in r.headers
            m = re.match(r"public, max-age=(\d+)", r.headers["Cache-Control"])
            assert m and 6 * 86400 < int(m.group(1)) <= 7 * 86400
            crl = x509.load_der_x509_crl(r.data)
            from werkzeug.http import http_date
            assert r.headers["Expires"] == http_date(crl.next_update_utc)


# ---------------------------------------------------------------------------
# metrics + CLI
# ---------------------------------------------------------------------------

class TestMetricsAndCli:
    def test_metrics_expose_scheduler_state(self, app, client, db, monkeypatch):
        with app.app_context():
            monkeypatch.setitem(app.config, "METRICS_ENABLED", True)
            monkeypatch.setitem(app.config, "METRICS_ALLOW_UNAUTHENTICATED", True)
            scheduler_service.tick(force=True)
            body = client.get("/metrics").get_data(as_text=True)
            assert "chancery_scheduler_last_tick_timestamp_seconds" in body
            assert "chancery_scheduler_lease_held 1.0" in body
            assert "chancery_scheduler_last_tick_failed 0.0" in body

    def test_scheduler_cli(self, app, db):
        with app.app_context():
            ca = _root("Cli")
            crl_service.generate_crl(ca, PASSPHRASE, validity_days=1)
            r = app.test_cli_runner().invoke(args=["scheduler", "tick"])
            assert r.exit_code == 0, r.output
            assert json.loads(r.output)["jobs"]["crl_refresh"]["refreshed"] == [ca.id]
            r = app.test_cli_runner().invoke(args=["scheduler", "status"])
            assert r.exit_code == 0 and '"lease"' in r.output and '"tick_seconds"' in r.output

    def test_cli_mutations_are_audited_through_the_shared_path(self, app, db):
        with app.app_context():
            from app.models.user import User
            u = User(username="locked", role="csr_requester")
            u.set_password("x" * 12)
            u.failed_login_count = 3
            db.session.add(u)
            db.session.commit()
            r = app.test_cli_runner().invoke(args=["users", "unlock", "locked"])
            assert r.exit_code == 0, r.output
            row = AuditLog.query.filter_by(action="unlock_user", target_id=u.id).one()
            assert row.username == "cli" and row.ip_address == "local"

            ca = _root("CliCrl")
            r = app.test_cli_runner().invoke(args=["crl", "refresh", "--all"])
            assert r.exit_code == 0, r.output
            row = AuditLog.query.filter_by(action="crl_refreshed", target_id=ca.id).one()
            assert row.username == "cli" and json.loads(row.details)["trigger"] == "cli"

            r = app.test_cli_runner().invoke(args=["certs", "recompute-expiry"])
            assert r.exit_code == 0
            assert AuditLog.query.filter_by(action="recompute_expiry").count() == 1
            r = app.test_cli_runner().invoke(args=["certs", "backfill-issuers"])
            assert r.exit_code == 0
            assert AuditLog.query.filter_by(action="backfill_issuers").count() == 1

    def test_log_action_actor_needs_no_request(self, app, db):
        with app.app_context():
            audit_service.log_action("probe", target_type="config", actor="scheduler")
            db.session.commit()
            row = AuditLog.query.filter_by(action="probe").one()
            assert (row.username, row.user_id, row.ip_address) == ("scheduler", None, "local")
