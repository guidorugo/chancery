"""In-app background scheduler (F8, 2.17.0) — closes assessment G4-1.

One daemon thread per gunicorn worker ticks every `SCHEDULER_TICK_SECONDS`.
A row in `scheduler_leases` makes exactly one worker run the jobs: each tick
tries a conditional UPDATE that succeeds only when the lease is unset,
expired, or already held by this worker (lease TTL = 3 ticks). No deployment
change is needed and any number of workers is safe.

The thread starts only when `CHANCERY_RUN_SCHEDULER=1` is in the environment
— `entrypoint-app.sh` sets it on the gunicorn exec line only — so the
boot-time `create_app()` call, `flask …` CLI runs and the test suite never
start it. `SCHEDULER_ENABLED=false` disables it entirely.

Jobs must never raise out of the tick: each is wrapped and its failure is
recorded on the lease row (and, for CRLs, in the audit log). A job may carry a
minimum interval (F10: `expiry_events` runs daily); its last successful run is
kept in `scheduler_jobs`, so the cadence survives restarts and lease hand-overs.
A tick whose job errors differ from the previous tick's audits `scheduler_error`
(actor `scheduler`), which reaches the webhook stream like every audit row.
"""
import logging
import os
import socket
import threading
import uuid
from datetime import datetime, timedelta, timezone

from cryptography import x509
from flask import current_app
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models.ca import CertificateAuthority
from ..models.certificate import Certificate
from ..models.scheduler_lease import SchedulerJob, SchedulerLease
from ..serialization import iso
from . import audit_service, crl_service, ocsp_service

LEASE_NAME = "main"
ENV_FLAG = "CHANCERY_RUN_SCHEDULER"
ACTOR = "scheduler"
DAILY = 24 * 3600

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_thread = None
_stop = threading.Event()
_holder = None
_state = {"lease_held": False, "last_tick": None, "last_summary": None}


# --- identity / lifecycle ------------------------------------------------------

def holder_id():
    global _holder
    if _holder is None:
        _holder = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
    return _holder


def should_start(config, environ):
    """True only for a real serving process: enabled, flagged by the
    entrypoint, and not under test."""
    if not config.get("SCHEDULER_ENABLED", True):
        return False
    if environ.get(ENV_FLAG) != "1":
        return False
    if config.get("TESTING"):
        return False
    return True


def start(app, environ=None):
    """Start the per-process scheduler thread if `should_start`. Returns True
    when a thread was started by this call."""
    global _thread
    environ = os.environ if environ is None else environ
    if not should_start(app.config, environ):
        return False
    with _lock:
        if _thread is not None and _thread.is_alive():
            return False
        _stop.clear()
        _thread = threading.Thread(target=_loop, args=(app,), name="chancery-scheduler", daemon=True)
        _thread.start()
    logger.info("Scheduler thread started (holder %s)", holder_id())
    return True


def stop():
    _stop.set()


def _loop(app):
    tick_seconds = max(5, int(app.config.get("SCHEDULER_TICK_SECONDS", 60)))
    # First tick shortly after boot so a stale CRL is fixed seconds after an
    # upgrade, then every tick_seconds.
    delay = min(10, tick_seconds)
    while not _stop.wait(delay):
        delay = tick_seconds
        with app.app_context():
            try:
                tick()
            except Exception:  # pragma: no cover - last line of defence
                logger.exception("Scheduler tick failed")
            finally:
                db.session.remove()


# --- lease ---------------------------------------------------------------------

def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)  # naive UTC, like every stored datetime


def _ensure_lease_row():
    if db.session.get(SchedulerLease, LEASE_NAME) is None:
        db.session.add(SchedulerLease(name=LEASE_NAME))
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()  # another worker inserted it first


def acquire_lease(now=None, ttl_seconds=None, holder=None):
    """Take or renew the lease in one conditional UPDATE. True when this
    holder owns it for the next `ttl_seconds`."""
    now = now or _utcnow()
    holder = holder or holder_id()
    if ttl_seconds is None:
        ttl_seconds = 3 * int(current_app.config.get("SCHEDULER_TICK_SECONDS", 60))
    _ensure_lease_row()
    result = db.session.execute(
        update(SchedulerLease)
        .where(SchedulerLease.name == LEASE_NAME,
               db.or_(SchedulerLease.expires_at.is_(None),
                      SchedulerLease.expires_at < now,
                      SchedulerLease.holder == holder))
        .values(holder=holder, expires_at=now + timedelta(seconds=ttl_seconds), last_tick_at=now)
    )
    db.session.commit()
    return result.rowcount == 1


def lease_row():
    return db.session.get(SchedulerLease, LEASE_NAME)


# --- jobs ----------------------------------------------------------------------

def crl_next_update(ca):
    """Aware nextUpdate of the CA's cached CRL, or None when absent/unparseable."""
    if not ca.crl_pem:
        return None
    try:
        return x509.load_pem_x509_crl(ca.crl_pem.encode()).next_update_utc
    except Exception:
        return None


def crl_is_stale(ca, now_aware, before_days):
    """A CRL is due when it has no nextUpdate or expires within `before_days`."""
    next_update = crl_next_update(ca)
    return next_update is None or next_update <= now_aware + timedelta(days=before_days)


def job_crl_refresh(now):
    """Regenerate every signing-capable CA's CRL that is missing or expires
    within CRL_REFRESH_BEFORE_DAYS. Per-CA failures are audited and skipped."""
    before_days = int(current_app.config.get("CRL_REFRESH_BEFORE_DAYS", 2))
    passphrase = current_app.config["MASTER_PASSPHRASE"]
    now_aware = now.replace(tzinfo=timezone.utc)
    refreshed, failed, fresh = [], [], 0
    for ca in CertificateAuthority.signing_capable().all():
        if not crl_is_stale(ca, now_aware, before_days):
            fresh += 1
            continue
        try:
            crl_service.generate_crl(ca, passphrase)
            audit_service.log_action("crl_refreshed", target_type="ca", target_id=ca.id,
                                     details={"trigger": "scheduler", "crl_number": ca.crl_number},
                                     actor=ACTOR)
            db.session.commit()
            refreshed.append(ca.id)
        except Exception as exc:
            db.session.rollback()
            logger.exception("Scheduled CRL refresh failed for CA %s", ca.id)
            try:
                audit_service.log_action("crl_refresh_failed", target_type="ca", target_id=ca.id,
                                         details={"trigger": "scheduler", "error": str(exc)[:200]},
                                         actor=ACTOR)
                db.session.commit()
            except Exception:
                db.session.rollback()
            failed.append(ca.id)
    return {"refreshed": refreshed, "failed": failed, "fresh": fresh}


def _expiry_details(obj, now):
    days_left = (obj.not_after - now).days
    if isinstance(obj, Certificate):
        return {"common_name": obj.common_name, "serial_number": obj.serial_number,
                "not_after": iso(obj.not_after), "days_left": days_left, "ca_id": obj.ca_id}
    return {"name": obj.name, "common_name": obj.common_name, "not_after": iso(obj.not_after),
            "days_left": days_left, "is_root": obj.is_root}


def _due_for_expiry_event(model, now, warning_days):
    """Unrevoked rows that need an expiry event, in notAfter order:

    - past notAfter and never reported as expired (`expiry_notified_at` is NULL
      or predates notAfter — i.e. only the "expiring soon" event went out), or
    - inside the warning window and never reported at all;
    superseded certificates (renewed, F9) are skipped.

    One timestamp column therefore tracks both stages: a value before notAfter
    means "expiring" was sent, a value after it means "expired" was sent too.
    """
    horizon = now + timedelta(days=warning_days)
    notified = model.expiry_notified_at
    query = model.query.filter(model.is_revoked == False)  # noqa: E712 — matches the filter_by(is_revoked=False) used app-wide
    if model is Certificate:
        # F9: a certificate that already has a renewal is superseded — the
        # reminder belongs to its successor.
        query = query.filter(~model.renewals.any())
    return (query
            .filter(db.or_(
                db.and_(model.not_after <= now,
                        db.or_(notified.is_(None), notified < model.not_after)),
                db.and_(model.not_after > now, model.not_after <= horizon, notified.is_(None)),
            ))
            .order_by(model.not_after).all())


def job_expiry_events(now):
    """Daily (F10): audit `certificate_expiring` / `certificate_expired` /
    `ca_expiring` / `ca_expired` once per object as it crosses
    CERT_EXPIRY_WARNING_DAYS and then notAfter. The audit row is what feeds the
    webhook. Each item is committed on its own so a failure never re-sends
    the ones before it."""
    warning_days = int(current_app.config.get("CERT_EXPIRY_WARNING_DAYS", 30))
    summary = {"certificate_expiring": [], "certificate_expired": [], "ca_expiring": [], "ca_expired": [],
               "failed": []}
    for model, prefix, target_type in ((Certificate, "certificate", "certificate"),
                                       (CertificateAuthority, "ca", "ca")):
        for obj in _due_for_expiry_event(model, now, warning_days):
            action = f"{prefix}_expired" if obj.not_after <= now else f"{prefix}_expiring"
            try:
                audit_service.log_action(action, target_type=target_type, target_id=obj.id,
                                         details=_expiry_details(obj, now), actor=ACTOR)
                obj.expiry_notified_at = now
                db.session.commit()
                summary[action].append(obj.id)
            except Exception:
                db.session.rollback()
                logger.exception("Expiry event %s for %s %s failed", action, target_type, obj.id)
                summary["failed"].append(f"{target_type}:{obj.id}")
    return summary


def job_ocsp_responders(now):
    """Hourly (F7): with OCSP_DELEGATED_RESPONDER on, issue a responder
    certificate for every signing-capable CA that has none, an expired one,
    or one expiring within OCSP_RESPONDER_RENEW_BEFORE_DAYS. Per-CA failures
    are audited and skipped."""
    if not ocsp_service.delegated_enabled():
        return {"disabled": True}
    passphrase = current_app.config["MASTER_PASSPHRASE"]
    rotated, failed, fresh = [], [], 0
    for ca in CertificateAuthority.signing_capable().all():
        try:
            if not ocsp_service.ensure_responder(ca, passphrase):
                fresh += 1
                continue
            audit_service.log_action("ocsp_responder_rotated", target_type="ca", target_id=ca.id,
                                     details={"trigger": "scheduler", **ocsp_service.responder_status(ca)},
                                     actor=ACTOR)
            db.session.commit()
            rotated.append(ca.id)
        except Exception as exc:
            db.session.rollback()
            logger.exception("OCSP responder rotation failed for CA %s", ca.id)
            try:
                audit_service.log_action("ocsp_responder_failed", target_type="ca", target_id=ca.id,
                                         details={"trigger": "scheduler", "error": str(exc)[:200]}, actor=ACTOR)
                db.session.commit()
            except Exception:
                db.session.rollback()
            failed.append(ca.id)
    return {"rotated": rotated, "failed": failed, "fresh": fresh}


# (name, callable, minimum seconds between successful runs; 0 = every tick)
JOBS = (
    ("crl_refresh", job_crl_refresh, 0),
    ("expiry_events", job_expiry_events, DAILY),
    ("ocsp_responders", job_ocsp_responders, 3600),
)


def _job_rows():
    """One SchedulerJob row per configured job, committed before any job runs
    so a later rollback cannot discard them."""
    rows = {}
    missing = False
    for name, _job, _interval in JOBS:
        row = db.session.get(SchedulerJob, name)
        if row is None:
            row = SchedulerJob(name=name)
            db.session.add(row)
            missing = True
        rows[name] = row
    if missing:
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            rows = {name: db.session.get(SchedulerJob, name) for name, _j, _i in JOBS}
    return rows


def job_is_due(row, interval, now):
    return interval <= 0 or row.last_run_at is None or (now - row.last_run_at).total_seconds() >= interval


def tick(now=None, force=False):
    """One scheduler pass: acquire the lease and run every job that is due,
    each isolated from the others. `force` skips both the lease and the
    per-job intervals (the CLI's `scheduler tick --force`). Returns a summary
    dict; `skipped` lists jobs whose interval has not elapsed."""
    now = now or _utcnow()
    summary = {"holder": holder_id(), "at": now.isoformat(), "lease": False, "jobs": {}, "skipped": []}
    if force:
        _ensure_lease_row()  # a forced pass still records its outcome on the row
    elif not acquire_lease(now):
        _state["lease_held"] = False
        return summary
    summary["lease"] = True
    _state["lease_held"] = True
    rows = _job_rows()
    errors = []
    for name, job, interval in JOBS:
        row = rows[name]
        if not force and not job_is_due(row, interval, now):
            summary["skipped"].append(name)
            continue
        try:
            summary["jobs"][name] = job(now)
            row = db.session.get(SchedulerJob, name)  # the job may have rolled back
            row.last_run_at = now
            row.last_error = None
        except Exception as exc:
            db.session.rollback()
            logger.exception("Scheduler job %s failed", name)
            summary["jobs"][name] = {"error": exc.__class__.__name__}
            message = f"{name}: {exc.__class__.__name__}: {str(exc)[:200]}"
            errors.append(message)
            row = db.session.get(SchedulerJob, name)
            row.last_error = message  # last_run_at stays: the job is retried next tick
        db.session.commit()
    _state["last_tick"] = now
    _state["last_summary"] = summary
    lease = lease_row()
    if lease is not None:
        joined = "; ".join(errors) if errors else None
        if joined and joined != lease.last_error:
            # New (or changed) failure: one audit row → webhook; a failure that
            # persists tick after tick is not repeated (metrics show it).
            try:
                audit_service.log_action("scheduler_error", target_type="scheduler",
                                         details={"errors": errors, "at": now.isoformat()}, actor=ACTOR)
            except Exception:
                logger.exception("Could not audit scheduler_error")
        lease.last_error = joined
        db.session.commit()
    return summary


def local_state():
    return dict(_state, holder=holder_id(), thread_alive=bool(_thread and _thread.is_alive()))


def jobs_status():
    """Per-job interval and last successful run (from `scheduler_jobs`)."""
    out = {}
    for name, _job, interval in JOBS:
        row = db.session.get(SchedulerJob, name)
        out[name] = {
            "interval_seconds": interval,
            "last_run_at": row.last_run_at.isoformat() if row is not None and row.last_run_at else None,
            "last_error": row.last_error if row is not None else None,
        }
    return out


def status():
    """Lease row, job rows, this process's view, and the effective config —
    for the CLI and metrics."""
    row = lease_row()
    return {
        "lease": None if row is None else {
            "holder": row.holder,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "last_tick_at": row.last_tick_at.isoformat() if row.last_tick_at else None,
            "last_error": row.last_error,
        },
        "jobs": jobs_status(),
        "this_process": local_state(),
        "config": {
            "enabled": bool(current_app.config.get("SCHEDULER_ENABLED", True)),
            "tick_seconds": int(current_app.config.get("SCHEDULER_TICK_SECONDS", 60)),
            "crl_refresh_before_days": int(current_app.config.get("CRL_REFRESH_BEFORE_DAYS", 2)),
            "cert_expiry_warning_days": int(current_app.config.get("CERT_EXPIRY_WARNING_DAYS", 30)),
        },
    }
