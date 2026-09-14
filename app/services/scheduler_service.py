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
recorded on the lease row (and, for CRLs, in the audit log).
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
from ..models.scheduler_lease import SchedulerLease
from . import audit_service, crl_service

LEASE_NAME = "main"
ENV_FLAG = "CHANCERY_RUN_SCHEDULER"
ACTOR = "scheduler"

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


JOBS = (("crl_refresh", job_crl_refresh),)


def tick(now=None, force=False):
    """One scheduler pass: acquire the lease (unless `force`) and run every
    job, each isolated from the others. Returns a summary dict."""
    now = now or _utcnow()
    summary = {"holder": holder_id(), "at": now.isoformat(), "lease": False, "jobs": {}}
    if force:
        _ensure_lease_row()  # a forced pass still records its outcome on the row
    elif not acquire_lease(now):
        _state["lease_held"] = False
        return summary
    summary["lease"] = True
    _state["lease_held"] = True
    errors = []
    for name, job in JOBS:
        try:
            summary["jobs"][name] = job(now)
        except Exception as exc:
            db.session.rollback()
            logger.exception("Scheduler job %s failed", name)
            summary["jobs"][name] = {"error": exc.__class__.__name__}
            errors.append(f"{name}: {exc.__class__.__name__}: {str(exc)[:200]}")
    _state["last_tick"] = now
    _state["last_summary"] = summary
    row = lease_row()
    if row is not None:
        row.last_error = "; ".join(errors) if errors else None
        db.session.commit()
    return summary


def local_state():
    return dict(_state, holder=holder_id(), thread_alive=bool(_thread and _thread.is_alive()))


def status():
    """Lease row + this process's view, for the CLI and metrics."""
    row = lease_row()
    return {
        "lease": None if row is None else {
            "holder": row.holder,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "last_tick_at": row.last_tick_at.isoformat() if row.last_tick_at else None,
            "last_error": row.last_error,
        },
        "this_process": local_state(),
        "config": {
            "enabled": bool(current_app.config.get("SCHEDULER_ENABLED", True)),
            "tick_seconds": int(current_app.config.get("SCHEDULER_TICK_SECONDS", 60)),
            "crl_refresh_before_days": int(current_app.config.get("CRL_REFRESH_BEFORE_DAYS", 2)),
        },
    }
