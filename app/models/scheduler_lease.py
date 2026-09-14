"""Scheduler bookkeeping rows (F8, 2.17.0; F10, 2.18.0).

gunicorn runs several workers and each starts the scheduler thread; the lease
makes exactly one of them run the jobs. A worker acquires it with a single
conditional UPDATE (expired, unset, or already mine) and renews it every
tick; if that worker dies, the lease expires and another takes over.

`scheduler_jobs` holds one row per job so a job with an interval (the daily
expiry-events pass) runs on schedule across restarts and worker hand-overs:
the lease holder reads `last_run_at` before running it.
"""
from ..extensions import db


class SchedulerLease(db.Model):
    __tablename__ = "scheduler_leases"

    name = db.Column(db.String(50), primary_key=True)
    holder = db.Column(db.String(160), nullable=True)      # hostname:pid:random
    expires_at = db.Column(db.DateTime, nullable=True)     # naive UTC
    last_tick_at = db.Column(db.DateTime, nullable=True)   # naive UTC
    last_error = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<SchedulerLease {self.name} holder={self.holder} expires={self.expires_at}>"


class SchedulerJob(db.Model):
    __tablename__ = "scheduler_jobs"

    name = db.Column(db.String(50), primary_key=True)
    last_run_at = db.Column(db.DateTime, nullable=True)    # naive UTC; last SUCCESSFUL run
    last_error = db.Column(db.Text, nullable=True)         # None once the job succeeds again

    def __repr__(self):
        return f"<SchedulerJob {self.name} last_run={self.last_run_at}>"
