"""Scheduler lease row (F8, 2.17.0).

gunicorn runs several workers and each starts the scheduler thread; the lease
makes exactly one of them run the jobs. A worker acquires it with a single
conditional UPDATE (expired, unset, or already mine) and renews it every
tick; if that worker dies, the lease expires and another takes over.
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
