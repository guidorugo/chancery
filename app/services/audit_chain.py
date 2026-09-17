"""F16 (3.3.0): audit-log integrity — hash chain, anchors, verification,
retention and export.

Chain: every `audit_logs` row gets `entry_hash = SHA-256(prev_hash || "\\n" ||
canonical JSON of the row)` where `prev_hash` is the previous row's entry_hash
("" for the first row). Rows are written unsealed by whatever request or job
produced them; sealing happens in id order by the scheduler's lease holder
(`seal()`), so concurrent gunicorn workers cannot fork the chain. Two guards
keep an in-flight transaction from being skipped: rows younger than
AUDIT_SEAL_GRACE_SECONDS are left for the next tick, and sealing stops at an id
gap (SQLite hands out contiguous ids; a gap means an uncommitted insert).
Sealing is deterministic, so a concurrent `flask audit seal` cannot disagree.

Anchor: the daily `audit_anchor` job appends an `audit_anchor` row carrying the
head hash and row count; through the webhook stream a receiver keeps an
out-of-band record that a rewritten chain cannot satisfy.

Retention (G10-3): with AUDIT_RETENTION_DAYS > 0 the daily `audit_prune` job
exports sealed rows older than the window to a JSON-lines file under
AUDIT_ARCHIVE_DIR, deletes them and appends an `audit_checkpoint` row whose
details carry the last pruned id and hash, so `verify()` can start from the
checkpoint instead of the (now gone) first row.
"""
import csv
import hashlib
import io
import json
import os
from datetime import datetime, timedelta, timezone

from flask import current_app
from sqlalchemy import func

from ..extensions import db
from ..models.audit_log import AuditLog
from ..serialization import iso

GENESIS = ""
CANONICAL_FIELDS = ("id", "timestamp", "user_id", "username", "action", "target_type", "target_id", "details", "ip_address")


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def canonical(row):
    """The bytes that are hashed: the row's stored fields, sorted keys, no spaces."""
    data = {
        "id": row.id, "timestamp": iso(row.timestamp), "user_id": row.user_id, "username": row.username,
        "action": row.action, "target_type": row.target_type, "target_id": row.target_id,
        "details": row.details, "ip_address": row.ip_address,
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_hash(row, prev_hash):
    return hashlib.sha256((prev_hash or GENESIS).encode("ascii") + b"\n" + canonical(row)).hexdigest()


# --- sealing ---------------------------------------------------------------

def head():
    """(id, entry_hash) of the last sealed row, or (None, GENESIS)."""
    row = (AuditLog.query.filter(AuditLog.entry_hash.isnot(None))
           .order_by(AuditLog.id.desc()).first())
    return (row.id, row.entry_hash) if row else (None, GENESIS)


def seal(now=None, grace_seconds=None):
    """Seal unsealed rows in id order. Returns a summary dict."""
    now = now or utcnow()
    if grace_seconds is None:
        grace_seconds = int(current_app.config.get("AUDIT_SEAL_GRACE_SECONDS", 5))
    cutoff = now - timedelta(seconds=grace_seconds)
    head_id, prev = head()
    pending = (AuditLog.query.filter(AuditLog.entry_hash.is_(None))
               .filter(AuditLog.id > (head_id or 0))
               .order_by(AuditLog.id).all())
    sealed, stopped = 0, None
    expected_id = (head_id or 0) + 1 if head_id is not None else None
    for row in pending:
        if expected_id is not None and row.id != expected_id:
            stopped = f"gap before #{row.id}"     # an uncommitted insert holds the id in between
            break
        if row.timestamp and row.timestamp > cutoff:
            stopped = f"#{row.id} younger than the grace period"
            break
        row.prev_hash = prev
        row.entry_hash = compute_hash(row, prev)
        prev = row.entry_hash
        head_id = row.id
        expected_id = row.id + 1
        sealed += 1
    db.session.commit()
    unsealed = AuditLog.query.filter(AuditLog.entry_hash.is_(None)).count()
    return {"sealed": sealed, "head_id": head_id, "head_hash": prev if head_id else None,
            "unsealed": unsealed, "stopped": stopped}


def status():
    """Cheap integrity summary for the page / JSON."""
    head_id, head_hash = head()
    unsealed = AuditLog.query.filter(AuditLog.entry_hash.is_(None)).count()
    anchor = AuditLog.query.filter_by(action="audit_anchor").order_by(AuditLog.id.desc()).first()
    checkpoint = AuditLog.query.filter_by(action="audit_checkpoint").order_by(AuditLog.id.desc()).first()
    return {"head_id": head_id, "head_hash": head_hash or None, "unsealed": unsealed,
            "total": AuditLog.query.count(),
            "last_anchor": anchor.to_dict() if anchor else None,
            "last_checkpoint": checkpoint.to_dict() if checkpoint else None,
            "retention_days": int(current_app.config.get("AUDIT_RETENTION_DAYS", 0) or 0)}


# --- verification -----------------------------------------------------------

def _checkpoint_for(first_row):
    """The checkpoint row that explains why rows before `first_row` are gone."""
    for cp in AuditLog.query.filter_by(action="audit_checkpoint").order_by(AuditLog.id.desc()).all():
        try:
            details = json.loads(cp.details or "{}")
        except ValueError:
            continue
        if details.get("pruned_through_id") == first_row.id - 1:
            return cp, details
    return None, None


def verify(from_id=None):
    """Walk the chain in id order. Returns a report; `ok` is False on the first
    row whose hash does not match (edited or missing predecessor)."""
    q = AuditLog.query.order_by(AuditLog.id)
    if from_id:
        q = q.filter(AuditLog.id >= from_id)
    rows = q.all()
    report = {"ok": True, "checked": 0, "first_bad_id": None, "reason": None, "start": None,
              "head_id": None, "head_hash": None, "unsealed": 0}
    if not rows:
        report["start"] = "empty"
        return report
    first = rows[0]
    if first.entry_hash is None:
        report["unsealed"] = sum(1 for r in rows if r.entry_hash is None)
        report["start"] = "unsealed"
        return report
    if from_id:
        prev = first.prev_hash or GENESIS
        report["start"] = f"#{first.id} (prev_hash taken as given)"
    elif not first.prev_hash:
        prev = GENESIS
        report["start"] = "genesis"
    else:
        cp, details = _checkpoint_for(first)
        if cp is None or details.get("pruned_through_hash") != first.prev_hash:
            report.update(ok=False, first_bad_id=first.id,
                          reason="the first row links to a predecessor that is gone and no checkpoint vouches for it",
                          start="unverifiable")
            return report
        prev = first.prev_hash
        report["start"] = f"checkpoint #{cp.id} (pruned through #{details.get('pruned_through_id')})"
    expected_id = first.id
    for row in rows:
        if row.entry_hash is None:
            report["unsealed"] += 1
            if any(r.entry_hash is not None for r in rows if r.id > row.id):
                report.update(ok=False, first_bad_id=row.id, reason="unsealed row inside the sealed range")
                return report
            continue
        if row.id != expected_id:
            report.update(ok=False, first_bad_id=row.id, reason=f"rows #{expected_id}–#{row.id - 1} are missing")
            return report
        if (row.prev_hash or GENESIS) != prev:
            report.update(ok=False, first_bad_id=row.id, reason="prev_hash does not match the previous row")
            return report
        if compute_hash(row, prev) != row.entry_hash:
            report.update(ok=False, first_bad_id=row.id, reason="entry_hash does not match the row's contents")
            return report
        prev = row.entry_hash
        expected_id = row.id + 1
        report["checked"] += 1
        report["head_id"], report["head_hash"] = row.id, row.entry_hash
    return report


# --- anchor ------------------------------------------------------------------

def anchor(actor="scheduler"):
    """Append an `audit_anchor` row (head id/hash + sealed count) — the webhook
    stream carries it to an out-of-band receiver."""
    from . import audit_service
    head_id, head_hash = head()
    sealed = AuditLog.query.filter(AuditLog.entry_hash.isnot(None)).count()
    details = {"head_id": head_id, "head_hash": head_hash or None, "sealed_rows": sealed}
    audit_service.log_action("audit_anchor", target_type="audit_log", target_id=head_id, details=details, actor=actor)
    db.session.commit()
    return details


# --- retention -----------------------------------------------------------------

def archive_dir():
    configured = current_app.config.get("AUDIT_ARCHIVE_DIR")
    if configured:
        return configured
    uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if uri.startswith("sqlite:///") and not uri.endswith(":memory:") and uri != "sqlite://":
        path = uri[len("sqlite:///"):]
        if path and path not in (":memory:",):
            return os.path.join(os.path.dirname(os.path.abspath(path)), "audit-archive")
    return os.path.join(current_app.instance_path, "audit-archive")


def prune(now=None, dry_run=False, actor="scheduler"):
    """Export and delete sealed rows older than AUDIT_RETENTION_DAYS, then append a checkpoint."""
    days = int(current_app.config.get("AUDIT_RETENTION_DAYS", 0) or 0)
    if days <= 0:
        return {"disabled": True}
    now = now or utcnow()
    cutoff = now - timedelta(days=days)
    # never prune the integrity rows themselves past the newest checkpoint/anchor? They are
    # ordinary rows: what matters is that the chain stays verifiable from the checkpoint.
    rows = (AuditLog.query.filter(AuditLog.entry_hash.isnot(None), AuditLog.timestamp < cutoff)
            .order_by(AuditLog.id).all())
    if not rows:
        return {"pruned": 0}
    # only a contiguous prefix of the chain may go (ids must stay contiguous)
    first_id = db.session.query(func.min(AuditLog.id)).scalar()
    if rows[0].id != first_id:
        return {"pruned": 0, "skipped": f"rows before #{rows[0].id} are unsealed"}
    contiguous = []
    expected = first_id
    for r in rows:
        if r.id != expected:
            break
        contiguous.append(r)
        expected = r.id + 1
    rows = contiguous
    result = {"pruned": len(rows), "from_id": rows[0].id, "through_id": rows[-1].id,
              "through_hash": rows[-1].entry_hash, "dry_run": dry_run}
    if dry_run:
        return result
    directory = archive_dir()
    os.makedirs(directory, exist_ok=True)
    filename = f"audit-{rows[0].id}-{rows[-1].id}-{now:%Y%m%dT%H%M%SZ}.jsonl"
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r.to_dict(), sort_keys=True, ensure_ascii=True) + "\n")
    os.chmod(path, 0o600)
    ids = [r.id for r in rows]
    AuditLog.query.filter(AuditLog.id.in_(ids)).delete(synchronize_session=False)
    from . import audit_service
    audit_service.log_action("audit_checkpoint", target_type="audit_log", target_id=rows[-1].id, actor=actor,
                             details={"pruned_from_id": rows[0].id, "pruned_through_id": rows[-1].id,
                                      "pruned_through_hash": rows[-1].entry_hash, "rows": len(rows),
                                      "file": filename, "retention_days": days})
    db.session.commit()
    result["file"] = path
    return result


# --- export -------------------------------------------------------------------

EXPORT_COLUMNS = ("id", "timestamp", "username", "user_id", "action", "target_type", "target_id",
                  "ip_address", "details", "prev_hash", "entry_hash")


def iter_csv(query, chunk=500):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(EXPORT_COLUMNS)
    yield buf.getvalue(); buf.seek(0); buf.truncate(0)
    for row in query.yield_per(chunk):
        writer.writerow([row.id, iso(row.timestamp), row.username, row.user_id, row.action, row.target_type,
                         row.target_id, row.ip_address, row.details or "", row.prev_hash or "", row.entry_hash or ""])
        yield buf.getvalue(); buf.seek(0); buf.truncate(0)


def iter_json(query, chunk=500):
    yield "["
    first = True
    for row in query.yield_per(chunk):
        yield ("" if first else ",\n") + json.dumps(row.to_dict(), sort_keys=True)
        first = False
    yield "]\n"


def iter_jsonl(query, chunk=500):
    for row in query.yield_per(chunk):
        yield json.dumps(row.to_dict(), sort_keys=True) + "\n"
