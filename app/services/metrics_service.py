"""Prometheus exposition for cert-manager (2.7.0).

A ``prometheus_client`` custom collector whose ``collect()`` runs the DB queries
at scrape time and yields metric families. Called only from the ``/metrics`` view
(gated by ``METRICS_ENABLED`` + a bearer token).

Exposure is minimal by default: per-CA series are keyed by the **opaque** ``ca_id``
only. CA names / subject CNs / key details appear ONLY in ``cert_manager_ca_info``,
and only when ``METRICS_INCLUDE_CA_DETAILS`` is enabled — join it on ``ca_id``.

State semantics mirror the dashboard (``app/routes/dashboard.py``): naive-UTC
``now``/``soon`` bounds, ``revoked`` wins, then ``expired`` < now, ``expiring_soon``
within ``CERT_EXPIRY_WARNING_DAYS``, else ``valid``.
"""
import os
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from prometheus_client import CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
from prometheus_client.core import GaugeMetricFamily
from sqlalchemy import and_, case, func

from .._version import __version__
from ..extensions import db
from ..models.audit_log import AuditLog
from ..models.ca import CertificateAuthority
from ..models.certificate import Certificate
from ..models.csr import CertificateSigningRequest
from ..models.user import User

CONTENT_TYPE = CONTENT_TYPE_LATEST

_CERT_STATES = ("valid", "expiring_soon", "expired", "revoked")

# Parsing a CRL is a real X.509 parse; memoise per CA keyed on crl_number so an
# unchanged CRL is parsed once across scrapes (crl_number bumps on regeneration).
_CRL_CACHE = {}  # ca_id -> (crl_number, next_update_ts | None)


def _unix(dt):
    """Naive-UTC (or aware) datetime -> Unix seconds; None passthrough.

    Stored datetimes are naive-UTC; ``datetime.timestamp()`` on a naive value
    would assume host-local time, so pin UTC first.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _crl_next_update_ts(ca):
    """CRL nextUpdate as Unix seconds, parsed from the stored PEM; None if the CA
    has no CRL or it can't be parsed. Never raises."""
    if not ca.crl_pem:
        return None
    cached = _CRL_CACHE.get(ca.id)
    if cached is not None and cached[0] == ca.crl_number:
        return cached[1]
    try:
        crl = x509.load_pem_x509_crl(ca.crl_pem.encode())
        nu = crl.next_update_utc
        ts = nu.timestamp() if nu is not None else None
    except Exception:
        ts = None
    _CRL_CACHE[ca.id] = (ca.crl_number, ts)
    return ts


def _ca_state(ca, now, soon):
    if ca.is_revoked:
        return "revoked"
    na = ca.not_after
    if na is None:
        return "valid"
    if na < now:
        return "expired"
    if na <= soon:
        return "expiring_soon"
    return "valid"


class CertManagerCollector:
    def __init__(self, config):
        self.config = config

    def collect(self):
        start = time.perf_counter()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        soon = now + timedelta(days=self.config.get("CERT_EXPIRY_WARNING_DAYS", 30))
        include_details = bool(self.config.get("METRICS_INCLUDE_CA_DETAILS", False))

        # --- build info ---------------------------------------------------
        version = os.environ.get("APP_VERSION") or __version__
        bi = GaugeMetricFamily(
            "cert_manager_build_info",
            "Build information for the running cert-manager instance.",
            labels=["version"])
        bi.add_metric([version], 1)
        yield bi

        # --- certificates by state: grouped conditional-sum per CA --------
        rows = db.session.query(
            Certificate.ca_id,
            func.coalesce(func.sum(case((Certificate.is_revoked.is_(True), 1), else_=0)), 0),
            func.coalesce(func.sum(case(
                (and_(Certificate.is_revoked.is_(False), Certificate.not_after < now), 1), else_=0)), 0),
            func.coalesce(func.sum(case(
                (and_(Certificate.is_revoked.is_(False),
                      Certificate.not_after >= now, Certificate.not_after <= soon), 1), else_=0)), 0),
            func.coalesce(func.sum(case(
                (and_(Certificate.is_revoked.is_(False), Certificate.not_after > soon), 1), else_=0)), 0),
        ).group_by(Certificate.ca_id).all()

        cert_totals = {s: 0 for s in _CERT_STATES}
        per_ca_counts = {}
        for ca_id, revoked, expired, expiring_soon, valid in rows:
            counts = {"revoked": int(revoked), "expired": int(expired),
                      "expiring_soon": int(expiring_soon), "valid": int(valid)}
            per_ca_counts[ca_id] = counts
            for s in _CERT_STATES:
                cert_totals[s] += counts[s]

        certs = GaugeMetricFamily(
            "cert_manager_certificates",
            "End-entity certificates by state (mutually exclusive; sum = total).",
            labels=["state"])
        for s in _CERT_STATES:
            certs.add_metric([s], cert_totals[s])
        yield certs

        # --- CAs: one pass computes every CA family + per-CA series --------
        cas = CertificateAuthority.query.all()
        ca_states = {s: 0 for s in _CERT_STATES}
        ca_backend, ca_type = {}, {"root": 0, "intermediate": 0}
        signing_capable = 0

        ca_expiry = GaugeMetricFamily(
            "cert_manager_ca_expiry_timestamp_seconds",
            "CA certificate notAfter as a Unix timestamp.", labels=["ca_id"])
        ca_crl_next = GaugeMetricFamily(
            "cert_manager_ca_crl_next_update_timestamp_seconds",
            "CA CRL nextUpdate as a Unix timestamp (parsed from the stored CRL).",
            labels=["ca_id"])
        ca_crl_num = GaugeMetricFamily(
            "cert_manager_ca_crl_number", "Current CRL number for the CA.",
            labels=["ca_id"])
        ca_certs = GaugeMetricFamily(
            "cert_manager_ca_certificates",
            "Certificates issued by each CA, by state.", labels=["ca_id", "state"])
        ca_info = GaugeMetricFamily(
            "cert_manager_ca_info",
            "Per-CA descriptive info (opt-in; reveals CA name/CN/key details). "
            "Join to the numeric series on ca_id.",
            labels=["ca_id", "name", "common_name", "is_root",
                    "key_backend", "key_type", "key_size"])

        for ca in cas:
            cid = str(ca.id)
            ca_states[_ca_state(ca, now, soon)] += 1
            ca_backend[ca.key_backend] = ca_backend.get(ca.key_backend, 0) + 1
            ca_type["root" if ca.is_root else "intermediate"] += 1
            if not ca.is_revoked and ca.has_signing_key and ca.approval_status == "approved":
                signing_capable += 1

            exp = _unix(ca.not_after)
            if exp is not None:
                ca_expiry.add_metric([cid], exp)
            ca_crl_num.add_metric([cid], ca.crl_number or 0)
            nu = _crl_next_update_ts(ca)
            if nu is not None:
                ca_crl_next.add_metric([cid], nu)
            counts = per_ca_counts.get(ca.id)
            for s in _CERT_STATES:
                ca_certs.add_metric([cid, s], counts[s] if counts else 0)

            if include_details:
                ca_info.add_metric(
                    [cid, ca.name or "", ca.common_name or "",
                     "true" if ca.is_root else "false", ca.key_backend or "",
                     ca.key_type or "", str(ca.key_size or "")], 1)

        caf = GaugeMetricFamily(
            "cert_manager_certificate_authorities",
            "Certificate authorities by state (sum = total CAs).", labels=["state"])
        for s in _CERT_STATES:
            caf.add_metric([s], ca_states[s])
        yield caf

        bf = GaugeMetricFamily(
            "cert_manager_certificate_authorities_by_backend",
            "Certificate authorities by signing-key backend.", labels=["backend"])
        for backend, n in sorted(ca_backend.items()):
            bf.add_metric([backend], n)
        yield bf

        tf = GaugeMetricFamily(
            "cert_manager_certificate_authorities_by_type",
            "Certificate authorities by root/intermediate.", labels=["type"])
        for t in ("root", "intermediate"):
            tf.add_metric([t], ca_type[t])
        yield tf

        yield GaugeMetricFamily(
            "cert_manager_certificate_authorities_signing_capable",
            "CAs able to sign (not revoked and holding a usable key).",
            value=signing_capable)

        yield ca_expiry
        yield ca_crl_next
        yield ca_crl_num
        yield ca_certs
        if include_details:
            yield ca_info

        # --- CSRs by status (closed set, zero-seeded) ---------------------
        csr_counts = {"pending": 0, "approved": 0, "rejected": 0}
        for status, n in db.session.query(
                CertificateSigningRequest.status, func.count()
        ).group_by(CertificateSigningRequest.status).all():
            if status in csr_counts:
                csr_counts[status] = int(n)
        csrf = GaugeMetricFamily(
            "cert_manager_csrs", "Certificate signing requests by status.",
            labels=["status"])
        for status in ("pending", "approved", "rejected"):
            csrf.add_metric([status], csr_counts[status])
        yield csrf

        # --- users --------------------------------------------------------
        users_role = {"admin": 0, "csr_requester": 0}
        for role, n in db.session.query(User.role, func.count()).group_by(User.role).all():
            users_role[role] = int(n)
        uf = GaugeMetricFamily(
            "cert_manager_users", "User accounts by role.", labels=["role"])
        for role in ("admin", "csr_requester"):
            uf.add_metric([role], users_role.get(role, 0))
        yield uf

        active = db.session.query(func.count()).select_from(User).filter(
            User.is_active_user.is_(True)).scalar()
        yield GaugeMetricFamily(
            "cert_manager_users_active", "Active user accounts.", value=active or 0)
        locked = db.session.query(func.count()).select_from(User).filter(
            User.locked_until.isnot(None), User.locked_until > now).scalar()
        yield GaugeMetricFamily(
            "cert_manager_users_locked", "Currently locked user accounts.",
            value=locked or 0)

        # --- audit --------------------------------------------------------
        audit_total = db.session.query(func.count()).select_from(AuditLog).scalar()
        yield GaugeMetricFamily(
            "cert_manager_audit_events", "Total audit-log entries.",
            value=audit_total or 0)

        # --- scrape self-timing (last) ------------------------------------
        yield GaugeMetricFamily(
            "cert_manager_scrape_duration_seconds",
            "Time spent building this metrics response, in seconds.",
            value=time.perf_counter() - start)


def render(config):
    """Collect and serialise all metrics to the Prometheus text format (bytes)."""
    registry = CollectorRegistry()
    registry.register(CertManagerCollector(config))
    return generate_latest(registry)
