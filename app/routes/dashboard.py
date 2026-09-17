from datetime import datetime, timedelta, timezone

from flask import Blueprint, render_template, jsonify, current_app
from flask_login import login_required, current_user

from ..models.audit_log import AuditLog
from ..models.ca import CertificateAuthority
from ..models.certificate import Certificate
from ..models.csr import CertificateSigningRequest
from ..responses import wants_json

dashboard_bp = Blueprint("dashboard", __name__)

# Rows fetched for the "Recent" panels (the JSON API answers a stable 10; the
# 3.0 dashboard shows the first RECENT_SHOWN and links to the filtered lists).
_RECENT_POOL = 10
RECENT_SHOWN = 8
ATTENTION_ROWS = 6


@dashboard_bp.route("/")
@login_required
def index():
    if current_user.is_admin:
        # Expiry counts (active certs only). notAfter is stored naive-UTC, so
        # compare against naive-UTC bounds.
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        soon = now + timedelta(days=current_app.config.get("CERT_EXPIRY_WARNING_DAYS", 30))
        stats = {
            "ca_count": CertificateAuthority.query.filter_by(is_revoked=False).count(),
            "cert_count": Certificate.query.count(),
            "cert_active": Certificate.query.filter_by(is_revoked=False).count(),
            "cert_revoked": Certificate.query.filter_by(is_revoked=True).count(),
            "cert_expiring_soon": Certificate.query.filter_by(is_revoked=False).filter(
                Certificate.not_after >= now, Certificate.not_after <= soon).count(),
            "cert_expired": Certificate.query.filter_by(is_revoked=False).filter(
                Certificate.not_after < now).count(),
            "csr_pending": CertificateSigningRequest.query.filter_by(status="pending").count(),
            "csr_total": CertificateSigningRequest.query.count(),
        }
        recent_certs = Certificate.query.order_by(Certificate.created_at.desc()).limit(_RECENT_POOL).all()
        recent_cas = CertificateAuthority.query.order_by(CertificateAuthority.created_at.desc()).limit(_RECENT_POOL).all()
        if wants_json():
            return jsonify({
                "stats": stats,
                "recent_cas": [ca.to_dict() for ca in recent_cas[:10]],
                "recent_certs": [c.to_dict() for c in recent_certs[:10]],
            })
        # 3.0 dashboard: what needs a hand, the signing CAs' health, recent activity.
        attention = {
            "expiring": Certificate.query.filter_by(is_revoked=False).filter(
                Certificate.not_after >= now, Certificate.not_after <= soon)
                .order_by(Certificate.not_after.asc()).limit(ATTENTION_ROWS).all(),
            "pending_csrs": CertificateSigningRequest.query.filter_by(status="pending")
                .order_by(CertificateSigningRequest.created_at.asc()).limit(ATTENTION_ROWS).all(),
            "pending_cas": CertificateAuthority.query.filter_by(approval_status="pending", is_revoked=False)
                .order_by(CertificateAuthority.created_at.asc()).limit(ATTENTION_ROWS).all(),
        }
        signing_cas = CertificateAuthority.signing_capable().order_by(CertificateAuthority.not_after.asc()).all()
        activity = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(RECENT_SHOWN).all()
        return render_template("dashboard.html", stats=stats, recent_certs=recent_certs[:RECENT_SHOWN],
                               recent_cas=recent_cas[:RECENT_SHOWN], attention=attention,
                               signing_cas=signing_cas, activity=activity,
                               warning_days=current_app.config.get("CERT_EXPIRY_WARNING_DAYS", 30))
    else:
        stats = {
            "csr_pending": CertificateSigningRequest.query.filter_by(
                created_by=current_user.id, status="pending"
            ).count(),
            "csr_approved": CertificateSigningRequest.query.filter_by(
                created_by=current_user.id, status="approved"
            ).count(),
            "csr_total": CertificateSigningRequest.query.filter_by(
                created_by=current_user.id
            ).count(),
        }
        recent_csrs = CertificateSigningRequest.query.filter_by(
            created_by=current_user.id
        ).order_by(CertificateSigningRequest.created_at.desc()).limit(_RECENT_POOL).all()
        if wants_json():
            return jsonify({
                "stats": stats,
                "recent_csrs": [c.to_dict() for c in recent_csrs[:10]],
            })
        recent_certs = Certificate.query.filter_by(requested_by=current_user.id).order_by(
            Certificate.created_at.desc()).limit(RECENT_SHOWN).all()
        return render_template("dashboard.html", stats=stats, recent_csrs=recent_csrs[:RECENT_SHOWN],
                               recent_certs=recent_certs)
