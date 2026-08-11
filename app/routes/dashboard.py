from datetime import datetime, timedelta, timezone

from flask import Blueprint, render_template, jsonify, current_app
from flask_login import login_required, current_user

from ..models.ca import CertificateAuthority
from ..models.certificate import Certificate
from ..models.csr import CertificateSigningRequest
from ..responses import wants_json

dashboard_bp = Blueprint("dashboard", __name__)


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
        recent_certs = Certificate.query.order_by(Certificate.created_at.desc()).limit(10).all()
        recent_cas = CertificateAuthority.query.order_by(CertificateAuthority.created_at.desc()).limit(10).all()
        if wants_json():
            return jsonify({
                "stats": stats,
                "recent_cas": [ca.to_dict() for ca in recent_cas],
                "recent_certs": [c.to_dict() for c in recent_certs],
            })
        return render_template("dashboard.html", stats=stats, recent_certs=recent_certs, recent_cas=recent_cas)
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
        ).order_by(CertificateSigningRequest.created_at.desc()).limit(10).all()
        if wants_json():
            return jsonify({
                "stats": stats,
                "recent_csrs": [c.to_dict() for c in recent_csrs],
            })
        return render_template("dashboard.html", stats=stats, recent_csrs=recent_csrs)
