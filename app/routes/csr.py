import json
import logging

from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, current_app, Response, jsonify,
)
from flask_login import login_required, current_user

from ..decorators import admin_required
from ..extensions import db
from ..models.ca import CertificateAuthority
from ..models.csr import CertificateSigningRequest
from ..responses import api_error, wants_json
from ..services import csr_service, cert_service, audit_service, dual_control_service

logger = logging.getLogger(__name__)

csr_bp = Blueprint("csr", __name__, url_prefix="/csr")


@csr_bp.route("/")
@login_required
def list_csrs():
    if current_user.is_admin:
        csrs = CertificateSigningRequest.query.order_by(
            CertificateSigningRequest.created_at.desc()
        ).all()
    else:
        csrs = CertificateSigningRequest.query.filter_by(
            created_by=current_user.id
        ).order_by(CertificateSigningRequest.created_at.desc()).all()
    if wants_json():
        return jsonify([c.to_dict() for c in csrs])
    return render_template("csr/list.html", csrs=csrs)


@csr_bp.route("/create", methods=["GET", "POST"])
@login_required
def create():
    def _err(message, status=400):
        if wants_json():
            return api_error(message, status)
        flash(message, "danger")
        return render_template("csr/create.html")

    if request.method == "POST":
        mode = request.form.get("mode", "generate")

        if mode == "upload":
            csr_pem = request.form.get("csr_pem", "").strip()
            if not csr_pem:
                return _err("CSR PEM data is required.")
            try:
                csr_model = csr_service.import_csr(csr_pem, created_by=current_user.id)
                audit_service.log_action("import_csr", target_type="csr", target_id=csr_model.id)
                db.session.commit()
                if wants_json():
                    return jsonify(csr_model.to_dict(detail=True)), 201
                flash(f"CSR for '{csr_model.common_name}' imported.", "success")
                return redirect(url_for("csr.detail", csr_id=csr_model.id))
            except Exception:
                logger.exception("Error importing CSR")
                return _err("An unexpected error occurred while importing the CSR.", 500)
        else:
            cn = request.form.get("cn", "").strip()
            org = request.form.get("org", "").strip()
            ou = request.form.get("ou", "").strip()
            country = request.form.get("country", "").strip()
            state = request.form.get("state", "").strip()
            locality = request.form.get("locality", "").strip()
            key_type = request.form.get("key_type", "RSA")
            san_raw = request.form.get("san", "").strip()

            try:
                key_size = int(request.form.get("key_size", "2048"))
            except ValueError:
                return _err("Key size must be a valid number.")

            if not cn:
                return _err("Common Name is required.")

            subject_attrs = {
                "CN": cn, "O": org, "OU": ou,
                "C": country, "ST": state, "L": locality,
            }
            san_list = [s.strip() for s in san_raw.split("\n") if s.strip()] if san_raw else []
            passphrase = current_app.config["MASTER_PASSPHRASE"]

            try:
                csr_model, key_pem, _ = csr_service.create_csr(
                    subject_attrs, san_list, key_type, key_size, passphrase,
                    created_by=current_user.id,
                )
                audit_service.log_action("create_csr", target_type="csr", target_id=csr_model.id)
                db.session.commit()
                if wants_json():
                    # The private key is returned once here — it is never stored.
                    payload = csr_model.to_dict(detail=True)
                    payload["private_key_pem"] = key_pem.decode() if key_pem else None
                    return jsonify(payload), 201
                flash(
                    f"CSR for '{csr_model.common_name}' created. "
                    "Download the private key now - it won't be stored.",
                    "warning",
                )
                return render_template(
                    "csr/detail.html", csr=csr_model,
                    key_pem=key_pem.decode() if key_pem else None,
                )
            except ValueError as e:
                # Invalid input (e.g. a bad subject field) — surface the
                # specific reason as a 400 rather than a generic 500.
                return _err(str(e))
            except Exception:
                logger.exception("Error creating CSR")
                return _err("An unexpected error occurred while creating the CSR.", 500)

    return render_template("csr/create.html")


@csr_bp.route("/<int:csr_id>")
@login_required
def detail(csr_id):
    csr_model = db.session.get(CertificateSigningRequest, csr_id)
    if not csr_model:
        if wants_json():
            return api_error("CSR not found.", 404)
        flash("CSR not found.", "danger")
        return redirect(url_for("csr.list_csrs"))

    if not current_user.is_admin and csr_model.created_by != current_user.id:
        if wants_json():
            return api_error("You do not have permission to view this CSR.", 403)
        flash("You do not have permission to view this CSR.", "danger")
        return redirect(url_for("csr.list_csrs"))

    if wants_json():
        return jsonify(csr_model.to_dict(detail=True))

    san_list = json.loads(csr_model.san_json) if csr_model.san_json else []
    return render_template("csr/detail.html", csr=csr_model, san_list=san_list)


@csr_bp.route("/<int:csr_id>/sign", methods=["GET", "POST"])
@admin_required
def sign(csr_id):
    csr_model = db.session.get(CertificateSigningRequest, csr_id)
    if not csr_model:
        if wants_json():
            return api_error("CSR not found.", 404)
        flash("CSR not found.", "danger")
        return redirect(url_for("csr.list_csrs"))

    if csr_model.status != "pending":
        if wants_json():
            return api_error("This CSR has already been processed.", 409)
        flash("This CSR has already been processed.", "warning")
        return redirect(url_for("csr.detail", csr_id=csr_id))

    if (dual_control_service.is_active()
            and csr_model.created_by == current_user.id
            and not dual_control_service.is_exempt(current_user)):
        msg = "Dual-control mode: a CSR must be signed by a different admin than its creator."
        if wants_json():
            return api_error(msg, 403)
        flash(msg, "warning")
        return redirect(url_for("csr.detail", csr_id=csr_id))

    if request.method == "POST":
        ocsp_server = current_app.config.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
        if ocsp_server == "localhost:5000":
            ocsp_server = request.host
        ocsp_scheme = current_app.config.get("OCSP_URL_SCHEME", "http")

        def _err(message, status=400):
            if wants_json():
                return api_error(message, status)
            flash(message, "danger")
            return render_template("csr/sign.html", csr=csr_model,
                                   cas=CertificateAuthority.signing_capable().all(),
                                   ocsp_scheme=ocsp_scheme, ocsp_server=ocsp_server)

        try:
            ca_id = int(request.form.get("ca_id"))
            validity_days = int(request.form.get("validity_days", "365"))
        except (ValueError, TypeError):
            return _err("CA ID and validity days must be valid numbers.")

        ca = db.session.get(CertificateAuthority, ca_id)
        if not ca:
            return _err("CA not found.", 404)

        if ca.is_revoked:
            return _err("Cannot sign CSR with a revoked CA.")

        passphrase = current_app.config["MASTER_PASSPHRASE"]

        ocsp_url = f"{ocsp_scheme}://{ocsp_server}/public/ocsp/{ca_id}"
        crl_dp_url = request.form.get("crl_dp_url", "").strip()
        if not crl_dp_url:
            crl_dp_url = f"{ocsp_scheme}://{ocsp_server}/public/crl/{ca_id}.crl"

        # Parse Key Usage and Extended Key Usage from checkboxes
        # If no ku_* fields are present at all (e.g. API call), use service defaults
        ku_fields = ["ku_digital_signature", "ku_key_encipherment",
                     "ku_content_commitment", "ku_data_encipherment", "ku_key_agreement"]
        eku_fields = ["eku_serverAuth", "eku_clientAuth", "eku_codeSigning",
                      "eku_emailProtection", "eku_timeStamping", "eku_ocspSigning"]
        has_ku_fields = any(f in request.form for f in ku_fields)
        has_eku_fields = any(f in request.form for f in eku_fields)

        key_usage = None
        extended_key_usage = None

        if has_ku_fields:
            key_usage = {
                "digital_signature": "ku_digital_signature" in request.form,
                "key_encipherment": "ku_key_encipherment" in request.form,
                "content_commitment": "ku_content_commitment" in request.form,
                "data_encipherment": "ku_data_encipherment" in request.form,
                "key_agreement": "ku_key_agreement" in request.form,
            }
            if not any(key_usage.values()):
                return _err("At least one Key Usage must be selected.")

        if has_eku_fields:
            eku_names = ["serverAuth", "clientAuth", "codeSigning",
                         "emailProtection", "timeStamping", "ocspSigning"]
            extended_key_usage = [name for name in eku_names
                                  if f"eku_{name}" in request.form]

        try:
            certificate = cert_service.sign_csr(
                csr_model, ca, validity_days, passphrase, ocsp_url=ocsp_url,
                key_usage=key_usage, extended_key_usage=extended_key_usage,
                crl_dp_url=crl_dp_url, signed_by=current_user.id,
            )
            audit_service.log_action("sign_csr", target_type="csr", target_id=csr_id,
                                     details={"certificate_id": certificate.id})
            db.session.commit()
            if wants_json():
                return jsonify(certificate.to_dict(detail=True)), 201
            flash(f"Certificate '{certificate.common_name}' issued.", "success")
            return redirect(url_for("certificates.detail", cert_id=certificate.id))
        except Exception:
            logger.exception("Error signing CSR")
            return _err("An unexpected error occurred while signing the CSR.", 500)

    cas = CertificateAuthority.signing_capable().all()
    server = current_app.config.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
    if server == "localhost:5000":
        server = request.host
    scheme = current_app.config.get("OCSP_URL_SCHEME", "http")
    return render_template("csr/sign.html", csr=csr_model, cas=cas,
                           ocsp_scheme=scheme, ocsp_server=server)


@csr_bp.route("/<int:csr_id>/reject", methods=["POST"])
@admin_required
def reject(csr_id):
    csr_model = db.session.get(CertificateSigningRequest, csr_id)
    if not csr_model:
        if wants_json():
            return api_error("CSR not found.", 404)
        flash("CSR not found.", "danger")
        return redirect(url_for("csr.list_csrs"))

    # API-5: only a pending CSR can be rejected. Without this guard an already
    # approved CSR could be flipped to "rejected" while its issued certificate
    # stays live — a misleading, inconsistent state.
    if csr_model.status != "pending":
        if wants_json():
            return api_error("This CSR has already been processed.", 409)
        flash("This CSR has already been processed.", "warning")
        return redirect(url_for("csr.detail", csr_id=csr_id))

    csr_model.status = "rejected"
    audit_service.log_action("reject_csr", target_type="csr", target_id=csr_id)
    db.session.commit()
    if wants_json():
        return jsonify(csr_model.to_dict(detail=True))
    flash(f"CSR for '{csr_model.common_name}' rejected.", "info")
    return redirect(url_for("csr.list_csrs"))
