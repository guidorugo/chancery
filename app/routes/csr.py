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
from ..services import (csr_service, cert_service, audit_service, dual_control_service,
                        public_url, profile_service, listing)

logger = logging.getLogger(__name__)

csr_bp = Blueprint("csr", __name__, url_prefix="/csr")


CSR_STATUS_FILTERS = ("pending", "approved", "rejected")


def _filter_csrs(query, lq):
    """F15: q (CN / SAN substring), status, ca_id, profile."""
    q = lq.text("q")
    if q:
        query = query.filter(db.or_(
            listing.contains(CertificateSigningRequest.common_name, q),
            listing.contains(CertificateSigningRequest.san_json, q),
        ))
    status = lq.choice("status", CSR_STATUS_FILTERS)
    if status:
        query = query.filter(CertificateSigningRequest.status == status)
    ca_id = lq.integer("ca_id")
    if ca_id is not None:
        query = query.filter(CertificateSigningRequest.ca_id == ca_id)
    profile = lq.text("profile")
    if profile:
        row = profile_service.lookup(profile)
        if row is None:
            raise ValueError(f"Unknown certificate profile '{profile}'.")
        query = query.filter(CertificateSigningRequest.profile_id == row.id)
    return query


@csr_bp.route("/")
@login_required
def list_csrs():
    query = CertificateSigningRequest.query
    if not current_user.is_admin:
        query = query.filter_by(created_by=current_user.id)  # ownership first (META-1)
    lq = listing.ListQuery(html=not wants_json())
    try:
        query = _filter_csrs(query, lq)
    except ValueError as e:
        if wants_json():
            return api_error(str(e), 400)
        flash(str(e), "danger")
        return redirect(url_for("csr.list_csrs"))
    csrs = lq.apply(query.order_by(CertificateSigningRequest.created_at.desc()))
    if wants_json():
        return lq.json(csrs, lambda c: c.to_dict())
    return render_template("csr/list.html", csrs=csrs, listing=lq,
                           status_filters=CSR_STATUS_FILTERS,
                           cas=CertificateAuthority.query.order_by(CertificateAuthority.name).all(),
                           profiles=profile_service.list_profiles())


@csr_bp.route("/create", methods=["GET", "POST"])
@login_required
def create():
    def _err(message, status=400):
        if wants_json():
            return api_error(message, status)
        flash(message, "danger")
        return render_template("csr/create.html", **_csr_create_context())

    if request.method == "POST":
        mode = request.form.get("mode", "generate")

        # F1: an optional requested profile, carried on the CSR to the sign
        # page (the signer may still change it). Enforcement happens at signing.
        try:
            requested_profile = _requested_profile(request.form.get("profile"))
        except ValueError as e:
            return _err(str(e))
        profile_id = requested_profile.id if requested_profile else None

        if mode == "upload":
            csr_pem = request.form.get("csr_pem", "").strip()
            if not csr_pem:
                return _err("CSR PEM data is required.")
            try:
                csr_model = csr_service.import_csr(csr_pem, created_by=current_user.id,
                                                   profile_id=profile_id)
                audit_service.log_action("import_csr", target_type="csr", target_id=csr_model.id)
                db.session.commit()
                if wants_json():
                    return jsonify(csr_model.to_dict(detail=True)), 201
                flash(f"CSR for '{csr_model.common_name}' imported.", "success")
                return redirect(url_for("csr.detail", csr_id=csr_model.id))
            except ValueError as e:
                # G7-2: a bad/unsupported CSR is a 400, not a generic 500.
                return _err(str(e))
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
                    created_by=current_user.id, profile_id=profile_id,
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

    return render_template("csr/create.html", **_csr_create_context())


def _requested_profile(value):
    """Optional profile named on a new CSR: None when blank, else an enabled
    profile (unknown/disabled → ValueError)."""
    if value is None or not str(value).strip():
        return None
    profile = profile_service.lookup(value)
    if profile is None:
        raise ValueError(f"Unknown certificate profile '{value}'.")
    if not profile.enabled:
        raise ValueError(f"Certificate profile '{profile.name}' is disabled.")
    return profile


def _csr_create_context():
    return {"profiles": profile_service.list_profiles(enabled_only=True)}


def _sign_context(csr_model):
    cas = CertificateAuthority.signing_capable().all()
    profiles = profile_service.list_profiles(enabled_only=True)
    selected = (csr_model.profile.key if csr_model.profile and csr_model.profile.enabled
                else profile_service.default_key(profiles))
    return {
        "csr": csr_model, "cas": cas,
        "ocsp_scheme": public_url.public_scheme(), "ocsp_server": public_url.public_host(),
        "profiles": profiles, "profiles_json": profile_service.form_payload(profiles),
        "ca_allowed_json": {str(ca.id): ca.allowed_profile_ids for ca in cas},
        "selected_profile": selected,
    }


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
        def _err(message, status=400):
            if wants_json():
                return api_error(message, status)
            flash(message, "danger")
            return render_template("csr/sign.html", **_sign_context(csr_model))

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

        # F1: the signer's profile choice (defaults to the one the requester
        # asked for), checked against the CA's allow-list.
        requested = request.form.get("profile")
        if (requested is None or not str(requested).strip()) and csr_model.profile is not None:
            requested = csr_model.profile.key
        try:
            profile = profile_service.resolve(requested, ca)
        except ValueError as e:
            return _err(str(e))

        passphrase = current_app.config["MASTER_PASSPHRASE"]

        # G8-3: a loopback hostname is refused — it would be baked in for life.
        try:
            ocsp_url, crl_dp_url = public_url.issuance_urls(ca_id, request.form.get("crl_dp_url"))
        except ValueError as e:
            return _err(str(e))

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
            requested_profile_id = csr_model.profile_id
            certificate = cert_service.sign_csr(
                csr_model, ca, validity_days, passphrase, ocsp_url=ocsp_url,
                key_usage=key_usage, extended_key_usage=extended_key_usage,
                crl_dp_url=crl_dp_url, signed_by=current_user.id, profile=profile,
            )
            details = {"certificate_id": certificate.id, "profile": profile.key}
            if requested_profile_id is not None and requested_profile_id != profile.id:
                requested_row = profile_service.lookup(str(requested_profile_id))
                details["profile_changed"] = {
                    "from": requested_row.key if requested_row else requested_profile_id,
                    "to": profile.key,
                }
            audit_service.log_action("sign_csr", target_type="csr", target_id=csr_id, details=details)
            db.session.commit()
            if wants_json():
                return jsonify(certificate.to_dict(detail=True)), 201
            flash(f"Certificate '{certificate.common_name}' issued.", "success")
            return redirect(url_for("certificates.detail", cert_id=certificate.id))
        except cert_service.CsrAlreadyProcessed as e:
            # G7-4: lost the single-flight claim to a concurrent request.
            return _err(str(e), 409)
        except ValueError as e:
            # G7-2: policy refusals (PoP failure, weak key, validity cap, bad
            # SAN, expired CA) are 400s, not "unexpected error" 500s.
            return _err(str(e))
        except Exception:
            logger.exception("Error signing CSR")
            return _err("An unexpected error occurred while signing the CSR.", 500)

    return render_template("csr/sign.html", **_sign_context(csr_model))


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
