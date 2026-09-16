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
from ..models.certificate import Certificate
from ..responses import api_error, wants_json
from ..services import (cert_service, crl_service, audit_service, dual_control_service,
                        public_url, profile_service, listing)
from ..services.filenames import content_disposition

logger = logging.getLogger(__name__)


certificates_bp = Blueprint("certificates", __name__, url_prefix="/certificates")


def _crl_refresh_warning(refresh):
    """G10-1: run the post-revocation CRL refresh; a failure becomes a warning
    string (the revocation and its audit row are already committed)."""
    try:
        refresh()
        return None
    except Exception as exc:
        logger.exception("CRL refresh after revocation failed")
        db.session.rollback()
        return (f"Revoked, but the CRL refresh failed: {exc}. "
                "Regenerate the CRL from the CA page.")


CERT_STATUS_FILTERS = ("active", "revoked", "expiring", "expired")


def _filter_certificates(query, lq):
    """F15: q (CN / serial / SAN substring), status, ca_id, profile."""
    q = lq.text("q")
    if q:
        query = query.filter(db.or_(
            listing.contains(Certificate.common_name, q),
            listing.contains(Certificate.serial_number, q),
            listing.contains(Certificate.san_json, q),
        ))
    status = lq.choice("status", CERT_STATUS_FILTERS)
    if status:
        now, soon = listing.expiry_bounds()
        if status == "revoked":
            query = query.filter(Certificate.is_revoked.is_(True))
        elif status == "active":
            query = query.filter(Certificate.is_revoked.is_(False), Certificate.not_after >= now)
        elif status == "expiring":
            query = query.filter(Certificate.is_revoked.is_(False),
                                 Certificate.not_after >= now, Certificate.not_after <= soon)
        elif status == "expired":
            query = query.filter(Certificate.is_revoked.is_(False), Certificate.not_after < now)
    ca_id = lq.integer("ca_id")
    if ca_id is not None:
        query = query.filter(Certificate.ca_id == ca_id)
    profile = lq.text("profile")
    if profile:
        row = profile_service.lookup(profile)
        if row is None:
            raise ValueError(f"Unknown certificate profile '{profile}'.")
        query = query.filter(Certificate.profile_id == row.id)
    return query


@certificates_bp.route("/")
@login_required
def list_certs():
    query = Certificate.query
    if not current_user.is_admin:
        # Ownership scoping is applied before any filter (META-1).
        query = query.filter_by(requested_by=current_user.id)
    lq = listing.ListQuery(html=not wants_json())
    try:
        query = _filter_certificates(query, lq)
    except ValueError as e:
        if wants_json():
            return api_error(str(e), 400)
        flash(str(e), "danger")
        return redirect(url_for("certificates.list_certs"))
    certs = lq.apply(query.order_by(Certificate.created_at.desc()))
    if wants_json():
        return lq.json(certs, lambda c: c.to_dict())
    return render_template("certificates/list.html", certs=certs, listing=lq,
                           status_filters=CERT_STATUS_FILTERS,
                           cas=CertificateAuthority.query.order_by(CertificateAuthority.name).all(),
                           profiles=profile_service.list_profiles())


@certificates_bp.route("/create", methods=["GET", "POST"])
@admin_required
def create():
    if (dual_control_service.is_active()
            and not dual_control_service.is_exempt(current_user)):
        msg = ("Dual-control mode: direct certificate creation is disabled. "
               "Create a CSR and have another admin sign it.")
        if wants_json():
            return api_error(msg, 403)
        flash(msg, "warning")
        return redirect(url_for("csr.create"))

    if request.method == "POST":
        cn = request.form.get("cn", "").strip()
        org = request.form.get("org", "").strip()
        ou = request.form.get("ou", "").strip()
        country = request.form.get("country", "").strip()
        state = request.form.get("state", "").strip()
        locality = request.form.get("locality", "").strip()
        key_type = request.form.get("key_type", "RSA")

        def _err(message, status=400):
            db.session.rollback()  # 2.27.1: a failed flush must not break the re-render
            if wants_json():
                return api_error(message, status)
            flash(message, "danger")
            return render_template("certificates/create.html", **_create_context())

        try:
            ca_id = int(request.form.get("ca_id"))
            key_size = int(request.form.get("key_size", "2048"))
            validity_days = int(request.form.get("validity_days", "365"))
        except (ValueError, TypeError):
            return _err("CA ID, key size, and validity days must be valid numbers.")
        san_raw = request.form.get("san", "").strip()

        if not cn:
            return _err("Common Name is required.")

        ca = db.session.get(CertificateAuthority, ca_id)
        if not ca:
            return _err("CA not found.", 404)

        if ca.is_revoked:
            return _err("Cannot issue certificates from a revoked CA.")

        # F1: the profile is resolved server-side (absent → the unrestricted
        # `custom` profile) and checked against the CA's allow-list.
        try:
            profile = profile_service.resolve(request.form.get("profile"), ca)
        except ValueError as e:
            return _err(str(e))

        subject_attrs = {
            "CN": cn, "O": org, "OU": ou,
            "C": country, "ST": state, "L": locality,
        }
        san_list = [s.strip() for s in san_raw.split("\n") if s.strip()] if san_raw else []
        passphrase = current_app.config["MASTER_PASSPHRASE"]

        # Build OCSP URL and CRL DP URL (G8-3: a loopback hostname is refused —
        # it would be baked into the certificate for life).
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
            certificate = cert_service.create_certificate(
                ca, subject_attrs, san_list, validity_days, passphrase,
                key_type=key_type, key_size=key_size, ocsp_url=ocsp_url,
                key_usage=key_usage, extended_key_usage=extended_key_usage,
                crl_dp_url=crl_dp_url, issued_by=current_user.id, profile=profile,
            )
            audit_service.log_action("create_certificate", target_type="certificate",
                                     target_id=certificate.id, details={"profile": profile.key})
            db.session.commit()
            if wants_json():
                return jsonify(certificate.to_dict(detail=True)), 201
            flash(f"Certificate '{certificate.common_name}' created.", "success")
            return redirect(url_for("certificates.detail", cert_id=certificate.id))
        except ValueError as e:
            # Invalid input (e.g. a bad subject field or out-of-range validity)
            # — surface the specific reason as a 400 rather than a generic 500.
            return _err(str(e))
        except Exception:
            logger.exception("Error creating certificate")
            return _err("An unexpected error occurred while creating the certificate.", 500)

    return render_template("certificates/create.html", **_create_context())


def _create_context():
    """Template context shared by the create form and its error re-render."""
    cas = CertificateAuthority.signing_capable().all()
    profiles = profile_service.list_profiles(enabled_only=True)
    return {
        "cas": cas,
        "ocsp_scheme": public_url.public_scheme(),
        "ocsp_server": public_url.public_host(),
        "profiles": profiles,
        "profiles_json": profile_service.form_payload(profiles),
        "ca_allowed_json": {str(ca.id): ca.allowed_profile_ids for ca in cas},
        "selected_profile": profile_service.default_key(profiles),
    }


@certificates_bp.route("/<int:cert_id>")
@login_required
def detail(cert_id):
    certificate = db.session.get(Certificate, cert_id)
    if not certificate:
        if wants_json():
            return api_error("Certificate not found.", 404)
        flash("Certificate not found.", "danger")
        return redirect(url_for("certificates.list_certs"))

    if not current_user.is_admin and certificate.requested_by != current_user.id:
        if wants_json():
            return api_error("You do not have permission to view this certificate.", 403)
        flash("You do not have permission to view this certificate.", "danger")
        return redirect(url_for("certificates.list_certs"))

    if wants_json():
        return jsonify(certificate.to_dict(detail=True))

    san_list = json.loads(certificate.san_json) if certificate.san_json else []

    subject = json.loads(certificate.subject_json) if certificate.subject_json else {}

    if certificate.key_usage_json:
        key_usage = json.loads(certificate.key_usage_json)
    else:
        key_usage = {
            "digital_signature": True, "key_encipherment": True,
            "content_commitment": False, "data_encipherment": False,
            "key_agreement": False,
        }

    if certificate.extended_key_usage_json:
        extended_key_usage = json.loads(certificate.extended_key_usage_json)
    else:
        extended_key_usage = ["serverAuth", "clientAuth"]

    return render_template("certificates/detail.html", cert=certificate,
                           san_list=san_list, subject=subject,
                           key_usage=key_usage, extended_key_usage=extended_key_usage)


@certificates_bp.route("/<int:cert_id>/revoke", methods=["GET", "POST"])
@admin_required
def revoke(cert_id):
    certificate = db.session.get(Certificate, cert_id)
    if not certificate:
        if wants_json():
            return api_error("Certificate not found.", 404)
        flash("Certificate not found.", "danger")
        return redirect(url_for("certificates.list_certs"))

    if request.method == "POST":
        reason = request.form.get("reason", "unspecified")
        if reason not in crl_service.REVOCATION_REASONS:  # G7-3
            if wants_json():
                return api_error("Invalid revocation reason.", 400)
            flash("Invalid revocation reason.", "danger")
            return redirect(url_for("certificates.revoke", cert_id=cert_id))
        passphrase = current_app.config["MASTER_PASSPHRASE"]
        try:
            # G10-1: the state change and its audit row commit together; the
            # CRL refresh runs afterwards and cannot lose either.
            crl_service.revoke_certificate(cert_id, reason, passphrase=passphrase,
                                           commit=False, refresh=False)
            audit_service.log_action("revoke_certificate", target_type="certificate", target_id=cert_id,
                                     details={"reason": reason})
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            if wants_json():
                return api_error(str(e), 409 if "already revoked" in str(e) else 400)
            flash(str(e), "danger")
            return redirect(url_for("certificates.detail", cert_id=cert_id))
        except Exception:
            db.session.rollback()
            logger.exception("Error revoking certificate")
            if wants_json():
                return api_error("An unexpected error occurred while revoking the certificate.", 500)
            flash("An unexpected error occurred while revoking the certificate.", "danger")
        else:
            warning = _crl_refresh_warning(
                lambda: crl_service.refresh_crl(certificate.ca, passphrase))
            if wants_json():
                payload = certificate.to_dict(detail=True)
                if warning:
                    payload["warning"] = warning
                return jsonify(payload)
            flash(f"Certificate '{certificate.common_name}' revoked.", "success")
            if warning:
                flash(warning, "warning")
            return redirect(url_for("certificates.detail", cert_id=cert_id))

    return render_template("certificates/revoke.html", cert=certificate)


@certificates_bp.route("/<int:cert_id>/renew", methods=["GET", "POST"])
@admin_required
def renew(cert_id):
    """F9: issue a successor certificate (same subject/SANs/KU/EKU/profile).

    Dual control treats a CSR-lineage renewal as signing (the requester may
    not renew their own certificate) and an escrowed-key renewal as direct
    creation (refused while active); the bootstrap admin is exempt from both.
    """
    old = db.session.get(Certificate, cert_id)
    if not old:
        if wants_json():
            return api_error("Certificate not found.", 404)
        flash("Certificate not found.", "danger")
        return redirect(url_for("certificates.list_certs"))

    csr_lineage = not old.private_key_enc
    if dual_control_service.is_active() and not dual_control_service.is_exempt(current_user):
        if not csr_lineage:
            msg = ("Dual-control mode: renewing a directly issued certificate is direct creation, "
                   "which is disabled. Create a CSR and have another admin sign it.")
        elif old.requested_by == current_user.id:
            msg = "Dual-control mode: a certificate must be renewed by a different admin than its requester."
        else:
            msg = None
        if msg:
            if wants_json():
                return api_error(msg, 403)
            flash(msg, "warning")
            return redirect(url_for("certificates.detail", cert_id=cert_id))

    context = {
        "cert": old,
        "default_validity_days": cert_service.original_validity_days(old),
        "can_rekey": bool(old.private_key_enc),
    }
    if request.method == "GET":
        return render_template("certificates/renew.html", **context)

    def _err(message, status=400):
        if wants_json():
            return api_error(message, status)
        flash(message, "danger")
        return redirect(url_for("certificates.renew", cert_id=cert_id))

    raw_days = (request.form.get("validity_days") or "").strip()
    try:
        validity_days = int(raw_days) if raw_days else None
    except ValueError:
        return _err("Validity days must be a whole number.")
    rekey = request.form.get("rekey") in ("on", "1", "true", "yes")
    revoke_old = request.form.get("revoke_old") in ("on", "1", "true", "yes")
    force = request.form.get("force") in ("on", "1", "true", "yes")
    try:
        ocsp_url, crl_dp_url = public_url.issuance_urls(old.ca_id, request.form.get("crl_dp_url"))
    except ValueError as e:
        return _err(str(e))

    passphrase = current_app.config["MASTER_PASSPHRASE"]
    try:
        new = cert_service.renew_certificate(
            old, passphrase, validity_days=validity_days, rekey=rekey, revoke_old=revoke_old,
            ocsp_url=ocsp_url, crl_dp_url=crl_dp_url, issued_by=current_user.id, force=force)
        audit_service.log_action(
            "renew_certificate", target_type="certificate", target_id=new.id,
            details={"old_id": old.id, "new_id": new.id, "rekey": rekey, "revoked_old": revoke_old,
                     "validity_days": cert_service.original_validity_days(new),
                     "profile": new.profile.key if new.profile else None})
        db.session.commit()
    except cert_service.AlreadyRenewed as e:
        db.session.rollback()
        return _err(str(e), 409)
    except ValueError as e:
        db.session.rollback()
        return _err(str(e))
    except Exception:
        db.session.rollback()
        logger.exception("Error renewing certificate")
        return _err("An unexpected error occurred while renewing the certificate.", 500)

    warning = None
    if revoke_old:
        warning = _crl_refresh_warning(lambda: crl_service.refresh_crl(old.ca, passphrase))
    if wants_json():
        payload = new.to_dict(detail=True)
        payload["old_id"] = old.id
        if warning:
            payload["warning"] = warning
        return jsonify(payload), 201
    flash(f"Certificate '{old.common_name}' renewed as #{new.id}"
          f"{' with a new key' if rekey else ''}{'; the old certificate is revoked' if revoke_old else ''}.",
          "success")
    if warning:
        flash(warning, "warning")
    return redirect(url_for("certificates.detail", cert_id=new.id))


@certificates_bp.route("/<int:cert_id>/download", methods=["GET", "POST"])
@login_required
def download(cert_id):
    certificate = db.session.get(Certificate, cert_id)
    if not certificate:
        flash("Certificate not found.", "danger")
        return redirect(url_for("certificates.list_certs"))

    if not current_user.is_admin and certificate.requested_by != current_user.id:
        flash("You do not have permission to download this certificate.", "danger")
        return redirect(url_for("certificates.list_certs"))

    fmt = request.values.get("format", "pem")

    # C3: PKCS#12 bundles the private key and takes an export password; make it
    # POST-only and read the password from the form so neither the key material
    # nor the password lands in a GET URL / access log.
    if fmt == "pkcs12" and request.method != "POST":
        flash("PKCS#12 export must be submitted via POST.", "danger")
        return redirect(url_for("certificates.detail", cert_id=cert_id))

    audit_service.log_action("download_certificate", target_type="certificate", target_id=cert_id,
                             details={"format": fmt})
    db.session.commit()

    if fmt == "der":
        data = cert_service.export_certificate_der(certificate)
        return Response(
            data,
            mimetype="application/x-x509-ca-cert",
            headers={"Content-Disposition": content_disposition(certificate.common_name, "der", fallback=f"certificate-{certificate.id}")},
        )
    elif fmt == "pkcs12":
        passphrase = current_app.config["MASTER_PASSPHRASE"]
        export_password = request.form.get("password", "")
        try:
            data = cert_service.export_pkcs12(certificate, passphrase, export_password)
            return Response(
                data,
                mimetype="application/x-pkcs12",
                headers={"Content-Disposition": content_disposition(certificate.common_name, "p12", fallback=f"certificate-{certificate.id}")},
            )
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("certificates.detail", cert_id=cert_id))
    elif fmt in ("fullchain", "chain"):
        # leaf -> intermediates -> root (fullchain) or the issuing chain only
        # (chain); public material, GET is fine. F11: `via=<alt_id>` routes
        # the chain through an alternate (cross-signed) CA certificate.
        via = None
        if request.values.get("via"):
            from ..models.ca_certificate import CaCertificate
            try:
                via = db.session.get(CaCertificate, int(request.values.get("via")))
            except (TypeError, ValueError):
                via = None
            if via is None:
                if wants_json():
                    return api_error("Unknown alternate CA certificate.", 404)
                flash("Unknown alternate CA certificate.", "danger")
                return redirect(url_for("certificates.detail", cert_id=cert_id))
        try:
            if fmt == "fullchain":
                data = cert_service.export_fullchain_pem(certificate, via)
            else:
                data = cert_service.export_chain_pem(certificate, via)
        except ValueError as e:
            if wants_json():
                return api_error(str(e), 400)
            flash(str(e), "danger")
            return redirect(url_for("certificates.detail", cert_id=cert_id))
        suffix = f"-{fmt}-via-{via.id}" if via else f"-{fmt}"
        return Response(
            data,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": content_disposition(f"{certificate.common_name}{suffix}", "pem", fallback=f"certificate-{certificate.id}")},
        )
    else:
        data = cert_service.export_certificate_pem(certificate)
        return Response(
            data,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": content_disposition(certificate.common_name, "pem", fallback=f"certificate-{certificate.id}")},
        )


@certificates_bp.route("/<int:cert_id>/download-key", methods=["POST"])
@admin_required
def download_key(cert_id):
    certificate = db.session.get(Certificate, cert_id)
    if not certificate:
        flash("Certificate not found.", "danger")
        return redirect(url_for("certificates.list_certs"))

    if not certificate.private_key_enc:
        flash("No private key available for this certificate.", "danger")
        return redirect(url_for("certificates.detail", cert_id=cert_id))

    audit_service.log_action("download_private_key", target_type="certificate", target_id=cert_id)
    db.session.commit()

    passphrase = current_app.config["MASTER_PASSPHRASE"]
    from ..services.crypto_utils import decrypt_private_key
    from cryptography.hazmat.primitives import serialization
    key = decrypt_private_key(certificate.private_key_enc, passphrase)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return Response(
        key_pem,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": content_disposition(certificate.common_name, "key", fallback=f"certificate-{certificate.id}")},
    )
