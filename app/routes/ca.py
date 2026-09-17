import logging
from datetime import datetime, timezone

from flask import Blueprint, Response, render_template, redirect, url_for, flash, request, current_app, jsonify
from flask_login import current_user
from sqlalchemy.exc import IntegrityError

from ..decorators import admin_required
from ..extensions import db
from ..models.ca import CertificateAuthority
from ..responses import api_error, wants_json
from ..services import ca_service, crl_service, audit_service, dual_control_service, profile_service, listing
from ..services.filenames import content_disposition
from ..services.keybackend import hsm_available
from ..services import name_constraints, certificate_policies, ocsp_service
from ..models.ca_certificate import CaCertificate

logger = logging.getLogger(__name__)

ca_bp = Blueprint("ca", __name__, url_prefix="/ca")

MAX_FILE_SIZE = 64 * 1024  # 64KB


def _get_pem_input(req, textarea_field, file_field):
    """Get PEM input from file upload (preferred) or textarea fallback."""
    uploaded = req.files.get(file_field)
    if uploaded and uploaded.filename:
        data = uploaded.read()
        if len(data) > MAX_FILE_SIZE:
            raise ValueError(f"Uploaded file exceeds 64KB size limit.")
        return data.decode("utf-8").strip()
    return req.form.get(textarea_field, "").strip()


def _create_page_context():
    """Template context for the create/import page.

    signing_cas: selectable parents when generating a new intermediate (must
    hold a private key). link_cas: selectable parents when linking an
    imported CA (certificate-only parents are fine there).
    """
    return {
        "signing_cas": CertificateAuthority.signing_capable().all(),
        "link_cas": CertificateAuthority.query.filter_by(is_revoked=False).all(),
        "hsm_available": hsm_available(),
        "profiles": profile_service.list_profiles(enabled_only=True),
    }


def _parse_allowed_profiles(form):
    """F1: the CA allow-list from the form — None (any profile) unless the
    'restrict' switch is on, in which case the ticked profile ids."""
    if form.get("restrict_profiles") != "on":
        return None
    ids = []
    for raw in form.getlist("allowed_profiles"):
        profile = profile_service.lookup(raw)
        if profile is None:
            raise ValueError(f"Unknown certificate profile '{raw}'.")
        ids.append(profile.id)
    if not ids:
        raise ValueError("Select at least one allowed profile, or turn the restriction off.")
    return ids


CA_STATUS_FILTERS = ("active", "revoked", "expired", "pending", "cert-only")
CA_TYPE_FILTERS = ("root", "intermediate")
CA_BACKEND_FILTERS = ("software", "softhsm")


def _filter_cas(query, lq):
    """F15: q (name / CN / serial substring), status, type, backend."""
    q = lq.text("q")
    if q:
        query = query.filter(db.or_(
            listing.contains(CertificateAuthority.name, q),
            listing.contains(CertificateAuthority.common_name, q),
            listing.contains(CertificateAuthority.serial_number, q),
        ))
    status = lq.choice("status", CA_STATUS_FILTERS)
    if status:
        now, _soon = listing.expiry_bounds()
        if status == "revoked":
            query = query.filter(CertificateAuthority.is_revoked.is_(True))
        elif status == "expired":
            query = query.filter(CertificateAuthority.is_revoked.is_(False),
                                 CertificateAuthority.not_after < now)
        elif status == "pending":
            query = query.filter(CertificateAuthority.is_revoked.is_(False),
                                 CertificateAuthority.approval_status == "pending")
        elif status == "cert-only":
            query = query.filter(CertificateAuthority.key_backend != "softhsm",
                                 CertificateAuthority.private_key_enc == b"")
        elif status == "active":
            query = query.filter(CertificateAuthority.is_revoked.is_(False),
                                 CertificateAuthority.not_after >= now,
                                 CertificateAuthority.approval_status == "approved")
    ca_type = lq.choice("type", CA_TYPE_FILTERS)
    if ca_type:
        query = query.filter(CertificateAuthority.is_root.is_(ca_type == "root"))
    backend = lq.choice("backend", CA_BACKEND_FILTERS)
    if backend:
        query = query.filter(CertificateAuthority.key_backend == backend)
    return query


@ca_bp.route("/")
@admin_required
def list_cas():
    lq = listing.ListQuery(html=not wants_json())
    try:
        query = _filter_cas(CertificateAuthority.query, lq)
    except ValueError as e:
        if wants_json():
            return api_error(str(e), 400)
        flash(str(e), "danger")
        return redirect(url_for("ca.list_cas"))
    cas = lq.apply(query.order_by(CertificateAuthority.created_at.desc()))
    if wants_json():
        return lq.json(cas, lambda ca: ca.to_dict())
    return render_template("ca/list.html", cas=cas, listing=lq,
                           status_filters=CA_STATUS_FILTERS, type_filters=CA_TYPE_FILTERS,
                           backend_filters=CA_BACKEND_FILTERS)


@ca_bp.route("/create", methods=["GET", "POST"])
@admin_required
def create():
    def _err(message, status=400):
        # JSON for API clients; re-render the form (with flash) for browsers.
        # 2.27.1: discard the failed transaction first — after an IntegrityError
        # the session is unusable and re-rendering the form (which queries the
        # CA list) raised PendingRollbackError, turning a 4xx into a 500.
        db.session.rollback()
        if wants_json():
            return api_error(message, status)
        flash(message, "danger")
        return render_template("ca/create.html", **_create_page_context())

    def _conflict(what):
        # The service pre-checks names/serials; this only catches a race
        # between that check and the INSERT (the database has the last word).
        logger.warning("CA %s refused by a database constraint", what)
        return _err("A CA with this name or serial number was created concurrently; "
                    "the name of a revoked CA can be reused, an active one's cannot.", 409)

    if request.method == "POST":
        mode = request.form.get("mode", "generate")
        # Dual control: a CA created while the mode is active starts pending
        # and must be approved by a different admin before it can sign.
        approval_status = "pending" if dual_control_service.is_active() else "approved"
        try:
            allowed_profile_ids = _parse_allowed_profiles(request.form)
        except ValueError as e:
            return _err(str(e))

        if mode == "upload":
            name = request.form.get("name", "").strip()
            if not name:
                return _err("CA Name is required.")

            upload_parent_id = request.form.get("upload_parent_id")
            parent_id = upload_parent_id if upload_parent_id else None
            passphrase = current_app.config["MASTER_PASSPHRASE"]
            import_format = request.form.get("import_format", "pem")

            try:
                if import_format == "pkcs12":
                    uploaded = request.files.get("p12_file")
                    if not uploaded or not uploaded.filename:
                        raise ValueError("A PKCS#12 (.p12/.pfx) file is required.")
                    p12_bytes = uploaded.read()
                    if len(p12_bytes) > MAX_FILE_SIZE:
                        raise ValueError("Uploaded file exceeds 64KB size limit.")
                    p12_password = request.form.get("p12_password", "")
                    ca = ca_service.import_pkcs12(name, p12_bytes, p12_password or None,
                                                  passphrase, parent_id=parent_id,
                                                  created_by=current_user.id,
                                                  approval_status=approval_status)
                else:
                    cert_pem = _get_pem_input(request, "cert_pem", "cert_file")
                    key_pem = _get_pem_input(request, "key_pem", "key_file")
                    cert_only = request.form.get("cert_only") == "on"
                    key_passphrase = request.form.get("key_passphrase", "")

                    if not cert_pem:
                        raise ValueError("Certificate PEM is required.")
                    if cert_only and key_pem:
                        raise ValueError("A private key was provided together with "
                                         "'certificate only' - remove one of the two.")
                    if not cert_only and not key_pem:
                        raise ValueError("Private Key PEM is required "
                                         "(or tick 'Import certificate only').")

                    ca = ca_service.import_ca(name, cert_pem, key_pem or None, passphrase,
                                              parent_id=parent_id,
                                              key_passphrase=key_passphrase or None,
                                              created_by=current_user.id,
                                              approval_status=approval_status)

                ca.set_allowed_profile_ids(allowed_profile_ids)
                imported_parents = getattr(ca, "_imported_parents", [])
                audit_service.log_action(
                    "import_ca", target_type="ca", target_id=ca.id,
                    details={"format": import_format, "has_key": ca.has_private_key,
                             "imported_parents": imported_parents,
                             "approval_status": ca.approval_status},
                )
                db.session.commit()
                msg = f"CA '{ca.name}' imported successfully."
                if imported_parents:
                    msg += (f" {len(imported_parents)} parent CA(s) imported from the "
                            f"chain: {', '.join(imported_parents)}.")
                if not ca.has_private_key:
                    msg += (" Imported without a private key: this CA cannot issue "
                            "certificates, sign CRLs, or answer OCSP.")
                if ca.approval_status == "pending":
                    msg += (" Dual control: it awaits approval by another admin "
                            "before it can sign anything.")
                if wants_json():
                    return jsonify(ca.to_dict(detail=True)), 201
                flash(msg, "success" if ca.has_private_key and ca.approval_status != "pending" else "warning")
                return redirect(url_for("ca.detail", ca_id=ca.id))
            except ValueError as e:
                return _err(str(e))
            except IntegrityError:
                return _conflict("import")
            except Exception:
                logger.exception("Error importing CA")
                return _err("An unexpected error occurred while importing the CA.", 500)

        else:
            # Generate mode - existing logic
            name = request.form.get("name", "").strip()
            cn = request.form.get("cn", "").strip()
            org = request.form.get("org", "").strip()
            ou = request.form.get("ou", "").strip()
            country = request.form.get("country", "").strip()
            state = request.form.get("state", "").strip()
            locality = request.form.get("locality", "").strip()
            key_type = request.form.get("key_type", "RSA")
            ca_type = request.form.get("ca_type", "root")
            parent_id = request.form.get("parent_id")
            path_length_str = request.form.get("path_length", "").strip()
            key_backend = request.form.get("key_backend", "software")
            if key_backend not in ("software", "softhsm"):
                key_backend = "software"
            if key_backend == "softhsm" and not hsm_available():
                return _err("The HSM (SoftHSM) key backend is not configured on this server.")

            try:
                key_size = int(request.form.get("key_size", "2048"))
                validity_days = int(request.form.get("validity_days", "3650"))
                path_length = int(path_length_str) if path_length_str else None
            except ValueError:
                return _err("Key size, validity days, and path length must be valid numbers.")
            # F2: name constraints (one DNS:/IP:/EMAIL:/URI: entry per line).
            try:
                constraints = name_constraints.normalise(request.form.get("nc_permitted", ""),
                                                         request.form.get("nc_excluded", ""))
            except ValueError as e:
                return _err(str(e))
            # F3: certificate policies (one "OID [CPS URI]" per line).
            try:
                policies = certificate_policies.normalise(request.form.get("certificate_policies", ""))
            except ValueError as e:
                return _err(str(e))

            if not name or not cn:
                return _err("Name and Common Name are required.")
            if path_length is not None and path_length < 0:  # G7-3
                return _err("Path length must be zero or greater.")
            if ca_type == "intermediate" and not (parent_id or "").strip():  # G7-5
                return _err("A parent CA is required for an intermediate CA.")

            subject_attrs = {
                "CN": cn, "O": org, "OU": ou,
                "C": country, "ST": state, "L": locality,
            }
            passphrase = current_app.config["MASTER_PASSPHRASE"]

            try:
                if ca_type == "intermediate" and parent_id:
                    try:
                        parent_ca_id = int(parent_id)
                    except ValueError:
                        return _err("Invalid parent CA ID.")
                    # G4-2: resolve through signing_capable() so a revoked,
                    # pending or keyless parent is refused server-side too
                    # (the dropdown only hides them).
                    parent_ca = CertificateAuthority.signing_capable().filter_by(id=parent_ca_id).first()
                    if not parent_ca:
                        return _err("Parent CA not found, or it cannot sign (revoked, awaiting "
                                    "approval, or without a private key).")
                    ca = ca_service.create_intermediate_ca(
                        name, parent_ca, subject_attrs, key_type, key_size,
                        validity_days, passphrase, path_length=path_length,
                        backend=key_backend, created_by=current_user.id,
                        approval_status=approval_status, constraints=constraints,
                        policies=policies,
                    )
                else:
                    ca = ca_service.create_root_ca(
                        name, subject_attrs, key_type, key_size,
                        validity_days, passphrase, path_length=path_length,
                        backend=key_backend, created_by=current_user.id,
                        approval_status=approval_status, constraints=constraints,
                        policies=policies,
                    )
                ca.set_allowed_profile_ids(allowed_profile_ids)
                audit_service.log_action("create_ca", target_type="ca", target_id=ca.id,
                                         details={"approval_status": ca.approval_status,
                                                  "allowed_profiles": allowed_profile_ids,
                                                  "name_constraints": constraints,
                                                  "certificate_policies": policies})
                db.session.commit()
                if wants_json():
                    return jsonify(ca.to_dict(detail=True)), 201
                if ca.approval_status == "pending":
                    flash(f"CA '{ca.name}' created and awaiting approval by another "
                          "admin before it can issue anything.", "warning")
                else:
                    flash(f"CA '{ca.name}' created successfully.", "success")
                return redirect(url_for("ca.detail", ca_id=ca.id))
            except ValueError as e:
                # Invalid input (e.g. a bad subject field or out-of-range
                # validity) — surface the reason as a 400, not a generic 500.
                return _err(str(e))
            except IntegrityError:
                return _conflict("creation")
            except Exception:
                logger.exception("Error creating CA")
                return _err("An unexpected error occurred while creating the CA.", 500)

    return render_template("ca/create.html", **_create_page_context())


@ca_bp.route("/detect-parent", methods=["POST"])
@admin_required
def detect_parent():
    cert_pem = request.form.get("cert_pem", "").strip()
    if not cert_pem:
        return jsonify({"is_self_signed": None, "parent_id": None})

    is_self_signed, parent_id = ca_service.detect_parent_ca(cert_pem)
    return jsonify({"is_self_signed": is_self_signed, "parent_id": parent_id})


@ca_bp.route("/<int:ca_id>")
@admin_required
def detail(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        if wants_json():
            return api_error("CA not found.", 404)
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))
    if wants_json():
        return jsonify(ca.to_dict(detail=True))
    chain = ca_service.get_ca_chain(ca)
    from ..services.acme import service as acme_service
    acme_ctx = {
        "acme_global": bool(current_app.config.get("ACME_ENABLED")),
        "acme_directory_url": acme_service.acme_url("acme.directory", ca.id),
        "acme_eab_keys": ca.acme_eab_keys.order_by(db.desc("id")).limit(50).all(),
        "acme_accounts": ca.acme_accounts.count(),
        "acme_new_eab": request.args.get("_eab_kid") and None,
    }
    return render_template("ca/detail.html", ca=ca, chain=chain, **acme_ctx,
                           profiles=profile_service.list_profiles(),
                           ocsp_delegated=ocsp_service.delegated_enabled(),
                           ocsp_responder=ocsp_service.responder_status(ca),
                           cross_issuers=[c for c in CertificateAuthority.signing_capable().order_by(CertificateAuthority.name).all()
                                          if c.id != ca.id])


@ca_bp.route("/<int:ca_id>/ocsp-responder/rotate", methods=["POST"])
@admin_required
def rotate_ocsp_responder(ca_id):
    """F7: issue a new delegated OCSP responder certificate now."""
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        if wants_json():
            return api_error("CA not found.", 404)
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))
    try:
        ocsp_service.ensure_responder(ca, current_app.config["MASTER_PASSPHRASE"], force=True)
        status = ocsp_service.responder_status(ca)
        audit_service.log_action("ocsp_responder_rotated", target_type="ca", target_id=ca.id,
                                 details={"trigger": "manual", **status})
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        if wants_json():
            return api_error(str(e), 400)
        flash(str(e), "danger")
        return redirect(url_for("ca.detail", ca_id=ca.id))
    except Exception:
        db.session.rollback()
        logger.exception("OCSP responder rotation failed")
        if wants_json():
            return api_error("An unexpected error occurred while rotating the OCSP responder.", 500)
        flash("An unexpected error occurred while rotating the OCSP responder.", "danger")
        return redirect(url_for("ca.detail", ca_id=ca.id))
    if wants_json():
        return jsonify({"ca_id": ca.id, "ocsp_responder": status})
    flash(f"OCSP responder certificate for '{ca.name}' rotated; valid until {status['not_after'][:10]}.", "success")
    return redirect(url_for("ca.detail", ca_id=ca.id))


@ca_bp.route("/<int:ca_id>/profiles", methods=["POST"])
@admin_required
def set_profiles(ca_id):
    """F1: change the CA's profile allow-list (None = any profile)."""
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        if wants_json():
            return api_error("CA not found.", 404)
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))
    try:
        ids = _parse_allowed_profiles(request.form)
    except ValueError as e:
        if wants_json():
            return api_error(str(e), 400)
        flash(str(e), "danger")
        return redirect(url_for("ca.detail", ca_id=ca.id))
    ca.set_allowed_profile_ids(ids)
    audit_service.log_action("update_ca_profiles", target_type="ca", target_id=ca.id,
                             details={"allowed_profiles": ids})
    db.session.commit()
    if wants_json():
        return jsonify(ca.to_dict(detail=True))
    flash("Allowed profiles updated." if ids else "Profile restriction removed — any profile may be used.",
          "success")
    return redirect(url_for("ca.detail", ca_id=ca.id))


@ca_bp.route("/<int:ca_id>/approve", methods=["POST"])
@admin_required
def approve(ca_id):
    """Dual-control approval of a pending CA by a different admin.

    While dual control is active the creator cannot approve their own CA
    (the literal bootstrap admin account excepted). Once the mode is
    inactive, any admin — including the creator — may approve a leftover
    pending CA.
    """
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        if wants_json():
            return api_error("CA not found.", 404)
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))

    if ca.approval_status != "pending":
        if wants_json():
            return api_error("This CA is not awaiting approval.", 409)
        flash("This CA is not awaiting approval.", "warning")
        return redirect(url_for("ca.detail", ca_id=ca_id))

    reason = dual_control_service.refuse_reason(current_user, ca.created_by, "a CA") if dual_control_service.is_active() else None
    if reason:
        msg = reason
        if wants_json():
            return api_error(msg, 403)
        flash(msg, "warning")
        return redirect(url_for("ca.detail", ca_id=ca_id))

    ca.approval_status = "approved"
    ca.approved_by = current_user.id
    ca.approved_at = datetime.now(timezone.utc)
    audit_service.log_action("approve_ca", target_type="ca", target_id=ca.id,
                             details={"created_by": ca.created_by})
    db.session.commit()
    # The initial CRL was deferred while the CA was pending — publish it now.
    ca_service.publish_initial_crl(ca, current_app.config["MASTER_PASSPHRASE"])
    if wants_json():
        return jsonify(ca.to_dict(detail=True))
    flash(f"CA '{ca.name}' approved. It can now issue certificates.", "success")
    return redirect(url_for("ca.detail", ca_id=ca_id))


@ca_bp.route("/<int:ca_id>/download", methods=["GET", "POST"])
@admin_required
def download(ca_id):
    """Export the CA: format=pem (default) | chain | key | pkcs12.

    pem/chain are non-secret and may be fetched with GET. key and pkcs12
    export private-key material and are therefore POST-only, so the key PEM
    and the pkcs12 export password never appear in a GET URL (browser
    history, Referer, proxy/access logs). pkcs12 requires a `password` form
    field. key/pkcs12 are unavailable for certificate-only CAs.
    """
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))

    fmt = request.values.get("format", "pem")
    passphrase = current_app.config["MASTER_PASSPHRASE"]

    # Private-key exports must not be triggerable by a GET URL that would
    # land in logs/history; require POST for them.
    if fmt in ("key", "pkcs12") and request.method != "POST":
        flash("Private-key export must be submitted via POST.", "danger")
        return redirect(url_for("ca.detail", ca_id=ca.id))

    if fmt == "chain":
        via = None
        if request.values.get("via"):
            via = _alternate_or_none(request.values.get("via"))
            if via is None:
                flash("Unknown alternate certificate.", "danger")
                return redirect(url_for("ca.detail", ca_id=ca.id))
        try:
            chain = ca_service.get_ca_chain(ca, via)
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("ca.detail", ca_id=ca.id))
        suffix = f"-chain-via-{via.id}" if via else "-chain"
        return Response(
            chain,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": content_disposition(f"{ca.name}{suffix}", "pem", fallback=f"ca-{ca.id}{suffix}")},
        )

    if fmt == "key":
        try:
            key_pem = ca_service.export_ca_key_pem(ca, passphrase)
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("ca.detail", ca_id=ca.id))
        audit_service.log_action("download_ca_private_key", target_type="ca", target_id=ca.id)
        db.session.commit()
        return Response(
            key_pem,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": content_disposition(ca.name, "key", fallback=f"ca-{ca.id}")},
        )

    if fmt == "pkcs12":
        # Read from the form only — never request.values (which would accept
        # the password from the query string and leak it into logs).
        password = request.form.get("password", "")
        try:
            data = ca_service.export_ca_pkcs12(ca, passphrase, password)
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("ca.detail", ca_id=ca.id))
        audit_service.log_action("export_ca_pkcs12", target_type="ca", target_id=ca.id)
        db.session.commit()
        return Response(
            data,
            mimetype="application/x-pkcs12",
            headers={"Content-Disposition": content_disposition(ca.name, "p12", fallback=f"ca-{ca.id}")},
        )

    return Response(
        ca.certificate_pem,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": content_disposition(ca.name, "pem", fallback=f"ca-{ca.id}")},
    )


@ca_bp.route("/<int:ca_id>/revoke", methods=["GET", "POST"])
@admin_required
def revoke(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        if wants_json():
            return api_error("CA not found.", 404)
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))

    if ca.is_revoked:
        if wants_json():
            return api_error("CA is already revoked.", 409)
        flash("CA is already revoked.", "warning")
        return redirect(url_for("ca.detail", ca_id=ca.id))

    if request.method == "POST":
        reason = request.form.get("reason", "unspecified")
        if reason not in crl_service.REVOCATION_REASONS:  # G7-3
            if wants_json():
                return api_error("Invalid revocation reason.", 400)
            flash("Invalid revocation reason.", "danger")
            return redirect(url_for("ca.revoke", ca_id=ca.id))
        passphrase = current_app.config["MASTER_PASSPHRASE"]
        try:
            # G10-1: the state change and its audit row commit together; the
            # CRL refresh runs afterwards and cannot lose either.
            _, certs_revoked, sub_cas_revoked = crl_service.revoke_ca(
                ca_id, reason, passphrase=passphrase, commit=False, refresh=False)
            audit_service.log_action("revoke_ca", target_type="ca", target_id=ca_id,
                                     details={"reason": reason, "certs_revoked": certs_revoked,
                                              "sub_cas_revoked": sub_cas_revoked})
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("Error revoking CA")
            if wants_json():
                return api_error("An unexpected error occurred while revoking the CA.", 500)
            flash("An unexpected error occurred while revoking the CA.", "danger")
        else:
            warning = _crl_refresh_warning(
                lambda: crl_service.publish_revocation_crls(ca, passphrase))
            msg = f"CA '{ca.name}' revoked."
            if certs_revoked:
                msg += f" {certs_revoked} certificate(s) revoked."
            if sub_cas_revoked:
                msg += f" {sub_cas_revoked} sub-CA(s) revoked."
            if wants_json():
                payload = ca.to_dict(detail=True)
                if warning:
                    payload["warning"] = warning
                return jsonify(payload)
            flash(msg, "success")
            if warning:
                flash(warning, "warning")
            return redirect(url_for("ca.detail", ca_id=ca.id))

    # Count affected items for the confirmation page
    from ..models.certificate import Certificate
    cert_count = Certificate.query.filter_by(ca_id=ca.id, is_revoked=False).count()
    sub_ca_count = _count_active_sub_cas(ca)
    return render_template("ca/revoke.html", ca=ca, cert_count=cert_count, sub_ca_count=sub_ca_count)


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


def _count_active_sub_cas(ca):
    """Recursively count non-revoked sub-CAs."""
    count = 0
    for child in ca.children:
        if not child.is_revoked:
            count += 1
            count += _count_active_sub_cas(child)
    return count


@ca_bp.route("/<int:ca_id>/crl", methods=["POST"])
@admin_required
def generate_crl(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        if wants_json():
            return api_error("CA not found.", 404)
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))

    if ca.is_revoked:
        if wants_json():
            return api_error("Cannot generate CRL for a revoked CA.", 400)
        flash("Cannot generate CRL for a revoked CA.", "danger")
        return redirect(url_for("ca.detail", ca_id=ca.id))

    passphrase = current_app.config["MASTER_PASSPHRASE"]
    try:
        crl_service.generate_crl(ca, passphrase)
        audit_service.log_action("generate_crl", target_type="ca", target_id=ca.id)
        db.session.commit()
        if wants_json():
            return jsonify(ca.to_dict(detail=True))
        flash(f"CRL #{ca.crl_number} generated successfully.", "success")
    except ValueError as e:
        if wants_json():
            return api_error(str(e), 400)
        flash(str(e), "danger")
    except Exception:
        logger.exception("Error generating CRL")
        if wants_json():
            return api_error("An unexpected error occurred while generating the CRL.", 500)
        flash("An unexpected error occurred while generating the CRL.", "danger")

    return redirect(url_for("ca.detail", ca_id=ca.id))


# --- F11: alternate CA certificates (re-issue, cross-sign, import) --------------

def _alternate_or_none(raw):
    try:
        return db.session.get(CaCertificate, int(raw))
    except (TypeError, ValueError):
        return None


def _ca_or_error(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        if wants_json():
            return None, api_error("CA not found.", 404)
        flash("CA not found.", "danger")
        return None, redirect(url_for("ca.list_cas"))
    return ca, None


def _alt_error(ca, message, status=400):
    if wants_json():
        return api_error(message, status)
    flash(message, "danger")
    return redirect(url_for("ca.detail", ca_id=ca.id))


def _alt_approval_status():
    """Both operations are CA-creation events under dual control: pending
    until another admin approves (the bootstrap account is exempt)."""
    if dual_control_service.is_active() and not dual_control_service.is_exempt(current_user):
        return "pending"
    return "approved"


@ca_bp.route("/<int:ca_id>/reissue", methods=["POST"])
@admin_required
def reissue(ca_id):
    """F11: new certificate for the same key (same SKI/extensions, new serial and validity)."""
    ca, err = _ca_or_error(ca_id)
    if err:
        return err
    raw_days = (request.form.get("validity_days") or "").strip()
    try:
        validity_days = int(raw_days) if raw_days else None
    except ValueError:
        return _alt_error(ca, "Validity days must be a whole number.")
    status = _alt_approval_status()
    try:
        row = ca_service.reissue_ca_certificate(ca, current_app.config["MASTER_PASSPHRASE"], validity_days=validity_days,
                                                created_by=current_user.id, approval_status=status)
        audit_service.log_action("reissue_ca_certificate", target_type="ca", target_id=ca.id,
                                 details={"approval_status": status, "alternate_id": row.id,
                                          "serial_number": ca.serial_number if status == "approved" else row.serial_number,
                                          "not_after": ca.not_after.isoformat() if status == "approved" else row.not_after.isoformat()})
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return _alt_error(ca, str(e))
    except Exception:
        db.session.rollback()
        logger.exception("Error re-issuing CA certificate")
        return _alt_error(ca, "An unexpected error occurred while re-issuing the CA certificate.", 500)
    if status == "approved":
        warning = _crl_refresh_warning_ca(ca)
        if wants_json():
            payload = ca.to_dict(detail=True)
            if warning:
                payload["warning"] = warning
            return jsonify(payload), 201
        flash(f"CA certificate for '{ca.name}' re-issued (new serial, valid until {ca.not_after:%Y-%m-%d}); "
              "the previous certificate is kept as an alternate.", "success")
        if warning:
            flash(warning, "warning")
    else:
        if wants_json():
            return jsonify(row.to_dict()), 201
        flash("Re-issued certificate created and awaiting approval by another admin before it becomes the primary.", "warning")
    return redirect(url_for("ca.detail", ca_id=ca.id))


def _crl_refresh_warning_ca(ca):
    """After a re-issue the CRL is regenerated so its AKI/issuer match the new
    primary exactly (same key, so old CRLs stay valid too)."""
    if not ca.has_signing_key or ca.approval_status != "approved":
        return None
    try:
        crl_service.refresh_crl(ca, current_app.config["MASTER_PASSPHRASE"])
        return None
    except Exception:
        logger.exception("CRL refresh after re-issue failed")
        return "The CA certificate was re-issued but the CRL could not be regenerated; run Generate CRL."


@ca_bp.route("/<int:ca_id>/cross-sign", methods=["POST"])
@admin_required
def cross_sign(ca_id):
    """F11: a cross-certificate for this CA's key issued by another CA (`issuer_ca_id`)."""
    ca, err = _ca_or_error(ca_id)
    if err:
        return err
    try:
        issuer_id = int(request.form.get("issuer_ca_id", ""))
    except ValueError:
        return _alt_error(ca, "Choose the issuing CA.")
    issuer = CertificateAuthority.signing_capable().filter_by(id=issuer_id).first()
    if issuer is None:
        return _alt_error(ca, "Issuing CA not found, or it cannot sign (revoked, awaiting approval, or without a private key).")
    raw_days = (request.form.get("validity_days") or "").strip()
    try:
        validity_days = int(raw_days) if raw_days else None
    except ValueError:
        return _alt_error(ca, "Validity days must be a whole number.")
    status = _alt_approval_status()
    try:
        row = ca_service.cross_sign_ca(ca, issuer, current_app.config["MASTER_PASSPHRASE"], validity_days=validity_days,
                                       created_by=current_user.id, approval_status=status)
        audit_service.log_action("cross_sign_ca", target_type="ca", target_id=ca.id,
                                 details={"issuer_ca_id": issuer.id, "alternate_id": row.id, "approval_status": status,
                                          "serial_number": row.serial_number, "not_after": row.not_after.isoformat()})
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return _alt_error(ca, str(e))
    except Exception:
        db.session.rollback()
        logger.exception("Error cross-signing CA")
        return _alt_error(ca, "An unexpected error occurred while cross-signing the CA.", 500)
    if wants_json():
        return jsonify(row.to_dict()), 201
    if status == "approved":
        flash(f"'{ca.name}' cross-signed by '{issuer.name}' (valid until {row.not_after:%Y-%m-%d}).", "success")
    else:
        flash("Cross-certificate created and awaiting approval by another admin.", "warning")
    return redirect(url_for("ca.detail", ca_id=ca.id))


@ca_bp.route("/<int:ca_id>/certificates/import", methods=["POST"])
@admin_required
def import_alternate(ca_id):
    """F11: attach an externally issued cross-certificate for this CA's key."""
    ca, err = _ca_or_error(ca_id)
    if err:
        return err
    pem = (request.form.get("cert_pem") or "").strip()
    if not pem:
        return _alt_error(ca, "Certificate PEM data is required.")
    try:
        row = ca_service.import_alternate_certificate(ca, pem, created_by=current_user.id)
        audit_service.log_action("import_ca_certificate", target_type="ca", target_id=ca.id,
                                 details={"alternate_id": row.id, "issuer_ca_id": row.issuer_ca_id,
                                          "serial_number": row.serial_number})
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return _alt_error(ca, str(e))
    if wants_json():
        return jsonify(row.to_dict()), 201
    flash("Cross-signed certificate imported.", "success")
    return redirect(url_for("ca.detail", ca_id=ca.id))


@ca_bp.route("/<int:ca_id>/certificates/<int:alt_id>/approve", methods=["POST"])
@admin_required
def approve_alternate(ca_id, alt_id):
    ca, err = _ca_or_error(ca_id)
    if err:
        return err
    row = db.session.get(CaCertificate, alt_id)
    if row is None or row.ca_id != ca.id:
        return _alt_error(ca, "Alternate certificate not found.", 404)
    if row.approval_status != "pending":
        return _alt_error(ca, "This certificate is not awaiting approval.", 409)
    reason = dual_control_service.refuse_reason(current_user, row.created_by, "a CA certificate") if dual_control_service.is_active() else None
    if reason:
        return _alt_error(ca, reason, 403)
    kind = row.kind
    try:
        result = ca_service.approve_alternate(row, current_user.id)
        audit_service.log_action("approve_ca_certificate", target_type="ca", target_id=ca.id,
                                 details={"alternate_id": alt_id, "kind": kind})
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return _alt_error(ca, str(e))
    warning = _crl_refresh_warning_ca(ca) if kind == "reissue" else None
    if wants_json():
        payload = ca.to_dict(detail=True) if kind == "reissue" else result.to_dict()
        if warning:
            payload["warning"] = warning
        return jsonify(payload)
    flash("Re-issued certificate approved and promoted to primary." if kind == "reissue" else "Cross-certificate approved.", "success")
    if warning:
        flash(warning, "warning")
    return redirect(url_for("ca.detail", ca_id=ca.id))


@ca_bp.route("/<int:ca_id>/certificates/<int:alt_id>/delete", methods=["POST"])
@admin_required
def delete_alternate(ca_id, alt_id):
    ca, err = _ca_or_error(ca_id)
    if err:
        return err
    row = db.session.get(CaCertificate, alt_id)
    if row is None or row.ca_id != ca.id:
        return _alt_error(ca, "Alternate certificate not found.", 404)
    details = {"alternate_id": alt_id, "kind": row.kind, "serial_number": row.serial_number}
    ca_service.delete_alternate(row)
    audit_service.log_action("delete_ca_certificate", target_type="ca", target_id=ca.id, details=details)
    db.session.commit()
    if wants_json():
        return jsonify({"deleted": alt_id})
    flash("Alternate certificate removed.", "success")
    return redirect(url_for("ca.detail", ca_id=ca.id))


# --- F14: ACME settings and external-account-binding keys -------------------------

def _acme_dual_control_guard(ca):
    """Enabling ACME is the approved act under dual control: while the mode is
    active the CA's creator may not switch it on themselves (the bootstrap
    admin stays exempt, as for CA approval)."""
    if (dual_control_service.is_active() and not dual_control_service.is_exempt(current_user)
            and ca.created_by == current_user.id):
        raise ValueError("Dual control: another administrator must enable ACME on a CA you created.")


@ca_bp.route("/<int:ca_id>/acme", methods=["POST"])
@admin_required
def set_acme(ca_id):
    """Update a CA's ACME settings: enabled, profile, require EAB."""
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        if wants_json():
            return api_error("CA not found.", 404)
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))
    try:
        enable = request.form.get("acme_enabled") in ("on", "true", "1")
        if enable and not ca.acme_enabled:
            _acme_dual_control_guard(ca)
            if not ca.has_signing_key or ca.is_revoked or ca.approval_status != "approved":
                raise ValueError("Only an approved, unrevoked CA with a signing key can serve ACME.")
        raw_profile = (request.form.get("acme_profile") or "").strip()
        profile = None
        if raw_profile and raw_profile != "custom":
            profile = profile_service.lookup(raw_profile)
            if profile is None:
                raise ValueError(f"Unknown certificate profile '{raw_profile}'.")
            allowed = ca.allowed_profile_ids
            if allowed and profile.id not in allowed:
                raise ValueError("That profile is not in this CA's allowed profiles.")
        ca.acme_enabled = enable
        ca.acme_profile_id = profile.id if profile else None
        ca.acme_require_eab = request.form.get("acme_require_eab") in ("on", "true", "1")
        ca.acme_allow_wildcards = request.form.get("acme_allow_wildcards") in ("on", "true", "1")
        audit_service.log_action("update_ca_acme", target_type="ca", target_id=ca.id,
                                 details={"enabled": ca.acme_enabled, "profile": profile.key if profile else "custom",
                                          "require_eab": ca.acme_require_eab, "allow_wildcards": ca.acme_allow_wildcards})
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        if wants_json():
            return api_error(str(e), 403 if "Dual control" in str(e) else 400)
        flash(str(e), "danger")
        return redirect(url_for("ca.detail", ca_id=ca.id))
    if wants_json():
        return jsonify(ca.to_dict(detail=True))
    if ca.acme_enabled and not current_app.config.get("ACME_ENABLED"):
        flash("ACME settings saved, but ACME_ENABLED is off on this server — set it in .env to serve the directory.", "warning")
    else:
        flash("ACME settings saved.", "success")
    return redirect(url_for("ca.detail", ca_id=ca.id, _anchor="acme"))


@ca_bp.route("/<int:ca_id>/acme/eab", methods=["POST"])
@admin_required
def create_acme_eab(ca_id):
    """Issue an EAB key; the MAC key is shown once."""
    from ..services.acme import service as acme_service
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        if wants_json():
            return api_error("CA not found.", 404)
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))
    row, mac = acme_service.create_eab_key(ca, name=request.form.get("name"), created_by=current_user.id)
    db.session.commit()
    if wants_json():
        return jsonify({**row.to_dict(), "hmac_key": mac}), 201
    flash(f"EAB key created. kid: {row.kid} — MAC key (shown once): {mac}", "success")
    return redirect(url_for("ca.detail", ca_id=ca.id, _anchor="acme"))


@ca_bp.route("/<int:ca_id>/acme/eab/<int:key_id>/revoke", methods=["POST"])
@admin_required
def revoke_acme_eab(ca_id, key_id):
    from ..models.acme import AcmeEabKey
    from ..services.acme import service as acme_service
    row = db.session.get(AcmeEabKey, key_id)
    if row is None or row.ca_id != ca_id:
        if wants_json():
            return api_error("EAB key not found.", 404)
        flash("EAB key not found.", "danger")
        return redirect(url_for("ca.detail", ca_id=ca_id))
    if not row.revoked:
        acme_service.revoke_eab_key(row)
        db.session.commit()
    if wants_json():
        return jsonify(row.to_dict())
    flash(f"EAB key {row.kid} revoked.", "success")
    return redirect(url_for("ca.detail", ca_id=ca_id, _anchor="acme"))
