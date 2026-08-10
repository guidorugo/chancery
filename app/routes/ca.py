import logging
import re

from flask import Blueprint, Response, render_template, redirect, url_for, flash, request, current_app, jsonify

from ..decorators import admin_required
from ..extensions import db
from ..models.ca import CertificateAuthority
from ..responses import api_error, wants_json
from ..services import ca_service, crl_service, audit_service
from ..services.keybackend import hsm_available

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


def _safe_filename(name, extension):
    """Sanitize user-provided name for Content-Disposition header."""
    safe = re.sub(r'[^\w.\-]', '_', name)
    return f'attachment; filename="{safe}.{extension}"'


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
    }


@ca_bp.route("/")
@admin_required
def list_cas():
    cas = CertificateAuthority.query.order_by(CertificateAuthority.created_at.desc()).all()
    if wants_json():
        return jsonify([ca.to_dict() for ca in cas])
    return render_template("ca/list.html", cas=cas)


@ca_bp.route("/create", methods=["GET", "POST"])
@admin_required
def create():
    def _err(message, status=400):
        # JSON for API clients; re-render the form (with flash) for browsers.
        if wants_json():
            return api_error(message, status)
        flash(message, "danger")
        return render_template("ca/create.html", **_create_page_context())

    if request.method == "POST":
        mode = request.form.get("mode", "generate")

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
                                                  passphrase, parent_id=parent_id)
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
                                              key_passphrase=key_passphrase or None)

                imported_parents = getattr(ca, "_imported_parents", [])
                audit_service.log_action(
                    "import_ca", target_type="ca", target_id=ca.id,
                    details={"format": import_format, "has_key": ca.has_private_key,
                             "imported_parents": imported_parents},
                )
                db.session.commit()
                msg = f"CA '{ca.name}' imported successfully."
                if imported_parents:
                    msg += (f" {len(imported_parents)} parent CA(s) imported from the "
                            f"chain: {', '.join(imported_parents)}.")
                if not ca.has_private_key:
                    msg += (" Imported without a private key: this CA cannot issue "
                            "certificates, sign CRLs, or answer OCSP.")
                if wants_json():
                    return jsonify(ca.to_dict(detail=True)), 201
                flash(msg, "success" if ca.has_private_key else "warning")
                return redirect(url_for("ca.detail", ca_id=ca.id))
            except ValueError as e:
                return _err(str(e))
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

            if not name or not cn:
                return _err("Name and Common Name are required.")

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
                    parent_ca = db.session.get(CertificateAuthority, parent_ca_id)
                    if not parent_ca:
                        return _err("Parent CA not found.")
                    ca = ca_service.create_intermediate_ca(
                        name, parent_ca, subject_attrs, key_type, key_size,
                        validity_days, passphrase, path_length=path_length,
                        backend=key_backend,
                    )
                else:
                    ca = ca_service.create_root_ca(
                        name, subject_attrs, key_type, key_size,
                        validity_days, passphrase, path_length=path_length,
                        backend=key_backend,
                    )
                audit_service.log_action("create_ca", target_type="ca", target_id=ca.id)
                db.session.commit()
                if wants_json():
                    return jsonify(ca.to_dict(detail=True)), 201
                flash(f"CA '{ca.name}' created successfully.", "success")
                return redirect(url_for("ca.detail", ca_id=ca.id))
            except ValueError as e:
                # Invalid input (e.g. a bad subject field or out-of-range
                # validity) — surface the reason as a 400, not a generic 500.
                return _err(str(e))
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
    return render_template("ca/detail.html", ca=ca, chain=chain)


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
        return Response(
            ca_service.get_ca_chain(ca),
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": _safe_filename(f"{ca.name}-chain", "pem")},
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
            headers={"Content-Disposition": _safe_filename(ca.name, "key")},
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
            headers={"Content-Disposition": _safe_filename(ca.name, "p12")},
        )

    return Response(
        ca.certificate_pem,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": _safe_filename(ca.name, "pem")},
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
        try:
            _, certs_revoked, sub_cas_revoked = crl_service.revoke_ca(
                ca_id, reason, passphrase=current_app.config["MASTER_PASSPHRASE"])
            audit_service.log_action("revoke_ca", target_type="ca", target_id=ca_id,
                                     details={"reason": reason, "certs_revoked": certs_revoked,
                                              "sub_cas_revoked": sub_cas_revoked})
            db.session.commit()
            msg = f"CA '{ca.name}' revoked."
            if certs_revoked:
                msg += f" {certs_revoked} certificate(s) revoked."
            if sub_cas_revoked:
                msg += f" {sub_cas_revoked} sub-CA(s) revoked."
            if wants_json():
                return jsonify(ca.to_dict(detail=True))
            flash(msg, "success")
            return redirect(url_for("ca.detail", ca_id=ca.id))
        except Exception:
            logger.exception("Error revoking CA")
            if wants_json():
                return api_error("An unexpected error occurred while revoking the CA.", 500)
            flash("An unexpected error occurred while revoking the CA.", "danger")

    # Count affected items for the confirmation page
    from ..models.certificate import Certificate
    cert_count = Certificate.query.filter_by(ca_id=ca.id, is_revoked=False).count()
    sub_ca_count = _count_active_sub_cas(ca)
    return render_template("ca/revoke.html", ca=ca, cert_count=cert_count, sub_ca_count=sub_ca_count)


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
