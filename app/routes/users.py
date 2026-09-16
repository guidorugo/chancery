from flask import Blueprint, current_app, render_template, redirect, url_for, flash, request, jsonify
from flask_login import current_user, login_required

from ..decorators import admin_required
from ..extensions import db
from ..models.user import User
from ..models.audit_log import AuditLog
from ..responses import wants_json
from ..models.certificate_profile import CertificateProfile
from ..responses import api_error
from ..services import (audit_service, auth_service, ldap_service,
                        ldap_settings_service, webhook_service, profile_service)

users_bp = Blueprint("users", __name__, url_prefix="/users")


@users_bp.route("/")
@admin_required
def list_users():
    users = User.query.order_by(User.created_at.desc()).all()
    if wants_json():
        return jsonify([u.to_dict() for u in users])
    return render_template("users/list.html", users=users)


@users_bp.route("/create", methods=["GET", "POST"])
@admin_required
def create_user():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "csr_requester")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("users/create.html")

        if role not in ("admin", "csr_requester"):
            flash("Invalid role.", "danger")
            return render_template("users/create.html")

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return render_template("users/create.html")

        min_len = current_app.config.get("MIN_PASSWORD_LENGTH", 12)
        if len(password) < min_len:  # G6-2: same floor as self-service changes
            flash(f"Password must be at least {min_len} characters.", "danger")
            return render_template("users/create.html")

        user = User(username=username, role=role)
        user.set_password(password)
        # G6-2: an admin-chosen password is a bootstrap credential — the user
        # picks their own on first login, exactly like the seeded admin.
        user.must_change_password = True
        db.session.add(user)
        db.session.flush()
        audit_service.log_action("create_user", target_type="user", target_id=user.id,
                                 details={"role": role})
        db.session.commit()
        flash(f"User '{username}' created.", "success")
        return redirect(url_for("users.list_users"))

    return render_template("users/create.html")


@users_bp.route("/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("users.list_users"))

    if request.method == "POST":
        new_role = request.form.get("role", user.role)
        if new_role not in ("admin", "csr_requester"):
            flash("Invalid role.", "danger")
            return render_template("users/edit.html", user=user)

        # Last admin guard: don't allow demoting the last active admin
        if user.role == "admin" and new_role != "admin":
            admin_count = User.query.filter_by(role="admin", is_active_user=True).count()
            if admin_count <= 1:
                flash("Cannot change role: this is the last active admin.", "danger")
                return render_template("users/edit.html", user=user)

        old_role = user.role
        user.role = new_role
        audit_service.log_action("update_user_role", target_type="user", target_id=user.id,
                                 details={"old_role": old_role, "new_role": new_role})
        db.session.commit()
        flash(f"User '{user.username}' role updated to {new_role}.", "success")
        return redirect(url_for("users.list_users"))

    return render_template("users/edit.html", user=user)


@users_bp.route("/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_active(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("users.list_users"))

    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("users.list_users"))

    if user.is_active_user and user.role == "admin":
        admin_count = User.query.filter_by(role="admin", is_active_user=True).count()
        if admin_count <= 1:
            flash("Cannot deactivate the last active admin.", "danger")
            return redirect(url_for("users.list_users"))

    user.is_active_user = not user.is_active_user
    if user.is_active_user:
        # AUTH-4: reactivating an account also clears any residual lockout.
        auth_service.clear_lockout(user)
    action = "activate_user" if user.is_active_user else "deactivate_user"
    audit_service.log_action(action, target_type="user", target_id=user.id)
    db.session.commit()

    status = "activated" if user.is_active_user else "deactivated"
    flash(f"User '{user.username}' {status}.", "success")
    return redirect(url_for("users.list_users"))


@users_bp.route("/<int:user_id>/reset-password", methods=["GET", "POST"])
@admin_required
def reset_password(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("users.list_users"))

    if user.is_ldap_user:
        flash("Cannot set a local password for an LDAP-managed user.", "warning")
        return redirect(url_for("users.list_users"))

    if request.method == "POST":
        new_password = request.form.get("password", "")
        if not new_password:
            flash("Password is required.", "danger")
            return render_template("users/reset_password.html", user=user)
        min_len = current_app.config.get("MIN_PASSWORD_LENGTH", 12)
        if len(new_password) < min_len:  # G6-2
            flash(f"Password must be at least {min_len} characters.", "danger")
            return render_template("users/reset_password.html", user=user)

        user.set_password(new_password)
        user.must_change_password = True  # G6-2: rotate on first login
        # AUTH-4: a password reset should also lift any brute-force lockout so
        # the account is immediately usable again.
        auth_service.clear_lockout(user)
        audit_service.log_action("reset_user_password", target_type="user", target_id=user.id)
        db.session.commit()
        flash(f"Password for '{user.username}' has been reset.", "success")
        return redirect(url_for("users.list_users"))

    return render_template("users/reset_password.html", user=user)


def _ldap_form_to_cfg(form):
    """Translate the settings form into a config dict (same keys as env)."""
    def text(name):
        return (form.get(name) or "").strip()

    def flag(name):
        return form.get(name) == "on"

    try:
        timeout = int(text("timeout_seconds") or "5")
    except ValueError:
        timeout = 0  # validate() reports it
    return {
        "LDAP_ENABLED": flag("enabled"),
        "LDAP_SERVER_URI": text("server_uri"),
        "LDAP_USE_STARTTLS": flag("use_starttls"),
        "LDAP_TLS_VERIFY": flag("tls_verify"),
        "LDAP_ALLOW_PLAINTEXT": flag("allow_plaintext"),
        "LDAP_CA_CERT_FILE": "",
        "LDAP_CA_CERT_PEM": text("ca_cert_pem"),
        "LDAP_USER_DN_TEMPLATE": text("user_dn_template"),
        "LDAP_BIND_DN": text("bind_dn"),
        "LDAP_BIND_PASSWORD": form.get("bind_password") or "",
        "LDAP_USER_SEARCH_BASE": text("user_search_base"),
        "LDAP_USER_FILTER": text("user_filter") or "(uid={username})",
        "LDAP_ADMIN_GROUP_DN": text("admin_group_dn"),
        "LDAP_REQUESTER_GROUP_DN": text("requester_group_dn"),
        "LDAP_GROUP_MEMBER_ATTR": text("group_member_attr") or "memberOf",
        "LDAP_TIMEOUT_SECONDS": timeout,
    }


def _render_ldap_page(cfg, test_result=None):
    return render_template(
        "users/ldap.html",
        cfg=cfg,
        source=ldap_settings_service.config_source(),
        has_stored_password=bool(ldap_settings_service.stored_bind_password()),
        test_result=test_result,
    )


@users_bp.route("/ldap", methods=["GET", "POST"])
@admin_required
def ldap_settings():
    if request.method == "GET":
        return _render_ldap_page(ldap_settings_service.effective_config())

    cfg = _ldap_form_to_cfg(request.form)

    if request.form.get("action") == "test":
        # A blank write-only password field means "use the stored one".
        candidate = dict(cfg)
        if not candidate["LDAP_BIND_PASSWORD"]:
            candidate["LDAP_BIND_PASSWORD"] = ldap_settings_service.stored_bind_password()
        errors = ldap_settings_service.validate(dict(candidate, LDAP_ENABLED=True))
        if errors:
            for e in errors:
                flash(e, "danger")
            return _render_ldap_page(cfg)
        result = ldap_service.test_config(
            candidate,
            test_username=(request.form.get("test_username") or "").strip(),
            test_password=request.form.get("test_password") or "",
            role_mapper=auth_service.map_ldap_role,
        )
        audit_service.log_action("test_ldap_settings", target_type="config",
                                 details={"ok": result["ok"]})
        db.session.commit()
        return _render_ldap_page(cfg, test_result=result)

    errors = ldap_settings_service.validate(cfg)
    if errors:
        for e in errors:
            flash(e, "danger")
        return _render_ldap_page(cfg)

    ldap_settings_service.save(cfg, updated_by=current_user.id)
    audit_service.log_action(
        "update_ldap_settings", target_type="config",
        details={"enabled": cfg["LDAP_ENABLED"], "server_uri": cfg["LDAP_SERVER_URI"],
                 "mode": "direct_bind" if cfg["LDAP_USER_DN_TEMPLATE"] else "search_bind",
                 "bind_password_changed": bool(cfg["LDAP_BIND_PASSWORD"])},
    )
    db.session.commit()
    flash("LDAP settings saved. They take effect immediately and override the "
          "LDAP_* environment variables.", "success")
    return redirect(url_for("users.ldap_settings"))


@users_bp.route("/ldap/reset", methods=["POST"])
@admin_required
def ldap_settings_reset():
    ldap_settings_service.reset()
    audit_service.log_action("reset_ldap_settings", target_type="config")
    db.session.commit()
    flash("Saved LDAP settings removed — the environment configuration "
          "(LDAP_* variables) is in effect again.", "success")
    return redirect(url_for("users.ldap_settings"))


def _webhook_form_to_cfg(form):
    """Translate the webhook settings form into a config dict (env keys)."""
    def text(name):
        return (form.get(name) or "").strip()

    try:
        timeout = int(text("timeout_seconds") or "5")
    except ValueError:
        timeout = 0  # validate() reports it
    if form.get("all_events") == "on":
        events = "all"
    else:
        selected = [action for action in webhook_service.catalog_actions()
                    if form.get(f"event_{action}") == "on"]
        events = ",".join(selected)
    return {
        "WEBHOOK_ENABLED": form.get("enabled") == "on",
        "WEBHOOK_URL": text("url"),
        "WEBHOOK_SECRET": form.get("secret") or "",
        "WEBHOOK_EVENTS": events,
        "WEBHOOK_TIMEOUT_SECONDS": timeout,
    }


def _render_webhook_page(cfg, test_result=None):
    selected = webhook_service.selected_events(cfg)
    return render_template(
        "users/webhooks.html",
        cfg=cfg,
        catalog=webhook_service.EVENT_CATALOG,
        all_events=(selected is None),
        selected_events=(selected or set()),
        source=webhook_service.config_source(),
        has_stored_secret=bool(webhook_service.stored_secret()),
        test_result=test_result,
    )


@users_bp.route("/webhooks", methods=["GET", "POST"])
@admin_required
def webhook_settings():
    if request.method == "GET":
        return _render_webhook_page(webhook_service.effective_config())

    cfg = _webhook_form_to_cfg(request.form)

    if request.form.get("action") == "test":
        # A blank write-only secret field means "use the stored one".
        candidate = dict(cfg, WEBHOOK_ENABLED=True)
        if not candidate["WEBHOOK_SECRET"]:
            candidate["WEBHOOK_SECRET"] = webhook_service.stored_secret()
        result = webhook_service.send_test(candidate)
        audit_service.log_action("test_webhook", target_type="config",
                                 details={"ok": result["ok"]})
        db.session.commit()
        return _render_webhook_page(cfg, test_result=result)

    errors = webhook_service.validate(cfg)
    if errors:
        for e in errors:
            flash(e, "danger")
        return _render_webhook_page(cfg)

    webhook_service.save(cfg, updated_by=current_user.id)
    audit_service.log_action(
        "update_webhook_settings", target_type="config",
        details={"enabled": cfg["WEBHOOK_ENABLED"], "url": cfg["WEBHOOK_URL"],
                 "events": cfg["WEBHOOK_EVENTS"],
                 "secret_changed": bool(cfg["WEBHOOK_SECRET"])},
    )
    db.session.commit()
    flash("Webhook settings saved. They take effect immediately and override "
          "the WEBHOOK_* environment variables.", "success")
    return redirect(url_for("users.webhook_settings"))


@users_bp.route("/webhooks/reset", methods=["POST"])
@admin_required
def webhook_settings_reset():
    webhook_service.reset()
    audit_service.log_action("reset_webhook_settings", target_type="config")
    db.session.commit()
    flash("Saved webhook settings removed — the environment configuration "
          "(WEBHOOK_* variables) is in effect again.", "success")
    return redirect(url_for("users.webhook_settings"))


# ---------------------------------------------------------------------------
# Certificate profiles (F1, 2.13.0)
# ---------------------------------------------------------------------------

KU_LABELS = (
    ("digital_signature", "Digital Signature"), ("key_encipherment", "Key Encipherment"),
    ("content_commitment", "Content Commitment"), ("data_encipherment", "Data Encipherment"),
    ("key_agreement", "Key Agreement"),
)
EKU_LABELS = (
    ("serverAuth", "Server Auth (TLS)"), ("clientAuth", "Client Auth"),
    ("codeSigning", "Code Signing"), ("emailProtection", "Email Protection"),
    ("timeStamping", "Time Stamping"), ("ocspSigning", "OCSP Signing"),
)
SAN_LABELS = (("dns", "DNS"), ("ip", "IP"), ("email", "Email"), ("uri", "URI"), ("upn", "UPN"))


def _profile_form_to_fields(form, existing=None):
    """Translate the profile form into the dict profile_service.validate/apply take."""
    def text(name):
        return (form.get(name) or "").strip()

    is_custom = existing is not None and existing.is_custom
    fields = {
        "name": text("name"),
        "description": text("description"),
        "include_ocsp_aia": form.get("include_ocsp_aia") == "on",
        "default_validity_days": text("default_validity_days") or "365",
        "max_validity_days": text("max_validity_days"),
        "min_rsa_bits": text("min_rsa_bits"),
        "max_rsa_bits": text("max_rsa_bits"),
        "require_san": form.get("require_san") == "on",
        "cn_in_san": form.get("cn_in_san") == "on",
        "enabled": form.get("enabled") == "on",
        "certificate_policies": text("certificate_policies"),  # F3: "OID [CPS]" lines
    }
    if not is_custom:
        fields["key_usage"] = {f: form.get(f"ku_{f}") == "on" for f, _ in KU_LABELS}
        fields["extended_key_usage"] = [n for n, _ in EKU_LABELS if form.get(f"eku_{n}") == "on"]
    types = [t for t in profile_service.KEY_TYPES if form.get(f"kt_{t}") == "on"]
    fields["allowed_key_types"] = types if types else None
    ec = [s for s in profile_service.EC_SIZES if form.get(f"ec_{s}") == "on"]
    fields["allowed_ec_sizes"] = ec if ec else None
    san = [t for t, _ in SAN_LABELS if form.get(f"san_{t}") == "on"]
    fields["allowed_san_types"] = san if san else None
    return fields


def _render_profile_form(profile=None, fields=None):
    fields = dict(fields or {})
    if "certificate_policies_text" not in fields:
        from ..services import certificate_policies
        raw = fields.get("certificate_policies")
        fields["certificate_policies_text"] = raw if isinstance(raw, str) else certificate_policies.to_lines(raw)
    return render_template("users/profile_form.html", profile=profile, fields=fields,
                           ku_labels=KU_LABELS, eku_labels=EKU_LABELS, san_labels=SAN_LABELS,
                           key_types=profile_service.KEY_TYPES, ec_sizes=profile_service.EC_SIZES)


@users_bp.route("/profiles")
@admin_required
def profiles():
    rows = profile_service.list_profiles()
    if wants_json():
        return jsonify([p.to_dict() for p in rows])
    usage = {p.id: profile_service.usage_counts(p) for p in rows}
    return render_template("users/profiles.html", profiles=rows, usage=usage)


@users_bp.route("/profiles/new", methods=["GET", "POST"])
@admin_required
def profile_new():
    if request.method == "GET":
        return _render_profile_form(fields={"enabled": True, "include_ocsp_aia": True,
                                            "default_validity_days": 365})
    fields = _profile_form_to_fields(request.form)
    try:
        row = profile_service.create(fields, updated_by=current_user.id)
    except ValueError as e:
        if wants_json():
            return api_error(str(e), 400)
        flash(str(e), "danger")
        return _render_profile_form(fields=fields)
    audit_service.log_action("create_profile", target_type="profile", target_id=row.id,
                             details={"key": row.key, "name": row.name})
    db.session.commit()
    if wants_json():
        return jsonify(row.to_dict()), 201
    flash(f"Profile '{row.name}' created.", "success")
    return redirect(url_for("users.profiles"))


@users_bp.route("/profiles/<int:profile_id>/edit", methods=["GET", "POST"])
@admin_required
def profile_edit(profile_id):
    row = db.session.get(CertificateProfile, profile_id)
    if not row:
        if wants_json():
            return api_error("Profile not found.", 404)
        flash("Profile not found.", "danger")
        return redirect(url_for("users.profiles"))
    if request.method == "GET":
        return _render_profile_form(profile=row, fields=row.to_dict())
    fields = _profile_form_to_fields(request.form, existing=row)
    try:
        profile_service.update(row, fields, updated_by=current_user.id)
    except ValueError as e:
        if wants_json():
            return api_error(str(e), 400)
        flash(str(e), "danger")
        return _render_profile_form(profile=row, fields=fields)
    audit_service.log_action("update_profile", target_type="profile", target_id=row.id,
                             details={"key": row.key, "name": row.name})
    db.session.commit()
    if wants_json():
        return jsonify(row.to_dict())
    flash(f"Profile '{row.name}' updated.", "success")
    return redirect(url_for("users.profiles"))


@users_bp.route("/profiles/<int:profile_id>/toggle", methods=["POST"])
@admin_required
def profile_toggle(profile_id):
    row = db.session.get(CertificateProfile, profile_id)
    if not row:
        if wants_json():
            return api_error("Profile not found.", 404)
        flash("Profile not found.", "danger")
        return redirect(url_for("users.profiles"))
    row.enabled = not row.enabled
    row.updated_by = current_user.id
    audit_service.log_action("toggle_profile", target_type="profile", target_id=row.id,
                             details={"key": row.key, "enabled": row.enabled})
    db.session.commit()
    if wants_json():
        return jsonify(row.to_dict())
    flash(f"Profile '{row.name}' {'enabled' if row.enabled else 'disabled'}.", "success")
    return redirect(url_for("users.profiles"))


@users_bp.route("/profiles/<int:profile_id>/delete", methods=["POST"])
@admin_required
def profile_delete(profile_id):
    row = db.session.get(CertificateProfile, profile_id)
    if not row:
        if wants_json():
            return api_error("Profile not found.", 404)
        flash("Profile not found.", "danger")
        return redirect(url_for("users.profiles"))
    key, name = row.key, row.name
    try:
        profile_service.delete(row)
    except ValueError as e:
        if wants_json():
            return api_error(str(e), 409)
        flash(str(e), "danger")
        return redirect(url_for("users.profiles"))
    audit_service.log_action("delete_profile", target_type="profile", target_id=profile_id,
                             details={"key": key, "name": name})
    db.session.commit()
    if wants_json():
        return jsonify({"deleted": profile_id})
    flash(f"Profile '{name}' deleted.", "success")
    return redirect(url_for("users.profiles"))


@users_bp.route("/audit-log")
@admin_required
def audit_log():
    page = request.args.get("page", 1, type=int)
    per_page = 50
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    if wants_json():
        return jsonify({
            "items": [log.to_dict() for log in logs.items],
            "page": logs.page,
            "per_page": logs.per_page,
            "total": logs.total,
            "pages": logs.pages,
        })
    return render_template("users/audit_log.html", logs=logs)


# --- F12: scoped API tokens ------------------------------------------------------

@users_bp.route("/api-tokens", methods=["GET", "POST"])
@login_required
def api_tokens():
    """Own tokens for every account; admins also see everyone's and may revoke
    any. A new token's secret is shown once, in the response only."""
    from ..models.api_token import SCOPES, SCOPE_LABELS
    from ..services import api_token_service
    if request.method == "POST":
        scopes = [sc for sc in SCOPES if request.form.get(f"scope_{sc}") == "on"] or request.form.getlist("scopes")
        try:
            plaintext, row = api_token_service.create(
                current_user, request.form.get("name"), scopes,
                request.form.get("expires_in_days") or 30, created_by=current_user.id)
            db.session.commit()
        except ValueError as e:
            db.session.rollback()
            if wants_json():
                return api_error(str(e), 400)
            flash(str(e), "danger")
            return redirect(url_for("users.api_tokens"))
        if wants_json():
            payload = row.to_dict()
            payload["token"] = plaintext
            return jsonify(payload), 201
        return _render_api_tokens(new_token=plaintext, new_row=row)
    if wants_json():
        rows = api_token_service.list_all() if current_user.is_admin else api_token_service.list_for_user(current_user)
        return jsonify([r.to_dict() for r in rows])
    return _render_api_tokens()


def _render_api_tokens(new_token=None, new_row=None):
    from ..models.api_token import SCOPE_LABELS
    from ..services import api_token_service
    mine = api_token_service.list_for_user(current_user)
    others = [r for r in api_token_service.list_all() if r.user_id != current_user.id] if current_user.is_admin else []
    return render_template("users/api_tokens.html", mine=mine, others=others, scope_labels=SCOPE_LABELS,
                           max_days=api_token_service.max_days(), new_token=new_token, new_row=new_row)


@users_bp.route("/api-tokens/<int:token_id>/revoke", methods=["POST"])
@login_required
def revoke_api_token(token_id):
    from ..models.api_token import ApiToken
    from ..services import api_token_service
    row = db.session.get(ApiToken, token_id)
    if row is None or (row.user_id != current_user.id and not current_user.is_admin):
        if wants_json():
            return api_error("API token not found.", 404)
        flash("API token not found.", "danger")
        return redirect(url_for("users.api_tokens"))
    api_token_service.revoke(row)
    db.session.commit()
    if wants_json():
        return jsonify(row.to_dict())
    flash(f"API token '{row.name}' revoked.", "success")
    return redirect(url_for("users.api_tokens"))
