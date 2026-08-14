from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import current_user

from ..decorators import admin_required
from ..extensions import db
from ..models.user import User
from ..models.audit_log import AuditLog
from ..responses import wants_json
from ..services import (audit_service, auth_service, ldap_service,
                        ldap_settings_service, webhook_service)

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

        user = User(username=username, role=role)
        user.set_password(password)
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

        user.set_password(new_password)
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
