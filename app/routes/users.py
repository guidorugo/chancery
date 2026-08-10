from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import current_user

from ..decorators import admin_required
from ..extensions import db
from ..models.user import User
from ..models.audit_log import AuditLog
from ..responses import wants_json
from ..services import audit_service, auth_service

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
