from urllib.parse import urlsplit

from flask import Blueprint, current_app, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from ..extensions import db
from ..services import audit_service, auth_service
from ..services.audit_service import sanitize_username_for_log


def _is_safe_url(target):
    """Only allow a same-site, path-only relative redirect target.

    C5: a bare `startswith('/')` check let `/\\evil.com` through — browsers
    normalize the backslash to `/`, yielding a protocol-relative off-site
    redirect. Reject backslashes/control chars and require an empty scheme
    and host.
    """
    if not target:
        return False
    if "\\" in target or any(ord(c) < 0x20 for c in target):
        return False
    parts = urlsplit(target)
    return (
        not parts.scheme
        and not parts.netloc
        and target.startswith("/")
        and not target.startswith("//")
    )

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        result = auth_service.authenticate(username, password)

        if result.ok:
            login_user(result.user)
            audit_service.log_action(
                "login_success", target_type="user", target_id=result.user.id,
                details={"auth_method": result.auth_method},
            )
            db.session.commit()
            if result.user.must_change_password:
                flash("Please set a new password before continuing.", "warning")
                return redirect(url_for("auth.change_password"))
            next_page = request.args.get("next")
            if next_page and _is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for("dashboard.index"))

        audit_service.log_action(
            "login_failure", target_type="user",
            target_id=result.user.id if result.user else None,
            details={
                "reason": result.reason,
                "attempted_username": sanitize_username_for_log(username),
                "auth_method": result.auth_method,
            },
        )
        db.session.commit()

        if result.reason == auth_service.REASON_DEACTIVATED:
            flash("Your account has been deactivated.", "danger")
        elif result.reason == auth_service.REASON_LDAP_UNREACHABLE:
            flash("Directory service is unavailable. Try again later or use a local account.", "danger")
        else:
            # AUTH-2: one generic message for both invalid credentials AND a
            # lockout, so the login response can't be used to enumerate which
            # local usernames exist or are locked. The specific reason
            # (REASON_LOCKED / REASON_INVALID) is still recorded in the audit log.
            flash("Invalid username or password. If you have made several failed "
                  "attempts, please wait and try again later.", "danger")

    return render_template("auth/login.html")


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    # LDAP/externally-authenticated users have no local password to change here.
    if not current_user.has_usable_password():
        flash("Your password is managed by the directory and cannot be changed here.", "info")
        return redirect(url_for("dashboard.index"))

    forced = bool(current_user.must_change_password)
    min_len = current_app.config.get("MIN_PASSWORD_LENGTH", 12)

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not current_user.check_password(current_password):
            flash("Current password is incorrect.", "danger")
        elif len(new_password) < min_len:
            flash(f"New password must be at least {min_len} characters.", "danger")
        elif new_password != confirm_password:
            flash("New passwords do not match.", "danger")
        elif new_password == current_password:
            flash("New password must be different from the current password.", "danger")
        else:
            current_user.set_password(new_password)
            current_user.must_change_password = False
            audit_service.log_action(
                "change_password", target_type="user", target_id=current_user.id
            )
            db.session.commit()
            flash("Your password has been changed.", "success")
            return redirect(url_for("dashboard.index"))

    return render_template("auth/change_password.html", forced=forced, min_len=min_len)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit_service.log_action("logout", target_type="user", target_id=current_user.id)
    db.session.commit()
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
