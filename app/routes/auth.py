from urllib.parse import urlsplit

import json
import time
from datetime import datetime, timezone

from flask import Blueprint, current_app, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user

from ..extensions import db
from ..models.user import User
from ..services import audit_service, auth_service, crypto_utils, totp_service
from ..services.audit_service import sanitize_username_for_log

PRE_2FA_TTL_SECONDS = 300
LOW_RECOVERY_CODES = 2      # warn loudly when this many (or fewer) recovery codes are left


def _finish_login(user, auth_method, next_page=None, second_factor=None):
    """Complete a login: Flask-Login session, session-version stamp (G6-4),
    audit, forced-password redirect, safe `next`."""
    login_user(user)
    session["sv"] = user.session_version
    session.pop("pre_2fa", None)
    details = {"auth_method": auth_method}
    if second_factor:
        details["second_factor"] = second_factor
    audit_service.log_action("login_success", target_type="user", target_id=user.id, details=details)
    db.session.commit()
    if user.must_change_password:
        flash("Please set a new password before continuing.", "warning")
        return redirect(url_for("auth.change_password"))
    if next_page and _is_safe_url(next_page):
        return redirect(next_page)
    return redirect(url_for("dashboard.index"))


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
            if result.user.totp_enabled:
                # F13: password accepted; the session is not established until
                # the second factor is. Only the user id travels in the cookie.
                session["pre_2fa"] = {"uid": result.user.id, "exp": int(time.time()) + PRE_2FA_TTL_SECONDS,
                                      "method": result.auth_method, "next": request.args.get("next")}
                return redirect(url_for("auth.two_factor"))
            return _finish_login(result.user, result.auth_method, request.args.get("next"))

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
        elif result.reason == auth_service.REASON_PENDING:
            flash("Your account is awaiting approval by an administrator.", "warning")
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
            auth_service.bump_session_version(current_user, keep_current=True)  # G6-4: other sessions drop
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


# --- F13: TOTP second factor ---------------------------------------------------

def _pre_2fa_user():
    pending = session.get("pre_2fa")
    if not pending or pending.get("exp", 0) < time.time():
        session.pop("pre_2fa", None)
        return None, None
    user = db.session.get(User, pending["uid"])
    if user is None or not user.is_active or not user.totp_enabled:
        session.pop("pre_2fa", None)
        return None, None
    return user, pending


def _totp_secret(user):
    return crypto_utils.decrypt_secret(user.totp_secret_enc, current_app.config["MASTER_PASSPHRASE"])


def _check_second_factor(user, code):
    """Accept a TOTP code (replay-protected) or an unused recovery code.
    Returns "totp", "recovery" or None; persists the replay/consumption state."""
    step = totp_service.verify(_totp_secret(user), code, last_step=user.totp_last_step)
    if step is not None:
        user.totp_last_step = step
        db.session.add(user)
        return "totp"
    remaining, ok = totp_service.consume_recovery_code(user.recovery_codes, code)
    if ok:
        user.recovery_codes_json = json.dumps(remaining)
        db.session.add(user)
        return "recovery"
    return None


@auth_bp.route("/2fa", methods=["GET", "POST"])
def two_factor():
    user, pending = _pre_2fa_user()
    if user is None:
        flash("Please log in again.", "warning")
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        if auth_service.is_locked(user):
            flash("Too many failed attempts; please wait and try again later.", "danger")
            return render_template("auth/two_factor.html")
        kind = _check_second_factor(user, request.form.get("code", ""))
        if kind is None:
            auth_service.register_failed_attempt(user)      # 2FA failures count toward the lockout
            audit_service.log_action("login_2fa_failed", target_type="user", target_id=user.id,
                                     details={"username": user.username})
            db.session.commit()
            flash("That code was not accepted.", "danger")
            return render_template("auth/two_factor.html")
        auth_service.clear_lockout(user)
        response = _finish_login(user, pending.get("method", "local"), pending.get("next"), second_factor=kind)
        if kind == "recovery":
            left = len(user.recovery_codes)
            if left <= LOW_RECOVERY_CODES:
                flash(f"You signed in with a recovery code; only {left} remain. Generate new recovery codes now "
                      "(Two-factor page) so you are not locked out.", "danger")
            else:
                flash(f"You signed in with a recovery code; {left} remain.", "warning")
        return response
    return render_template("auth/two_factor.html")


@auth_bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def two_factor_setup():
    """Enrol: show a pending secret (QR + manual key), confirm one code, then
    show the recovery codes once. When already enabled, the page shows the
    status with disable / regenerate-codes forms."""
    issuer = current_app.config.get("TOTP_ISSUER", "Chancery")
    enforced = totp_service.enforced_for(current_user, current_app.config)
    forced = enforced and not current_user.totp_enabled
    if current_user.totp_enabled:
        return render_template("auth/two_factor_setup.html", enabled=True, forced=False, enforced=enforced,
                               remaining=len(current_user.recovery_codes), low=LOW_RECOVERY_CODES)
    if request.method == "POST":
        secret = session.get("totp_setup_secret")
        if not secret:
            flash("The enrolment expired; start again.", "warning")
            return redirect(url_for("auth.two_factor_setup"))
        step = totp_service.verify(secret, request.form.get("code", ""))
        if step is None:
            flash("That code was not accepted — check the time on your device and try again.", "danger")
            return render_template("auth/two_factor_setup.html", enabled=False, forced=forced, secret=secret,
                                   otpauth=totp_service.otpauth_url(issuer, current_user.username, secret),
                                   qr_svg=totp_service.qr_svg(totp_service.otpauth_url(issuer, current_user.username, secret)))
        codes, hashes = totp_service.generate_recovery_codes()
        current_user.totp_secret_enc = crypto_utils.encrypt_secret(secret, current_app.config["MASTER_PASSPHRASE"])
        current_user.totp_enabled = True
        current_user.totp_confirmed_at = datetime.now(timezone.utc)
        current_user.totp_last_step = step
        current_user.recovery_codes_json = json.dumps(hashes)
        auth_service.bump_session_version(current_user, keep_current=True)
        audit_service.log_action("totp_enabled", target_type="user", target_id=current_user.id)
        db.session.commit()
        session.pop("totp_setup_secret", None)
        flash("Two-factor authentication is enabled. Store the recovery codes below now — they will not be shown again.", "success")
        return render_template("auth/two_factor_setup.html", enabled=True, forced=False, enforced=enforced,
                               remaining=len(codes), new_codes=codes, low=LOW_RECOVERY_CODES)
    secret = session.get("totp_setup_secret") or totp_service.generate_secret()
    session["totp_setup_secret"] = secret
    url = totp_service.otpauth_url(issuer, current_user.username, secret)
    return render_template("auth/two_factor_setup.html", enabled=False, forced=forced, secret=secret, otpauth=url,
                           qr_svg=totp_service.qr_svg(url))


@auth_bp.route("/2fa/disable", methods=["POST"])
@login_required
def two_factor_disable():
    if not current_user.totp_enabled:
        return redirect(url_for("auth.two_factor_setup"))
    if totp_service.enforced_for(current_user, current_app.config):
        # 2.28.0: under REQUIRE_2FA the second factor is not optional. Losing the
        # authenticator is handled by an admin reset (or `flask users reset-2fa`),
        # after which enrolment is forced again at the next login.
        flash("Two-factor authentication is required for your account and cannot be disabled here. "
              "If you lose your authenticator, an administrator can reset it.", "warning")
        return redirect(url_for("auth.two_factor_setup"))
    if current_user.has_usable_password() and not current_user.check_password(request.form.get("password", "")):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("auth.two_factor_setup"))
    if _check_second_factor(current_user, request.form.get("code", "")) is None:
        flash("That code was not accepted.", "danger")
        return redirect(url_for("auth.two_factor_setup"))
    _clear_totp(current_user)
    auth_service.bump_session_version(current_user, keep_current=True)
    audit_service.log_action("totp_disabled", target_type="user", target_id=current_user.id)
    db.session.commit()
    flash("Two-factor authentication is disabled.", "success")
    return redirect(url_for("auth.two_factor_setup"))


@auth_bp.route("/2fa/recovery-codes", methods=["POST"])
@login_required
def two_factor_recovery_codes():
    if not current_user.totp_enabled:
        return redirect(url_for("auth.two_factor_setup"))
    if _check_second_factor(current_user, request.form.get("code", "")) is None:
        flash("That code was not accepted.", "danger")
        return redirect(url_for("auth.two_factor_setup"))
    codes, hashes = totp_service.generate_recovery_codes()
    current_user.recovery_codes_json = json.dumps(hashes)
    audit_service.log_action("recovery_codes_regenerated", target_type="user", target_id=current_user.id)
    db.session.commit()
    flash("New recovery codes generated; the old ones no longer work.", "success")
    return render_template("auth/two_factor_setup.html", enabled=True, forced=False,
                           enforced=totp_service.enforced_for(current_user, current_app.config),
                           remaining=len(codes), new_codes=codes, low=LOW_RECOVERY_CODES)


def _clear_totp(user):
    user.totp_secret_enc = None
    user.totp_enabled = False
    user.totp_confirmed_at = None
    user.totp_last_step = None
    user.recovery_codes_json = None
    db.session.add(user)
