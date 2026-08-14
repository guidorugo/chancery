import os
import sys

from flask import Flask, current_app, flash, g, jsonify, redirect, request, session, url_for

from .config import Config
from .extensions import db, login_manager, csrf


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # G2: only trust X-Forwarded-* when explicitly told how many proxy hops sit
    # in front (TRUSTED_PROXY_COUNT). Default 0 = directly exposed, use
    # remote_addr as-is so a client cannot spoof its IP via a forged header.
    _hops = app.config.get("TRUSTED_PROXY_COUNT", 0)
    if _hops and _hops > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=_hops, x_proto=_hops, x_host=_hops, x_port=_hops
        )

    db.init_app(app)
    login_manager.init_app(app)
    # DoS-1: set up rate limiting BEFORE Basic Auth so the limiter's
    # before_request runs first — a flooding IP is rejected with 429 before the
    # expensive password-hash / audit write inside check_basic_auth.
    _setup_rate_limiting(app)
    _setup_basic_auth(app)
    csrf.init_app(app)

    _check_security(app)
    _validate_ldap_config(app)
    _validate_key_backend_config(app)
    _configure_session(app)
    _setup_security_headers(app)
    _setup_error_handlers(app)
    _register_template_context(app)
    _setup_password_change_guard(app)

    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.ca import ca_bp
    from .routes.certificates import certificates_bp
    from .routes.csr import csr_bp
    from .routes.public import public_bp
    from .routes.users import users_bp
    from .routes.health import health_bp
    from .routes.metrics import metrics_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(ca_bp)
    app.register_blueprint(certificates_bp)
    app.register_blueprint(csr_bp)
    app.register_blueprint(public_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(metrics_bp)

    # Monitoring probes must not be throttled if rate limiting is enabled.
    if getattr(app, "limiter", None) is not None:
        app.limiter.exempt(health_bp)
        app.limiter.exempt(metrics_bp)

    from .cli import keys_cli, certs_cli, users_cli, crl_cli, metrics_cli
    app.cli.add_command(keys_cli)
    app.cli.add_command(certs_cli)
    app.cli.add_command(users_cli)
    app.cli.add_command(crl_cli)
    app.cli.add_command(metrics_cli)

    with app.app_context():
        from . import models  # noqa: F401
        db.create_all()
        _migrate_schema()
        _create_default_admin(app)

    return app


def _register_template_context(app):
    """Expose the app version to every template (rendered as footer small-print).

    Uses the APP_VERSION env override if set, else the baked-in __version__ so
    the footer reflects exactly which build is running.
    """
    from ._version import __version__
    from .services import update_service

    app_version = os.environ.get("APP_VERSION") or __version__

    @app.context_processor
    def inject_app_version():
        update_available, latest_version = update_service.check(app.config)
        return {
            "app_version": app_version,
            "update_available": update_available,
            "latest_version": latest_version,
            "update_repo": app.config.get("UPDATE_CHECK_REPO") or "guidorugo/cert-manager",
        }


def _setup_password_change_guard(app):
    """Force a session user flagged ``must_change_password`` to set a new one
    before using the app (the bootstrap admin). Programmatic Basic Auth clients
    are exempt (they cannot do an interactive change); public endpoints and the
    change-password / logout routes stay reachable."""
    from flask import flash, redirect, url_for
    from flask_login import current_user

    _ALLOWED = {"auth.change_password", "auth.logout", "static"}

    @app.before_request
    def _require_password_change():
        if getattr(g, "basic_auth_used", False):
            return
        if request.blueprint in ("public", "health", "metrics") or request.endpoint in _ALLOWED:
            return
        if not current_user.is_authenticated:
            return
        if not getattr(current_user, "must_change_password", False):
            return
        flash("Please set a new password before continuing.", "warning")
        return redirect(url_for("auth.change_password"))


def _setup_basic_auth(app):
    """Configure HTTP Basic Auth via before_request + unauthorized_handler."""

    from .services.auth_service import CredentialCache
    app.basic_auth_cache = CredentialCache(app.config.get("BASIC_AUTH_CACHE_TTL_SECONDS", 60))

    @app.before_request
    def check_basic_auth():
        g.basic_auth_used = False
        g.basic_auth_user = None
        # g can outlive a single request when an app context is held open
        # around requests (tests do this); never let a previous request's
        # cached Flask-Login user leak into this one.
        g.pop("_login_user", None)

        if not app.config.get("BASIC_AUTH_ENABLED", True):
            return

        auth = request.authorization
        if auth is None or auth.type != "basic":
            return

        from .services import auth_service
        from .services.audit_service import log_action, sanitize_username_for_log

        result = auth_service.authenticate_basic(auth.username, auth.password)

        if not result.ok:
            log_action(
                "basic_auth_failed",
                target_type="user",
                details={
                    "username": sanitize_username_for_log(auth.username),
                    "auth_method": "basic_auth",
                    "reason": result.reason,
                },
            )
            db.session.commit()
            if result.reason == auth_service.REASON_LDAP_UNREACHABLE:
                response = jsonify({"error": "Directory service unavailable."})
                response.status_code = 503
                return response
            return

        g.basic_auth_used = True
        g.basic_auth_user = result.user
        # authenticate_basic() may have written audit entries (LDAP user
        # provisioning / role sync), and audit logging reads current_user —
        # which makes Flask-Login cache the anonymous user for the rest of
        # the request. Drop that cache so the request loader re-runs and
        # picks up g.basic_auth_user.
        g.pop("_login_user", None)

        log_action(
            "basic_auth_success",
            target_type="user",
            target_id=result.user.id,
            details={
                "username": result.user.username,
                "auth_method": "basic_auth",
                "auth_backend": result.auth_method,
            },
        )
        db.session.commit()

        # AUTH-3: a Basic-Auth user still flagged for a forced password change
        # must rotate it (via the web UI) before programmatic access is allowed,
        # so a never-rotated bootstrap seed can't be used indefinitely via the API.
        if getattr(result.user, "must_change_password", False):
            response = jsonify({
                "error": "Password change required — set a new password via the web UI "
                         "before using Basic Auth."
            })
            response.status_code = 403
            return response

    @login_manager.unauthorized_handler
    def handle_unauthorized():
        # login_manager is a module-level singleton, so every create_app()
        # call re-registers this handler. Read config through current_app —
        # not the closed-over app — so the handler always serves the app
        # actually handling the request.
        if current_app.config.get("BASIC_AUTH_ENABLED", True) and request.authorization is not None:
            realm = current_app.config.get("BASIC_AUTH_REALM", "cert-manager")
            response = jsonify({"error": "Invalid credentials."})
            response.status_code = 401
            response.headers["WWW-Authenticate"] = f'Basic realm="{realm}"'
            return response
        # API-4: a JSON client with no Basic-Auth header gets a clean 401 JSON
        # (no WWW-Authenticate, so no browser Basic dialog) rather than an HTML redirect.
        from .responses import wants_json
        if wants_json():
            return jsonify({"error": "Authentication required."}), 401
        return current_app.login_manager.login_view and _redirect_to_login() or ("Unauthorized", 401)

    def _redirect_to_login():
        from flask import flash, redirect, url_for
        flash("Please log in to access this page.", "warning")
        return redirect(url_for(login_manager.login_view, next=request.url))


def _check_security(app):
    """Reject insecure defaults in production."""
    if app.config.get("TESTING"):
        return
    if app.debug:
        # F2: debug mode exposes the Werkzeug interactive debugger (arbitrary
        # remote code execution) and skips the fatal insecure-default checks
        # below. Make that loud rather than silent — never enable debug in
        # production (the shipped gunicorn stack never does).
        print("WARNING: Flask debug mode is ON — the interactive debugger allows "
              "remote code execution and the insecure-default checks are skipped. "
              "Use only for local development.", file=sys.stderr)
        return

    insecure_secret = Config._INSECURE_SECRET_KEY
    insecure_passphrase = Config._INSECURE_PASSPHRASE

    # CORE-2: reject empty/blank as well as the literal insecure default — an
    # empty secret file (e.g. truncated on disk) must not boot silently. An
    # empty MASTER_PASSPHRASE would encrypt every CA key under an empty KDF input.
    secret = app.config.get("SECRET_KEY")
    if not secret or not secret.strip() or secret == insecure_secret:
        print("FATAL: SECRET_KEY is unset, blank, or the insecure default. "
              "Set a strong SECRET_KEY.", file=sys.stderr)
        sys.exit(1)

    passphrase = app.config.get("MASTER_PASSPHRASE")
    if not passphrase or not passphrase.strip() or passphrase == insecure_passphrase:
        print("FATAL: MASTER_PASSPHRASE is unset, blank, or the insecure default. "
              "Set a strong MASTER_PASSPHRASE.", file=sys.stderr)
        sys.exit(1)

    # NOTE: the ADMIN_PASSWORD insecure-default guard lives in
    # _create_default_admin — it only matters when the seed actually creates the
    # first admin. Once an admin exists, ADMIN_PASSWORD is unused and may be
    # removed from the environment / .env.


def _validate_ldap_config(app):
    """Fail fast on an unusable LDAP configuration (runs in every mode).

    This guards the environment-variable config only. Settings saved from the
    admin UI (ldap_settings row, which takes precedence at runtime) are
    validated by ldap_settings_service.validate() before they can be stored.
    """
    if not app.config.get("LDAP_ENABLED"):
        return

    def fatal(msg):
        print(f"FATAL: {msg}", file=sys.stderr)
        sys.exit(1)

    if not app.config.get("LDAP_SERVER_URI"):
        fatal("LDAP_ENABLED is true but LDAP_SERVER_URI is not set.")

    # E3: refuse silent plaintext LDAP. Every server URI must be ldaps:// or use
    # StartTLS, unless the operator explicitly opts into cleartext.
    if not app.config.get("LDAP_ALLOW_PLAINTEXT"):
        uris = [u.strip() for u in app.config["LDAP_SERVER_URI"].split(",") if u.strip()]
        plaintext = [u for u in uris
                     if u.lower().startswith("ldap://") and not app.config.get("LDAP_USE_STARTTLS")]
        if plaintext:
            fatal("LDAP over cleartext is refused: " + ", ".join(plaintext) +
                  ". Use ldaps:// or set LDAP_USE_STARTTLS=true; to override "
                  "(not recommended) set LDAP_ALLOW_PLAINTEXT=true.")

    template = app.config.get("LDAP_USER_DN_TEMPLATE")
    search_base = app.config.get("LDAP_USER_SEARCH_BASE")

    if template and search_base:
        fatal("Set either LDAP_USER_DN_TEMPLATE (direct bind) or "
              "LDAP_USER_SEARCH_BASE (search+bind), not both.")
    if not template and not search_base:
        fatal("LDAP_ENABLED is true but neither LDAP_USER_DN_TEMPLATE nor "
              "LDAP_USER_SEARCH_BASE is set.")
    if template and "{username}" not in template:
        fatal("LDAP_USER_DN_TEMPLATE must contain a {username} placeholder.")
    if search_base:
        if "{username}" not in app.config.get("LDAP_USER_FILTER", ""):
            fatal("LDAP_USER_FILTER must contain a {username} placeholder.")
        if not app.config.get("LDAP_BIND_DN") or not app.config.get("LDAP_BIND_PASSWORD"):
            fatal("Search+bind mode requires LDAP_BIND_DN and LDAP_BIND_PASSWORD "
                  "(anonymous directory search is not supported).")


def _validate_key_backend_config(app):
    """Fail fast when KEY_BACKEND=softhsm but the PKCS#11 token can't be used."""
    if app.config.get("KEY_BACKEND") != "softhsm":
        return

    def fatal(msg):
        print(f"FATAL: {msg}", file=sys.stderr)
        sys.exit(1)

    try:
        import pkcs11  # noqa: F401
    except Exception as exc:
        fatal(f"KEY_BACKEND=softhsm but python-pkcs11 is not importable: {exc}")

    module = app.config.get("PKCS11_MODULE")
    if not module or not os.path.exists(module):
        fatal(f"KEY_BACKEND=softhsm but PKCS11_MODULE does not exist: {module!r}")
    if not app.config.get("PKCS11_TOKEN_LABEL"):
        fatal("KEY_BACKEND=softhsm but PKCS11_TOKEN_LABEL is not set.")
    if not app.config.get("PKCS11_USER_PIN"):
        fatal("KEY_BACKEND=softhsm but PKCS11_USER_PIN (or PKCS11_USER_PIN_FILE) is not set.")


def _setup_security_headers(app):
    """Add security response headers to all responses."""
    import secrets

    @app.before_request
    def _set_csp_nonce():
        # TMPL-1: a per-request nonce authorises exactly the inline <script>
        # blocks our templates emit, so 'unsafe-inline' can be dropped from
        # script-src (inline event handlers were moved to addEventListener).
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def _inject_csp_nonce():
        return {"csp_nonce": g.get("csp_nonce", "")}

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # E2/TMPL-1: restrict resource origins, frame embedding, and base URI.
        # script-src uses a per-request nonce (no 'unsafe-inline'); style-src
        # keeps 'unsafe-inline' for the handful of inline style="" attributes
        # (far lower risk than script). object/frame-ancestors are locked down.
        nonce = g.get("csp_nonce", "")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            f"script-src 'self' https://cdn.jsdelivr.net 'nonce-{nonce}'; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
            "form-action 'self'",
        )
        # `same-origin` (not `no-referrer`): still never leaks the Referer to
        # third parties, but DOES send it on same-origin requests — so Flask-WTF's
        # HTTPS CSRF referer check works behind a TLS proxy. `no-referrer` made the
        # browser send no Referer at all, which that check rejects, 400'ing every
        # form POST (login included) over TLS.
        response.headers.setdefault("Referrer-Policy", "same-origin")
        # HSTS is ignored by browsers over plain HTTP, so it's safe to always
        # send; it takes effect once the app is served over TLS.
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
        )
        return response


def _setup_error_handlers(app):
    """API-4/CORE-6: return JSON on common error statuses for API clients
    (Basic Auth / Accept: application/json), the default HTML otherwise."""
    from urllib.parse import urlsplit

    from flask_login import current_user
    from flask_wtf.csrf import CSRFError

    from .responses import wants_json

    @app.errorhandler(404)
    def _handle_404(e):
        if wants_json():
            return jsonify({"error": "Not found."}), 404
        return e.get_response()

    @app.errorhandler(405)
    def _handle_405(e):
        if wants_json():
            return jsonify({"error": "Method not allowed."}), 405
        return e.get_response()

    @app.errorhandler(500)
    def _handle_500(e):
        if wants_json():
            return jsonify({"error": "Internal server error."}), 500
        return "Internal Server Error", 500

    @app.errorhandler(CSRFError)
    def _handle_csrf_error(e):
        if wants_json():
            return jsonify({"error": e.description}), 400
        if not current_user.is_authenticated:
            # An idle session outlived PERMANENT_SESSION_LIFETIME, taking the
            # server-side CSRF token with it, so a form submitted from a stale
            # page (most visibly Logout) died on a raw 400. The user is
            # effectively logged out already — treat it as a session expiry.
            flash("Your session has expired. Please log in again.", "warning")
            return redirect(url_for("auth.login"))
        # Logged in but the submitted token is stale/invalid (e.g. a form
        # rendered before an app restart rotated SECRET_KEY): let the user
        # retry from a fresh page. Referrer is only honoured same-host —
        # Referrer-Policy: same-origin doesn't bind an attacker's own page.
        flash(
            "The form's security token was missing or expired — please try again.",
            "warning",
        )
        ref = request.referrer
        if ref:
            parts = urlsplit(ref)
            if not parts.netloc or parts.netloc == request.host:
                return redirect(ref)
        return redirect(url_for("dashboard.index"))


def _configure_session(app):
    """Set session cookie security flags."""

    @app.before_request
    def make_session_permanent():
        session.permanent = True


def _setup_rate_limiting(app):
    """Set up optional rate limiting if Flask-Limiter is installed and enabled."""
    if not app.config.get("RATE_LIMIT_ENABLED"):
        app.limiter = None
        return

    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=[app.config.get("RATE_LIMIT_DEFAULT", "60/minute")],
            storage_uri="memory://",
        )
        app.limiter = limiter
    except ImportError:
        print("WARNING: RATE_LIMIT_ENABLED is true but Flask-Limiter is not installed. "
              "Install it with: pip install Flask-Limiter", file=sys.stderr)
        app.limiter = None


def _migrate_schema():
    """Add new columns to existing SQLite tables (ALTER TABLE)."""
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)

    # Migrate users table
    if "users" in inspector.get_table_names():
        columns = {col["name"] for col in inspector.get_columns("users")}
        if "role" not in columns:
            # D2: default the new column to least-privilege so an upgrade from a
            # pre-role schema does not blanket-grant admin to every existing
            # user; then promote the configured ADMIN_USERNAME so an admin still
            # exists. (On a fresh DB the column exists already and this is skipped.)
            db.session.execute(text(
                "ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'csr_requester'"
            ))
            db.session.execute(
                text("UPDATE users SET role = 'admin' WHERE username = :u"),
                {"u": current_app.config.get("ADMIN_USERNAME", "admin")},
            )
        if "is_active_user" not in columns:
            db.session.execute(text(
                "ALTER TABLE users ADD COLUMN is_active_user BOOLEAN NOT NULL DEFAULT 1"
            ))
        if "auth_source" not in columns:
            db.session.execute(text(
                "ALTER TABLE users ADD COLUMN auth_source VARCHAR(10) NOT NULL DEFAULT 'local'"
            ))
        if "failed_login_count" not in columns:  # D1
            db.session.execute(text(
                "ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0"
            ))
        if "locked_until" not in columns:
            db.session.execute(text(
                "ALTER TABLE users ADD COLUMN locked_until DATETIME"
            ))
        if "must_change_password" not in columns:
            db.session.execute(text(
                "ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0"
            ))

    # Migrate certificate_authorities table
    if "certificate_authorities" in inspector.get_table_names():
        columns = {col["name"] for col in inspector.get_columns("certificate_authorities")}
        if "crl_pem" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN crl_pem TEXT"
            ))
        if "is_revoked" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN is_revoked BOOLEAN NOT NULL DEFAULT 0"
            ))
        if "revoked_at" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN revoked_at DATETIME"
            ))
        if "revocation_reason" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN revocation_reason VARCHAR(50)"
            ))
        # A1 key-backend columns (existing CAs are software-backed)
        if "key_backend" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN key_backend VARCHAR(20) NOT NULL DEFAULT 'software'"
            ))
        if "key_label" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN key_label VARCHAR(200)"
            ))

    # Migrate certificates table
    if "certificates" in inspector.get_table_names():
        columns = {col["name"] for col in inspector.get_columns("certificates")}
        if "requested_by" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificates ADD COLUMN requested_by INTEGER REFERENCES users(id)"
            ))

    # Migrate certificate_signing_requests table
    if "certificate_signing_requests" in inspector.get_table_names():
        columns = {col["name"] for col in inspector.get_columns("certificate_signing_requests")}
        if "created_by" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_signing_requests ADD COLUMN created_by INTEGER REFERENCES users(id)"
            ))
        if "signed_by" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_signing_requests ADD COLUMN signed_by INTEGER REFERENCES users(id)"
            ))

    # Migrate csr_user role to csr_requester
    if "users" in inspector.get_table_names():
        db.session.execute(text(
            "UPDATE users SET role = 'csr_requester' WHERE role = 'csr_user'"
        ))

    db.session.commit()


def _create_default_admin(app):
    from sqlalchemy.exc import IntegrityError
    from .models.user import User

    if User.query.count() != 0:
        return
    password = app.config["ADMIN_PASSWORD"]
    # Reject the insecure default only here, where the seed would actually
    # become the first admin's password (skipped under testing/debug, matching
    # _check_security). Because this runs once — only when no user exists —
    # ADMIN_PASSWORD can be dropped from .env after the first admin is created.
    if (password == Config._INSECURE_ADMIN_PASSWORD
            and not app.config.get("TESTING") and not app.debug):
        print("FATAL: creating the initial admin, but ADMIN_PASSWORD is the "
              "insecure default 'admin'. Set a strong ADMIN_PASSWORD.", file=sys.stderr)
        sys.exit(1)
    admin = User(username=app.config["ADMIN_USERNAME"], role="admin")
    admin.set_password(password)
    # The ADMIN_PASSWORD env is a bootstrap seed — force a change on first login
    # so it cannot silently become the permanent admin password.
    admin.must_change_password = True
    db.session.add(admin)
    try:
        db.session.commit()
    except IntegrityError:
        # D5: another gunicorn worker seeded the admin concurrently — the unique
        # username constraint makes the race safe; just roll back. (ADMIN_PASSWORD
        # only seeds the first boot; rotate it via the UI afterwards.)
        db.session.rollback()
