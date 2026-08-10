from flask import g, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()

login_manager.login_view = "auth.login"
login_manager.login_message_category = "warning"


class ConditionalCSRFProtect(CSRFProtect):
    """CSRFProtect subclass that skips CSRF validation for Basic Auth requests.

    API-3: the skip is withheld when the browser marks the request as
    cross-site (Sec-Fetch-Site: cross-site) — otherwise a victim's browser-cached
    Basic-Auth credentials could ride a cross-site form POST past CSRF. Non-browser
    clients (curl/scripts) send no Sec-Fetch-Site header and are unaffected.
    """

    # Accept and forward any arguments so the signature stays compatible with
    # Flask-WTF's internal calls (1.3.0 added apply_exemptions=True).
    def protect(self, *args, **kwargs):
        if getattr(g, "basic_auth_used", False) and not _is_cross_site_request():
            return
        return super().protect(*args, **kwargs)


def _is_cross_site_request():
    return (request.headers.get("Sec-Fetch-Site") or "").lower() == "cross-site"


csrf = ConditionalCSRFProtect()
