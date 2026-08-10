from functools import wraps

from flask import flash, jsonify, redirect, url_for
from flask_login import current_user, login_required

from .responses import wants_json


def role_required(*roles):
    """Decorator that requires the user to have one of the specified roles."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.role not in roles:
                # API-4: any JSON client (Basic Auth or Accept: application/json)
                # gets a JSON 403; browsers get the flash + redirect.
                if wants_json():
                    return jsonify({"error": "You do not have permission to access this resource."}), 403
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for("dashboard.index"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """Decorator that requires the user to be an admin."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            if wants_json():
                return jsonify({"error": "You do not have permission to access this resource."}), 403
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for("dashboard.index"))
        return f(*args, **kwargs)
    return decorated_function
