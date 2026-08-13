"""DB-backed LDAP configuration (admin UI) with env-var fallback.

Precedence: when an LdapSettings row exists, it is the effective LDAP
configuration; otherwise the LDAP_* environment variables (app.config) apply.
The row is validated at save time with the same rules the startup guard
applies to the env config, so an invalid directory setup can never be stored.

The effective config is cached on flask.g for the request; a test run can
inject a candidate (unsaved) config via g._ldap_cfg_override so the whole
ldap_service code path can be exercised before committing anything.
"""
from flask import current_app, g

from ..extensions import db
from ..models.ldap_settings import LdapSettings
from . import crypto_utils

# Keys mirrored 1:1 between app.config and the DB row. LDAP_CA_CERT_PEM is
# DB-only (the env config points at a file via LDAP_CA_CERT_FILE instead).
CONFIG_KEYS = [
    "LDAP_ENABLED",
    "LDAP_SERVER_URI",
    "LDAP_USE_STARTTLS",
    "LDAP_TLS_VERIFY",
    "LDAP_ALLOW_PLAINTEXT",
    "LDAP_CA_CERT_FILE",
    "LDAP_CA_CERT_PEM",
    "LDAP_USER_DN_TEMPLATE",
    "LDAP_BIND_DN",
    "LDAP_BIND_PASSWORD",
    "LDAP_USER_SEARCH_BASE",
    "LDAP_USER_FILTER",
    "LDAP_ADMIN_GROUP_DN",
    "LDAP_REQUESTER_GROUP_DN",
    "LDAP_GROUP_MEMBER_ATTR",
    "LDAP_TIMEOUT_SECONDS",
]


def get_row():
    return db.session.get(LdapSettings, 1)


def _row_to_config(row):
    password = ""
    if row.bind_password_enc:
        password = crypto_utils.decrypt_secret(
            row.bind_password_enc, current_app.config["MASTER_PASSPHRASE"]
        )
    return {
        "LDAP_ENABLED": row.enabled,
        "LDAP_SERVER_URI": row.server_uri,
        "LDAP_USE_STARTTLS": row.use_starttls,
        "LDAP_TLS_VERIFY": row.tls_verify,
        "LDAP_ALLOW_PLAINTEXT": row.allow_plaintext,
        "LDAP_CA_CERT_FILE": "",
        "LDAP_CA_CERT_PEM": row.ca_cert_pem,
        "LDAP_USER_DN_TEMPLATE": row.user_dn_template,
        "LDAP_BIND_DN": row.bind_dn,
        "LDAP_BIND_PASSWORD": password,
        "LDAP_USER_SEARCH_BASE": row.user_search_base,
        "LDAP_USER_FILTER": row.user_filter,
        "LDAP_ADMIN_GROUP_DN": row.admin_group_dn,
        "LDAP_REQUESTER_GROUP_DN": row.requester_group_dn,
        "LDAP_GROUP_MEMBER_ATTR": row.group_member_attr,
        "LDAP_TIMEOUT_SECONDS": row.timeout_seconds,
    }


def _env_config():
    cfg = {k: current_app.config.get(k) for k in CONFIG_KEYS if k != "LDAP_CA_CERT_PEM"}
    cfg["LDAP_CA_CERT_PEM"] = ""
    return cfg


def effective_config():
    """The LDAP config in effect: test override > DB row > environment."""
    override = g.get("_ldap_cfg_override")
    if override is not None:
        return override
    cached = g.get("_ldap_cfg_cache")
    if cached is not None:
        return cached
    row = get_row()
    cfg = _row_to_config(row) if row is not None else _env_config()
    g._ldap_cfg_cache = cfg
    return cfg


def config_source():
    """'db' when the admin-saved row is in effect, else 'env'."""
    return "db" if get_row() is not None else "env"


def validate(cfg):
    """Same rules as the startup guard, returned as a list instead of exiting."""
    errors = []
    if not cfg["LDAP_ENABLED"]:
        return errors

    if not cfg["LDAP_SERVER_URI"]:
        errors.append("Server URI is required when LDAP is enabled.")
    elif not cfg["LDAP_ALLOW_PLAINTEXT"]:
        uris = [u.strip() for u in cfg["LDAP_SERVER_URI"].split(",") if u.strip()]
        plaintext = [u for u in uris
                     if u.lower().startswith("ldap://") and not cfg["LDAP_USE_STARTTLS"]]
        if plaintext:
            errors.append(
                "LDAP over cleartext is refused: " + ", ".join(plaintext)
                + ". Use ldaps://, enable StartTLS, or explicitly allow plaintext."
            )

    template = cfg["LDAP_USER_DN_TEMPLATE"]
    search_base = cfg["LDAP_USER_SEARCH_BASE"]
    if template and search_base:
        errors.append("Set either a user DN template (direct bind) or a "
                      "search base (search+bind), not both.")
    if not template and not search_base:
        errors.append("Set a user DN template (direct bind) or a search base "
                      "(search+bind).")
    if template and "{username}" not in template:
        errors.append("The user DN template must contain a {username} placeholder.")
    if search_base:
        if "{username}" not in (cfg["LDAP_USER_FILTER"] or ""):
            errors.append("The user filter must contain a {username} placeholder.")
        if not cfg["LDAP_BIND_DN"]:
            errors.append("Search+bind mode requires a service account bind DN.")

    try:
        if int(cfg["LDAP_TIMEOUT_SECONDS"]) < 1:
            errors.append("Timeout must be at least 1 second.")
    except (TypeError, ValueError):
        errors.append("Timeout must be a number of seconds.")

    return errors


def save(cfg, updated_by=None):
    """Persist a validated config dict as the single settings row.

    An empty LDAP_BIND_PASSWORD keeps the currently stored password (the form
    field is write-only); the caller commits (with its audit entry).
    """
    row = get_row()
    if row is None:
        row = LdapSettings(id=1)
        db.session.add(row)

    row.enabled = cfg["LDAP_ENABLED"]
    row.server_uri = cfg["LDAP_SERVER_URI"]
    row.use_starttls = cfg["LDAP_USE_STARTTLS"]
    row.tls_verify = cfg["LDAP_TLS_VERIFY"]
    row.allow_plaintext = cfg["LDAP_ALLOW_PLAINTEXT"]
    row.ca_cert_pem = cfg["LDAP_CA_CERT_PEM"]
    row.user_dn_template = cfg["LDAP_USER_DN_TEMPLATE"]
    row.bind_dn = cfg["LDAP_BIND_DN"]
    row.user_search_base = cfg["LDAP_USER_SEARCH_BASE"]
    row.user_filter = cfg["LDAP_USER_FILTER"]
    row.admin_group_dn = cfg["LDAP_ADMIN_GROUP_DN"]
    row.requester_group_dn = cfg["LDAP_REQUESTER_GROUP_DN"]
    row.group_member_attr = cfg["LDAP_GROUP_MEMBER_ATTR"]
    row.timeout_seconds = int(cfg["LDAP_TIMEOUT_SECONDS"])
    row.updated_by = updated_by
    if cfg["LDAP_BIND_PASSWORD"]:
        row.bind_password_enc = crypto_utils.encrypt_secret(
            cfg["LDAP_BIND_PASSWORD"], current_app.config["MASTER_PASSPHRASE"]
        )
    g.pop("_ldap_cfg_cache", None)
    return row


def reset():
    """Delete the row, reverting the app to the environment configuration."""
    row = get_row()
    if row is not None:
        db.session.delete(row)
    g.pop("_ldap_cfg_cache", None)


def stored_bind_password():
    """The currently stored bind password ('' if none) — for test runs where
    the write-only form field was left blank."""
    row = get_row()
    if row is None:
        return current_app.config.get("LDAP_BIND_PASSWORD", "")
    if not row.bind_password_enc:
        return ""
    return crypto_utils.decrypt_secret(
        row.bind_password_enc, current_app.config["MASTER_PASSPHRASE"]
    )
