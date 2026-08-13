"""LDAP directory authentication.

Pure LDAP logic: verifies credentials against the directory and returns the
user's DN and group memberships. No database access — user provisioning and
role mapping live in auth_service.

Two modes, selected by configuration:
- Direct bind: LDAP_USER_DN_TEMPLATE builds the user's DN from the username
  and binds as that DN. Groups are then read from the user's own entry.
- Search + bind: a service account (LDAP_BIND_DN) searches
  LDAP_USER_SEARCH_BASE with LDAP_USER_FILTER for the user's entry, then a
  second connection binds as the found DN to verify the password.
"""
import logging
import ssl
from dataclasses import dataclass

import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

from . import ldap_settings_service

logger = logging.getLogger(__name__)


def _cfg(key):
    """Effective LDAP config value (admin-saved DB row wins over env vars)."""
    return ldap_settings_service.effective_config()[key]


class LdapUnavailableError(Exception):
    """The directory could not be reached (or the service bind failed)."""


@dataclass
class LdapResult:
    dn: str
    groups: list  # group DNs, lowercased for comparison


def authenticate_ldap(username, password):
    """Verify credentials against the LDAP directory.

    Returns an LdapResult on success, None for bad credentials or unknown
    users. Raises LdapUnavailableError when the directory is unreachable or
    the service account cannot bind, so callers can distinguish "LDAP down"
    from "wrong password".

    An empty (or whitespace-only) password is rejected before any bind is
    attempted: LDAP servers treat a simple bind with an empty password as an
    anonymous bind, which would otherwise "succeed" for any username.
    """
    if not username or not password or not password.strip():
        return None

    server = _build_server()

    template = _cfg("LDAP_USER_DN_TEMPLATE")
    if template:
        user_dn = template.format(username=escape_rdn(username))
        conn = _bind_as_user(server, user_dn, password)
        if conn is None:
            return None
        groups = _read_own_groups(conn, user_dn)
        conn.unbind()
        return LdapResult(dn=user_dn, groups=groups)

    user_dn, groups = _search_user(server, username)
    if user_dn is None:
        return None
    conn = _bind_as_user(server, user_dn, password)
    if conn is None:
        return None
    conn.unbind()
    return LdapResult(dn=user_dn, groups=groups)


def _build_server():
    """Build a Server (or failover ServerPool) from LDAP_SERVER_URI."""
    uris = [u.strip() for u in _cfg("LDAP_SERVER_URI").split(",") if u.strip()]
    timeout = _cfg("LDAP_TIMEOUT_SECONDS")

    tls = None
    uses_tls = any(u.lower().startswith("ldaps://") for u in uris)
    if uses_tls or _cfg("LDAP_USE_STARTTLS"):
        validate = ssl.CERT_REQUIRED if _cfg("LDAP_TLS_VERIFY") else ssl.CERT_NONE
        tls = ldap3.Tls(
            validate=validate,
            ca_certs_file=_cfg("LDAP_CA_CERT_FILE") or None,
            ca_certs_data=_cfg("LDAP_CA_CERT_PEM") or None,
        )

    servers = [
        ldap3.Server(uri, tls=tls, connect_timeout=timeout, get_info=ldap3.NONE)
        for uri in uris
    ]
    if len(servers) == 1:
        return servers[0]
    return ldap3.ServerPool(servers, ldap3.FIRST, active=1, exhaust=True)


def _auto_bind_mode():
    if _cfg("LDAP_USE_STARTTLS"):
        return ldap3.AUTO_BIND_TLS_BEFORE_BIND
    return ldap3.AUTO_BIND_NO_TLS


def _connect(server, user_dn, password):
    return ldap3.Connection(
        server,
        user=user_dn,
        password=password,
        auto_bind=_auto_bind_mode(),
        receive_timeout=_cfg("LDAP_TIMEOUT_SECONDS"),
        read_only=True,
        auto_referrals=False,
    )


def _bind_as_user(server, user_dn, password):
    """Bind as the end user. Returns the connection, or None for bad credentials."""
    try:
        return _connect(server, user_dn, password)
    except LDAPBindError:
        return None
    except LDAPException as exc:
        logger.warning("LDAP unavailable during user bind: %s", exc)
        raise LdapUnavailableError(str(exc)) from exc


def _search_user(server, username):
    """Service-account search for the user's DN and groups (search+bind mode).

    Returns (dn, groups) or (None, []). A failed service bind or search is an
    operational error — raised as LdapUnavailableError, never treated as bad
    end-user credentials.
    """
    search_base = _cfg("LDAP_USER_SEARCH_BASE")
    search_filter = _cfg("LDAP_USER_FILTER").format(
        username=escape_filter_chars(username)
    )
    group_attr = _cfg("LDAP_GROUP_MEMBER_ATTR")

    try:
        conn = _connect(
            server,
            _cfg("LDAP_BIND_DN"),
            _cfg("LDAP_BIND_PASSWORD"),
        )
        conn.search(
            search_base,
            search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=[group_attr],
        )
        entries = list(conn.entries)
        conn.unbind()
    except LDAPException as exc:
        logger.warning("LDAP unavailable during user search: %s", exc)
        raise LdapUnavailableError(str(exc)) from exc

    if len(entries) != 1:
        if len(entries) > 1:
            logger.warning(
                "LDAP search for %r matched %d entries; rejecting as ambiguous",
                username, len(entries),
            )
        return None, []

    entry = entries[0]
    return entry.entry_dn, _entry_groups(entry, group_attr)


def _read_own_groups(conn, user_dn):
    """Read the user's group attribute from their own entry (direct-bind mode)."""
    group_attr = _cfg("LDAP_GROUP_MEMBER_ATTR")
    try:
        found = conn.search(
            user_dn,
            "(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=[group_attr],
        )
    except LDAPException as exc:
        logger.warning("Could not read %s for %s: %s", group_attr, user_dn, exc)
        return []
    if not found or not conn.entries:
        return []
    return _entry_groups(conn.entries[0], group_attr)


def _entry_groups(entry, group_attr):
    try:
        values = entry[group_attr].values
    except (KeyError, AttributeError):
        return []
    return [str(v).strip().lower() for v in (values or [])]


def test_config(candidate, test_username=None, test_password=None, role_mapper=None):
    """Live-check a candidate config without saving it (admin UI test button).

    The candidate dict is injected as the effective config for the duration of
    the call, so the exact production code path (server pool, TLS, bind mode,
    group read) is exercised. Returns {"ok": bool, "message": str, "detail":
    dict} and never raises — the caller renders the outcome in the UI.
    """
    from flask import g

    g._ldap_cfg_override = candidate
    try:
        if test_username and test_password:
            try:
                result = authenticate_ldap(test_username, test_password)
            except LdapUnavailableError as exc:
                return {"ok": False, "message": f"Directory unreachable: {exc}", "detail": {}}
            if result is None:
                return {"ok": False,
                        "message": "Connected, but the test credentials were rejected "
                                   "(bad password, unknown user, or filter mismatch).",
                        "detail": {}}
            detail = {"dn": result.dn, "groups": result.groups}
            if role_mapper is not None:
                # Map while the candidate config is still the effective one, so
                # the reported role reflects the group DNs in the form.
                role = role_mapper(result.groups)
                detail["role"] = role or "rejected (matches no mapped group)"
            return {"ok": True,
                    "message": f"Authenticated {test_username} successfully.",
                    "detail": detail}

        server = _build_server()
        if candidate["LDAP_USER_SEARCH_BASE"]:
            # Search+bind: verify the service bind and that the base resolves.
            conn = _connect(server, candidate["LDAP_BIND_DN"], candidate["LDAP_BIND_PASSWORD"])
            found = conn.search(candidate["LDAP_USER_SEARCH_BASE"], "(objectClass=*)",
                                search_scope=ldap3.BASE, attributes=["objectClass"])
            conn.unbind()
            if not found:
                return {"ok": False,
                        "message": "Service bind succeeded but the user search base "
                                   "was not found in the directory.", "detail": {}}
            return {"ok": True,
                    "message": "Service bind and search base check succeeded. "
                               "Add test credentials to verify a full user login.",
                    "detail": {}}

        # Direct bind: without test credentials only the transport can be
        # checked (TCP + TLS/StartTLS handshake).
        conn = ldap3.Connection(server, read_only=True)
        conn.open()
        if candidate["LDAP_USE_STARTTLS"]:
            conn.start_tls()
        conn.unbind()
        return {"ok": True,
                "message": "Server connection (and TLS handshake) succeeded. "
                           "Add test credentials to verify a full user login.",
                "detail": {}}
    except LDAPException as exc:
        return {"ok": False, "message": f"LDAP error: {exc}", "detail": {}}
    except OSError as exc:
        return {"ok": False, "message": f"Connection failed: {exc}", "detail": {}}
    finally:
        g.pop("_ldap_cfg_override", None)
