import os
from datetime import timedelta


def _read_secret(name, default=None):
    """Read a secret from `{name}_FILE` (Docker/systemd secret) if set,
    otherwise the `{name}` env var, otherwise `default`.

    The file convention keeps high-value secrets (MASTER_PASSPHRASE,
    SECRET_KEY) out of the process environment — so they don't appear in
    `docker inspect`, `/proc/<pid>/environ`, or the compose `.env`.
    """
    path = os.environ.get(f"{name}_FILE")
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    return os.environ.get(name, default)


class Config:
    SECRET_KEY = _read_secret("SECRET_KEY", "dev-secret-key")
    MASTER_PASSPHRASE = _read_secret("MASTER_PASSPHRASE", "dev-passphrase")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///cert-manager.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = _read_secret("ADMIN_PASSWORD", "admin")
    # C4: hostname baked into the OCSP/CRL URLs of issued certs. These URLs are
    # PERMANENT, so in production pin this to your real hostname. While left at
    # the default, the hostname is auto-detected from the request Host header
    # (convenient for a self-hosted LAN, but a client-controlled value) — pin it
    # to stop trusting the Host header.
    SERVER_NAME_FOR_OCSP = os.environ.get("SERVER_NAME_FOR_OCSP", "localhost:5000")

    # Cap request bodies to blunt memory-exhaustion DoS (C2). OCSP/CRL/import
    # payloads are all small; 1 MB is generous.
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH_BYTES") or str(1024 * 1024))

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Secure-by-default (L1): cookies are only sent over HTTPS. The reference
    # docker-compose runs plain HTTP and sets this false explicitly; put a TLS
    # proxy in front and leave it true in production.
    SESSION_COOKIE_SECURE = (os.environ.get("SESSION_COOKIE_SECURE") or "true").lower() == "true"

    # Number of trusted reverse-proxy hops (G2). 0 = app is directly exposed,
    # use remote_addr as-is (do NOT trust X-Forwarded-For). Set to 1 when
    # behind a single TLS-terminating proxy so audit/rate-limit see real IPs.
    TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT") or "0")

    # Issuance policy limits (B4). not_after is always additionally clamped to
    # the issuing CA's own not_after in the services.
    MAX_CERT_VALIDITY_DAYS = int(os.environ.get("MAX_CERT_VALIDITY_DAYS") or "825")
    MAX_CA_VALIDITY_DAYS = int(os.environ.get("MAX_CA_VALIDITY_DAYS") or "7305")
    # Minimum RSA key size accepted anywhere keys are generated/signed (B5).
    MIN_RSA_KEY_SIZE = int(os.environ.get("MIN_RSA_KEY_SIZE") or "2048")

    # Cache the decrypted CA signing key in memory for this many seconds so an
    # unauthenticated OCSP flood doesn't run 600k-PBKDF2 per request (C1).
    # 0 disables the cache (decrypt every request).
    OCSP_KEY_CACHE_TTL_SECONDS = int(os.environ.get("OCSP_KEY_CACHE_TTL_SECONDS") or "300")

    # A1: default backend for NEW CA signing keys. "software" (Fernet-encrypted,
    # today's behaviour) or "softhsm" (key held in a PKCS#11 token). Existing CAs
    # keep whatever backend they were created with, per-CA.
    KEY_BACKEND = os.environ.get("KEY_BACKEND", "software")
    # PKCS#11 / SoftHSM settings (only used when a CA is HSM-backed). The user
    # PIN is a secret and follows the _FILE convention like MASTER_PASSPHRASE.
    PKCS11_MODULE = os.environ.get(
        "PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"
    )
    PKCS11_TOKEN_LABEL = os.environ.get("PKCS11_TOKEN_LABEL", "cert-manager")
    PKCS11_USER_PIN = _read_secret("PKCS11_USER_PIN", None)
    PKCS11_SO_PIN = _read_secret("PKCS11_SO_PIN", None)

    OCSP_URL_SCHEME = os.environ.get("OCSP_URL_SCHEME", "http")
    PERMANENT_SESSION_LIFETIME = timedelta(
        # CORE-5: `or` fallback so a set-but-empty value (compose passes unset
        # vars as "") doesn't crash startup with int("").
        minutes=int(os.environ.get("SESSION_LIFETIME_MINUTES") or "30")
    )

    # DoS-1: per-IP rate limiting is ON by default (requires Flask-Limiter, now a
    # pinned dependency). Bounds the unauthenticated Basic-Auth / OCSP flood.
    # Set false to disable.
    RATE_LIMIT_ENABLED = (os.environ.get("RATE_LIMIT_ENABLED") or "true").lower() == "true"
    RATE_LIMIT_DEFAULT = os.environ.get("RATE_LIMIT_DEFAULT") or "60/minute"
    # D1: lock a local account after this many consecutive failed logins, for
    # this many minutes (applies to session login and Basic Auth). 0 disables.
    LOGIN_LOCKOUT_THRESHOLD = int(os.environ.get("LOGIN_LOCKOUT_THRESHOLD") or "5")
    LOGIN_LOCKOUT_MINUTES = int(os.environ.get("LOGIN_LOCKOUT_MINUTES") or "15")

    # Minimum length enforced when a user sets a new password via the
    # change-password page (incl. the forced first-login change).
    MIN_PASSWORD_LENGTH = int(os.environ.get("MIN_PASSWORD_LENGTH") or "12")

    # A certificate/CA is flagged "expiring soon" this many days before its
    # notAfter (dashboard counts, list/detail badges, JSON API, `flask certs`).
    CERT_EXPIRY_WARNING_DAYS = int(os.environ.get("CERT_EXPIRY_WARNING_DAYS") or "30")

    # "Newer release available?" check shown in the footer. On by default; set
    # UPDATE_CHECK_ENABLED=false for a hardened / air-gapped CA that must make no
    # outbound call. When on, the latest GitHub release tag is fetched at most
    # once per interval (server-side, cached, non-blocking) and compared to the
    # running version.
    UPDATE_CHECK_ENABLED = os.environ.get("UPDATE_CHECK_ENABLED", "true").lower() == "true"
    UPDATE_CHECK_REPO = os.environ.get("UPDATE_CHECK_REPO") or "guidorugo/cert-manager"
    UPDATE_CHECK_INTERVAL_SECONDS = int(os.environ.get("UPDATE_CHECK_INTERVAL_SECONDS") or "21600")
    UPDATE_CHECK_TIMEOUT_SECONDS = int(os.environ.get("UPDATE_CHECK_TIMEOUT_SECONDS") or "4")

    BASIC_AUTH_ENABLED = os.environ.get("BASIC_AUTH_ENABLED", "true").lower() == "true"
    BASIC_AUTH_REALM = os.environ.get("BASIC_AUTH_REALM", "cert-manager")
    # Verified Basic Auth credentials are cached in memory for this many
    # seconds to avoid an LDAP bind / password-hash check per request (0 = off)
    BASIC_AUTH_CACHE_TTL_SECONDS = int(os.environ.get("BASIC_AUTH_CACHE_TTL_SECONDS") or "60")

    # LDAP authentication (optional). docker-compose passes unset variables
    # as empty strings, so vars with non-empty defaults use `or` fallbacks:
    # empty must behave exactly like unset.
    LDAP_ENABLED = os.environ.get("LDAP_ENABLED", "false").lower() == "true"
    LDAP_SERVER_URI = os.environ.get("LDAP_SERVER_URI", "")
    LDAP_USE_STARTTLS = os.environ.get("LDAP_USE_STARTTLS", "false").lower() == "true"
    LDAP_TLS_VERIFY = (os.environ.get("LDAP_TLS_VERIFY") or "true").lower() == "true"
    # E3: startup refuses cleartext ldap:// (no ldaps://, no StartTLS) unless this
    # is explicitly set true.
    LDAP_ALLOW_PLAINTEXT = os.environ.get("LDAP_ALLOW_PLAINTEXT", "false").lower() == "true"
    LDAP_CA_CERT_FILE = os.environ.get("LDAP_CA_CERT_FILE", "")
    LDAP_USER_DN_TEMPLATE = os.environ.get("LDAP_USER_DN_TEMPLATE", "")
    LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "")
    LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "")
    LDAP_USER_SEARCH_BASE = os.environ.get("LDAP_USER_SEARCH_BASE", "")
    LDAP_USER_FILTER = os.environ.get("LDAP_USER_FILTER") or "(uid={username})"
    LDAP_ADMIN_GROUP_DN = os.environ.get("LDAP_ADMIN_GROUP_DN", "")
    LDAP_REQUESTER_GROUP_DN = os.environ.get("LDAP_REQUESTER_GROUP_DN", "")
    LDAP_GROUP_MEMBER_ATTR = os.environ.get("LDAP_GROUP_MEMBER_ATTR") or "memberOf"
    LDAP_TIMEOUT_SECONDS = int(os.environ.get("LDAP_TIMEOUT_SECONDS") or "5")

    _INSECURE_SECRET_KEY = "dev-secret-key"
    _INSECURE_PASSPHRASE = "dev-passphrase"
    _INSECURE_ADMIN_PASSWORD = "admin"
