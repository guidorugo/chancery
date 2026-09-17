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
    # The DB filename keeps the pre-rename "cert-manager" name: changing it
    # would silently start an empty database on existing deployments.
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
    # Maximum RSA key size accepted for generation and in CSRs (G7-1): keygen
    # cost grows steeply with size and a 16384-bit request pins a worker.
    MAX_RSA_KEY_SIZE = int(os.environ.get("MAX_RSA_KEY_SIZE") or "8192")
    # Certificate profiles (F1). When true, every issuance must name a profile
    # (legacy requests without one are refused instead of falling back to
    # the unrestricted `custom` profile).
    PROFILES_REQUIRE_SELECTION = os.environ.get("PROFILES_REQUIRE_SELECTION", "false").lower() == "true"

    # Cache the decrypted CA signing key in memory for this many seconds so an
    # unauthenticated OCSP flood doesn't run 600k-PBKDF2 per request (C1).
    # 0 disables the cache (decrypt every request).
    OCSP_KEY_CACHE_TTL_SECONDS = int(os.environ.get("OCSP_KEY_CACHE_TTL_SECONDS") or "300")

    # PKI-2: cache the SIGNED OCSP response per (CA, serial, status) for this
    # many seconds so an unauthenticated flood doesn't re-sign on every request.
    # Status is part of the cache key and read fresh, so a revoked cert is never
    # answered GOOD from cache. 0 disables.
    OCSP_RESPONSE_CACHE_TTL_SECONDS = int(os.environ.get("OCSP_RESPONSE_CACHE_TTL_SECONDS") or "60")

    # F7 (2.24.0): sign OCSP responses with a short-lived delegated responder
    # certificate (EKU OCSPSigning, id-pkix-ocsp-nocheck) issued by the CA,
    # instead of the CA key itself. The CA key is then used once per
    # OCSP_RESPONDER_VALIDITY_DAYS; the scheduler renews responders
    # OCSP_RESPONDER_RENEW_BEFORE_DAYS before expiry. Default off until 3.0
    # (the responder ID of every CA changes when it flips).
    OCSP_DELEGATED_RESPONDER = (os.environ.get("OCSP_DELEGATED_RESPONDER") or "false").lower() == "true"
    OCSP_RESPONDER_VALIDITY_DAYS = int(os.environ.get("OCSP_RESPONDER_VALIDITY_DAYS") or "30")
    OCSP_RESPONDER_RENEW_BEFORE_DAYS = int(os.environ.get("OCSP_RESPONDER_RENEW_BEFORE_DAYS") or "7")

    # PKI-1: validity window stamped into a generated CRL (nextUpdate = now +
    # this many days). Raise it to reduce how often CRLs expire; cron
    # `flask crl refresh` to keep published CRLs fresh.
    CRL_VALIDITY_DAYS = int(os.environ.get("CRL_VALIDITY_DAYS") or "7")
    # Background scheduler (2.17.0, F8): refreshes CRLs before they expire.
    # One thread per gunicorn worker, a DB lease makes exactly one run the
    # jobs; started only under the entrypoint (CHANCERY_RUN_SCHEDULER=1).
    SCHEDULER_ENABLED = (os.environ.get("SCHEDULER_ENABLED") or "true").lower() == "true"
    SCHEDULER_TICK_SECONDS = int(os.environ.get("SCHEDULER_TICK_SECONDS") or "60")
    # A CRL is regenerated once it expires within this many days.
    CRL_REFRESH_BEFORE_DAYS = int(os.environ.get("CRL_REFRESH_BEFORE_DAYS") or "2")
    # Relying parties poll CRL/OCSP far more often than humans use the UI (G8-4).
    PUBLIC_RATE_LIMIT = os.environ.get("PUBLIC_RATE_LIMIT") or "600/minute"

    # F6 (2.21.0, G5-3): the digest used when signing certificates, CRLs, OCSP
    # responses and generated CSRs. "legacy" = SHA-256 for every RSA/EC key
    # (pre-2.21 behaviour, still the default until 3.0); "match-curve" = P-256
    # → SHA-256, P-384 → SHA-384, P-521 → SHA-512 as the CA/Browser Forum and
    # RFC 5759 profiles expect, and RSA_SIGNATURE_HASH for RSA keys. Ed25519/
    # Ed448 never take a separate digest. Existing certificates are untouched;
    # the setting applies to new signatures only.
    SIGNATURE_HASH_POLICY = (os.environ.get("SIGNATURE_HASH_POLICY") or "legacy").strip().lower()
    RSA_SIGNATURE_HASH = (os.environ.get("RSA_SIGNATURE_HASH") or "sha256").strip().lower()

    # A1: default backend for NEW CA signing keys. "software" (Fernet-encrypted,
    # today's behaviour) or "softhsm" (key held in a PKCS#11 token). Existing CAs
    # keep whatever backend they were created with, per-CA.
    KEY_BACKEND = os.environ.get("KEY_BACKEND", "software")
    # PKCS#11 / SoftHSM settings (only used when a CA is HSM-backed). The user
    # PIN is a secret and follows the _FILE convention like MASTER_PASSPHRASE.
    PKCS11_MODULE = os.environ.get(
        "PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"
    )
    # Keeps the pre-rename "cert-manager" label: an existing SoftHSM token
    # cannot be relabeled without re-init, which destroys non-extractable keys.
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
    UPDATE_CHECK_REPO = os.environ.get("UPDATE_CHECK_REPO") or "guidorugo/chancery"
    UPDATE_CHECK_INTERVAL_SECONDS = int(os.environ.get("UPDATE_CHECK_INTERVAL_SECONDS") or "21600")
    UPDATE_CHECK_TIMEOUT_SECONDS = int(os.environ.get("UPDATE_CHECK_TIMEOUT_SECONDS") or "4")

    # Prometheus /metrics endpoint (2.7.0). Opt-in and OFF by default (404 until
    # enabled). When enabled, a dedicated bearer token (see `flask metrics-token`)
    # is REQUIRED unless METRICS_ALLOW_UNAUTHENTICATED is set for an isolated
    # network. METRICS_INCLUDE_CA_DETAILS adds a `chancery_ca_info` metric
    # exposing CA names / subject CNs / key details — off by default, so the
    # default output is opaque ca_id + aggregate counts only.
    METRICS_ENABLED = os.environ.get("METRICS_ENABLED", "false").lower() == "true"
    METRICS_ALLOW_UNAUTHENTICATED = os.environ.get("METRICS_ALLOW_UNAUTHENTICATED", "false").lower() == "true"
    METRICS_INCLUDE_CA_DETAILS = os.environ.get("METRICS_INCLUDE_CA_DETAILS", "false").lower() == "true"

    BASIC_AUTH_ENABLED = os.environ.get("BASIC_AUTH_ENABLED", "true").lower() == "true"
    # F12 (2.26.0): scoped API tokens (`Authorization: Bearer chy_api_…`); the
    # longest lifetime an operator may give a token.
    API_TOKEN_MAX_DAYS = int(os.environ.get("API_TOKEN_MAX_DAYS") or "365")
    # F13 (2.27.0): force every admin to enrol a TOTP second factor on next login
    # (kept as an alias); 2.28.0: REQUIRE_2FA=off|admins|all is the real switch.
    REQUIRE_2FA_FOR_ADMINS = (os.environ.get("REQUIRE_2FA_FOR_ADMINS") or "false").lower() == "true"
    REQUIRE_2FA = (os.environ.get("REQUIRE_2FA") or "off").lower()
    TOTP_ISSUER = os.environ.get("TOTP_ISSUER") or "Chancery"
    # F14 (3.2.0): ACME server. Off by default; per-CA switches on the CA page.
    ACME_ENABLED = (os.environ.get("ACME_ENABLED") or "false").lower() == "true"
    ACME_BASE_URL = os.environ.get("ACME_BASE_URL") or None
    ACME_RATE_LIMIT = os.environ.get("ACME_RATE_LIMIT") or "300/minute"
    ACME_HTTP01_PORT = int(os.environ.get("ACME_HTTP01_PORT") or "80")
    ACME_HTTP01_TIMEOUT_SECONDS = int(os.environ.get("ACME_HTTP01_TIMEOUT_SECONDS") or "10")
    ACME_VALIDATION_ALLOW_LOOPBACK = (os.environ.get("ACME_VALIDATION_ALLOW_LOOPBACK") or "false").lower() == "true"
    ACME_VALIDATION_CONNECT_HOST = os.environ.get("ACME_VALIDATION_CONNECT_HOST") or None   # tests only
    ACME_ORDER_LIFETIME_HOURS = int(os.environ.get("ACME_ORDER_LIFETIME_HOURS") or "168")
    ACME_NONCE_LIFETIME_MINUTES = int(os.environ.get("ACME_NONCE_LIFETIME_MINUTES") or "60")
    ACME_DEFAULT_VALIDITY_DAYS = int(os.environ.get("ACME_DEFAULT_VALIDITY_DAYS") or "90")
    ACME_MAX_IDENTIFIERS = int(os.environ.get("ACME_MAX_IDENTIFIERS") or "100")
    # F16 (3.3.0): audit-log integrity and retention.
    AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS") or "0")     # 0 = keep everything
    AUDIT_ARCHIVE_DIR = os.environ.get("AUDIT_ARCHIVE_DIR") or None                 # default: <db dir>/audit-archive
    AUDIT_SEAL_GRACE_SECONDS = int(os.environ.get("AUDIT_SEAL_GRACE_SECONDS") or "5")
    BASIC_AUTH_REALM = os.environ.get("BASIC_AUTH_REALM", "chancery")
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

    # Dual control (2.10.0). When the flag is on AND the instance is genuinely
    # multi-user (another active account besides ADMIN_USERNAME, or LDAP in
    # effect), no single admin can both request and approve issuance: direct
    # certificate creation is disabled, a CSR's creator cannot sign it, and a
    # new CA needs approval by a different admin. The literal ADMIN_USERNAME
    # account is exempt from all three (break-glass — e.g. an LDAP outage must
    # not block issuance). See app/services/dual_control_service.py.
    DUAL_CONTROL_ENABLED = os.environ.get("DUAL_CONTROL_ENABLED", "false").lower() == "true"

    # Webhook notifications (2.10.0). Selected audit actions are POSTed as
    # JSON to WEBHOOK_URL (fire-and-forget background thread, fail-silent).
    # Settings saved in the admin UI (Preferences → Webhooks) override all of
    # these. WEBHOOK_EVENTS is a CSV of audit action names; "" = none,
    # "all"/"*" = every action. WEBHOOK_SECRET signs the body (HMAC-SHA256,
    # X-Chancery-Signature header).
    WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "false").lower() == "true"
    WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
    WEBHOOK_SECRET = _read_secret("WEBHOOK_SECRET", "")
    WEBHOOK_EVENTS = os.environ.get("WEBHOOK_EVENTS", "")
    WEBHOOK_TIMEOUT_SECONDS = int(os.environ.get("WEBHOOK_TIMEOUT_SECONDS") or "5")

    _INSECURE_SECRET_KEY = "dev-secret-key"
    _INSECURE_PASSPHRASE = "dev-passphrase"
    _INSECURE_ADMIN_PASSWORD = "admin"
