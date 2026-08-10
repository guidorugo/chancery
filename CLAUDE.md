# Certificate Manager - Development Guide

## Project Overview
Python/Flask web application for managing an X.509 Certificate Authority (CA).
Handles CA creation, certificate signing/revocation, CSR management, CRL generation, and OCSP responses.

## Tech Stack
- Python 3.13, Flask 3.1.3, SQLAlchemy 2.0.51, cryptography 50.0.0
- Bootstrap 5 (CDN), Gunicorn, SQLite

## Project Structure
- `.github/workflows/` - GitHub Actions CI (Docker build & push to GHCR)
- `app/` - Flask application (factory pattern in `__init__.py`)
- `app/models/` - SQLAlchemy models (User, CA, Certificate, CSR, AuditLog)
- `app/services/` - Business logic (crypto_utils, ca_service, cert_service, csr_service, crl_service, ocsp_service, audit_service)
- `app/routes/` - Flask blueprints (auth, dashboard, ca, certificates, csr, users, public)
- `app/decorators.py` - `role_required()`, `admin_required` access control decorators
- `app/templates/` - Jinja2 templates with Bootstrap 5
- `tests/` - pytest test suite

## Build & Run

### Docker (production)
```bash
./scripts/init-secrets.sh   # generates secrets/master_passphrase, .env (SECRET_KEY, ADMIN_PASSWORD), SoftHSM PINs
docker compose up --build
```
A fresh clone must run `scripts/init-secrets.sh` first — the compose bind-mounts `secrets/master_passphrase` (gitignored) and the app refuses to start with placeholder `SECRET_KEY`/`ADMIN_PASSWORD`. The script is idempotent.

### Pre-built image (GHCR)
```bash
docker pull ghcr.io/guidorugo/cert-manager:latest
```
Or switch `docker-compose.yml` to use `image:` instead of `build:` (see commented line).

### Local development
```bash
pip install -r requirements.txt
flask --app "app:create_app()" run --debug
```

### Run tests
```bash
pip install pytest
python -m pytest tests/ -v
```

## CI/CD
- **GitHub Actions workflow**: `.github/workflows/docker-publish.yml`
- **Triggers**: PRs → tests only. Push to `master` → tests + image build for validation (**not published**). `v*` tags → tests + build + **publish** (semver tags + `latest`). Publishing is gated to release tags so a merge never auto-pushes an image.
- **Registry**: `ghcr.io/guidorugo/cert-manager` — uses `GITHUB_TOKEN`, no extra secrets needed.
- **`.dockerignore`**: Excludes `venv/`, `tests/`, `.env`, `.git/`, etc. from the Docker build context.
- **Supply-chain hardening** (findings H2/I1/I2/J1/J2): Actions are **SHA-pinned** (comment = version); base image is **digest-pinned** in the Dockerfile; deps are **hash-locked** (`--require-hashes`); CI runs **pip-audit** (weekly cron too, blocking) and a **Trivy image scan** (report-only, on release tags); release images are **cosign-signed** (keyless OIDC) with **SLSA provenance + SBOM**. Pins are bumped by **Dependabot** (`.github/dependabot.yml`).
- **Dependencies**: `requirements.in` is the human-edited source; `requirements.txt` is the generated hash-locked lockfile. After editing `requirements.in`, regenerate: `docker run --rm -v "$PWD:/w" -w /w python:3.13-slim sh -c "pip install pip-tools && pip-compile --generate-hashes --output-file=requirements.txt requirements.in"`.

## Key Design Decisions
- **Private key encryption**: Fernet + PBKDF2-HMAC-SHA256 (600k iterations). Salt stored with ciphertext.
- **Key backends (A1, SoftHSM/PKCS#11)**: A CA's signing key lives behind a `KeyBackend` (`app/services/keybackend/`). Default `software` = today's Fernet-encrypted key; opt-in `softhsm` = key held in a PKCS#11 token, never in Python memory. Selected per-CA (`CertificateAuthority.key_backend`/`key_label` columns); `KEY_BACKEND` sets the default for new CAs, and the create form offers HSM per-CA when `hsm_available()`. Three-state model guards: `has_signing_key` (issue/CRL/OCSP/sub-CA — true for software+HSM), `is_exportable` (key/PKCS#12 export — software only), `signing_capable()` query. pyca can't sign with a PKCS#11 key, so the HSM backend builds the TBS with a same-algorithm throwaway key and swaps in the token's signature via `asn1crypto` (cert/CRL are byte-identical to software for RSA; OCSP is assembled directly since pyca refuses signer≠responder, reusing a throwaway pyca request's CertID). RSA uses `CKM_SHA256_RSA_PKCS`; EC signs the SHA-256 digest with raw `CKM_ECDSA` (SoftHSM lacks `CKM_ECDSA_SHA256`). Cross-backend intermediates work (parent's backend signs the child). Migrate existing keys one-way with `flask keys migrate-to-hsm`; HSM keys are `CKA_EXTRACTABLE=false` so export is refused. **SoftHSM is enabled by default (v2.3.0)**: `docker-compose.yml` wires the PKCS#11 config + the two PIN secrets, `scripts/init-secrets.sh` generates the PINs, and the entrypoint inits the token on first boot — so HSM is offered per-CA out of the box (`KEY_BACKEND` still defaults to `software`, so new CAs stay exportable unless set to `softhsm`). A local `docker-compose.override.yml` is therefore no longer needed. Deployment stays single-container (softhsm2 in the image). Differential tests in `tests/test_softhsm.py` gate byte-parity (skip cleanly without SoftHSM; CI installs it).
- **Master passphrase**: From `MASTER_PASSPHRASE` env var. Used for all key encrypt/decrypt.
- **OCSP**: Built-in responder at `/public/ocsp/<ca_id>`. Certificates include AIA extension.
- **CRL Distribution Points**: Auto-populated in certificates using `{scheme}://{server}/public/crl/{ca_id}.crl`. Added via `crl_dp_url` parameter in `cert_service.create_certificate()` and `cert_service.sign_csr()`. The CRL DP field in the create/sign forms is **editable** — users can override the auto-generated URL per-certificate. When `SERVER_NAME_FOR_OCSP` is at its default `localhost:5000`, the hostname is **auto-detected from `request.host`**. A warning banner appears in Advanced Settings when the detected hostname contains `localhost`.
- **Certificate profiles**: Both certificate creation and CSR signing forms have a collapsible Advanced Settings section with profile presets (Web Server, Client Auth, Email/S-MIME, Code Signing, Custom) that configure Key Usage and Extended Key Usage checkboxes. Default profile (Web Server) matches previous hardcoded defaults for backward compatibility.
- **Dark theme**: Bootstrap 5.3 `data-bs-theme`-based. An inline head script applies the saved theme (`localStorage` key `theme`) or the OS `prefers-color-scheme` before first paint; `.theme-toggle` buttons (navbar when logged in, floating top-right otherwise) switch and persist it. Use adaptive utility classes (`bg-body-tertiary`, `text-body-secondary`) in templates — never light-only ones like `bg-light`/`text-muted`.
- **Version & update check**: `app/_version.py` `__version__` is the single source of truth (bump on release; `APP_VERSION` env overrides the displayed value). A context processor renders it as footer small-print. The update check (`UPDATE_CHECK_ENABLED`, **on by default**; set false for an air-gapped CA, `app/services/update_service.py`) fetches the latest GitHub release **server-side, cached (`UPDATE_CHECK_INTERVAL_SECONDS`, default 6h), non-blocking (background refresh), fail-silent**, and shows a footer "Update available" badge when behind — no client-side fetch, so no CSP relaxation needed.
- **Certificate bundle download**: `/certificates/<id>/download?format=pem|der|fullchain|chain` (owner/admin, audited, GET). `fullchain` = leaf → intermediates → root; `chain` = the issuing chain without the leaf. Both are key-free PEM built by `cert_service.export_fullchain_pem` / `export_chain_pem` (reuse `ca_service.get_ca_chain`).
- **Health endpoint**: `GET /health` (`app/routes/health.py`, own blueprint, no auth, exempt from the first-login password-change guard **and** rate limiting) does a cheap `SELECT 1` → `200 {"status":"ok"}` / `503`; JSON only, no version/secrets. Wired to the Docker `healthcheck`.
- **Expiration tracking**: `Certificate`/`CertificateAuthority` expose `days_until_expiry` + `expiry_status` (`valid|expiring_soon|expired`, threshold `CERT_EXPIRY_WARNING_DAYS`, default 30) — surfaced in `to_dict()`, list/detail badges, and dashboard `cert_expiring_soon`/`cert_expired` counts (HTML + JSON). CLI: `flask certs expiring [--days N] [--json]`. Issuance stores the cert's real (CA-clamped) `not_after` (finding PKI-3); `flask certs recompute-expiry` backfills legacy rows.
- **CRL freshness & OCSP cache**: generated CRLs stamp `nextUpdate` = now + `CRL_VALIDITY_DAYS` (default 7); cron `flask crl refresh [--all]` regenerates stale (or all) CRLs. OCSP responses are cached per `(ca_id, serial, is_revoked, hash-alg)` for `OCSP_RESPONSE_CACHE_TTL_SECONDS` (default 60, 0 disables) — status is **in the key**, so a revoked cert is never served GOOD from cache.
- **CSP script nonce (TMPL-1)**: a per-request nonce (`g.csp_nonce`, exposed to templates as `csp_nonce`) authorises inline `<script>`; `script-src` has **no `'unsafe-inline'`** (all inline `on*` handlers were moved to `addEventListener`). `style-src` still allows `'unsafe-inline'`. Add `nonce="{{ csp_nonce }}"` to any new inline `<script>`.
- **CLI commands** (registered in `app/__init__.py`, defined in `app/cli.py`): `flask keys migrate-to-hsm [--ca-id N] [--dry-run]`, `flask certs expiring`/`recompute-expiry`, `flask users unlock <username>`, `flask crl refresh [--all]`.
- **Public endpoints**: CRL download and CA cert download require no auth.
- **Database**: SQLite, stored in `./data/` (Docker volume).
- **LDAP login (Phase 1)**: Optional LDAP auth for the session login via `auth_service.authenticate()` — local accounts first (break-glass admin works with LDAP down), then LDAP when `LDAP_ENABLED=true`. Two modes (exactly one must be configured): direct bind (`LDAP_USER_DN_TEMPLATE`) or search+bind (`LDAP_BIND_DN` + `LDAP_USER_SEARCH_BASE`). Group DNs map to roles (`LDAP_ADMIN_GROUP_DN` → admin, `LDAP_REQUESTER_GROUP_DN` → csr_requester; the requester group is a required-membership gate when set). LDAP users are auto-provisioned with `auth_source='ldap'` and the unusable-password sentinel (`!`), role re-synced each login, local deactivation wins. Empty passwords rejected before bind (anonymous-bind pitfall); filter/DN inputs escaped. Basic Auth works for LDAP users too via `auth_service.authenticate_basic()` with a per-process HMAC credential cache (`BASIC_AUTH_CACHE_TTL_SECONDS`, default 60s, 0 disables); cache hits skip the bind but re-read the User row so deactivation applies immediately; directory outage → HTTP 503 for LDAP-backed Basic Auth.

- **CA import**: `/ca/create` Upload tab. PEM (single cert or full chain bundle) via `ca_service.import_ca()` — encrypted keys supported (`key_passphrase`), key optional (certificate-only import for offline roots). PKCS#12 via `ca_service.import_pkcs12()`. Chain bundles auto-import parents certificate-only with unique auto-names, deduplicated by serial, signature-verified (`verify_directly_issued_by`). Keyless CAs store the empty-bytes sentinel in `private_key_enc` (no schema change); `CertificateAuthority.has_private_key` / `signing_capable()` gate issuance, CSR signing, CRL generation, new intermediates, and issuing dropdowns; OCSP returns an unsigned UNAUTHORIZED response for them.
- **CA export**: `/ca/<id>/download?format=pem|chain|key|pkcs12` (admin-only). `pem`/`chain` are non-secret and allow GET; `key`/`pkcs12` are **POST-only** (private-key material must not appear in a GET URL/log — the pkcs12 `password` is read from `request.form`, never `request.values`). `key` serves the decrypted private key PEM (audit: `download_ca_private_key`); `pkcs12` requires a non-empty `password` form field and bundles cert+key+parent chain (audit: `export_ca_pkcs12`), importable back via the PKCS#12 import. key/pkcs12 refuse certificate-only CAs.

## Roles & Access Control
- **admin**: Full access to all routes (CAs, certificates, CSR signing/rejection, user management, audit log).
- **csr_requester**: Can create/upload CSRs and view their own CSRs and certificates. Cannot access CA management, user management, or certificate creation/revocation.
- Routes are protected by `@admin_required` or `@login_required` decorators in `app/decorators.py`.
- Ownership enforced: `csr_requester` can only see CSRs where `created_by == current_user.id` and certificates where `requested_by == current_user.id`.
- Templates conditionally hide admin-only links/buttons using `{% if current_user.is_admin %}`.

## Audit Logging
- `app/services/audit_service.py` provides `log_action(action, target_type, target_id, details)`.
- Does NOT call `db.session.commit()` — caller commits as part of its transaction.
- All sensitive actions are logged: login/logout, CA/certificate/CSR operations, user management.
- Audit log viewable at `/users/audit-log` (admin only, paginated).

## Security Hardening
- **Insecure default rejection**: App refuses to start in non-debug, non-testing mode if `SECRET_KEY` or `MASTER_PASSPHRASE` are set to their insecure defaults (`sys.exit(1)`). `ADMIN_PASSWORD` is checked the same way **only in `_create_default_admin`, when it would actually seed the first admin** — so once an admin exists it is unused and can be removed from `.env`.
- **Forced first-login password change**: `_create_default_admin` sets `User.must_change_password` on the seeded admin; a `before_request` guard (in `app/__init__.py`) redirects a flagged **session** user to `/auth/change-password` until they rotate it (Basic Auth + public endpoints exempt; logout reachable). Existing users default to `False`, so upgrades don't force anyone. Self-service change-password (`MIN_PASSWORD_LENGTH`, default 12) is available to any local user via a navbar link.
- **Session cookies**: HttpOnly, SameSite=Lax. `SESSION_COOKIE_SECURE` configurable (default: false, set to true in production).
- **Session timeout**: Configurable via `SESSION_LIFETIME_MINUTES` (default 30).
- **Security headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a **nonce-based `Content-Security-Policy`** (`script-src` has no `'unsafe-inline'` — see the CSP nonce note above), `Referrer-Policy: no-referrer`, and `Strict-Transport-Security` on all responses.
- **Open redirect protection**: Login `next` parameter validated to reject absolute/external URLs.
- **Timing attack mitigation**: Dummy hash computation on failed login for nonexistent users.
- **SRI**: Bootstrap CDN resources include `integrity` and `crossorigin` attributes.
- **Content-Disposition sanitization**: Filenames in download headers are sanitized to prevent header injection.
- **OCSP URL scheme**: Configurable via `OCSP_URL_SCHEME` (default: `http`, set to `https` in production).
- **Schema migration**: `_migrate_schema()` in `app/__init__.py` handles adding new columns to existing SQLite tables via ALTER TABLE.
- **Last-admin guards**: Cannot deactivate or demote the last active admin user.
- **Non-root container (H1)**: `entrypoint.sh` starts as root only to `chown` the bind-mounted `/app/data`, then `setpriv`-drops to the `app` user (**uid 1000**) which runs `entrypoint-app.sh` (token init, migration, gunicorn). Compose adds `no-new-privileges` + `cap_drop: [ALL]` (only `CHOWN`/`SETUID`/`SETGID` added back). uid 1000 must be able to read the Docker secret files (bind-mounted with host ownership).

## HTTP Basic Auth
- **Alternative to session auth**: Enables programmatic access via `curl -u user:pass`, scripts, and automation.
- **Stateless**: No session cookie created — each request authenticates independently.
- **CSRF bypass**: CSRF validation is skipped only for requests with **valid** Basic Auth credentials.
- **JSON error responses**: Basic Auth clients receive JSON `{"error": "..."}` for 401/403 instead of HTML redirects.
- **Audit logged**: Both success (`basic_auth_success`) and failure (`basic_auth_failed`) are logged.
- **Config**: `BASIC_AUTH_ENABLED` (default: true), `BASIC_AUTH_REALM` (default: "cert-manager").
- **HTTPS required in production**: Basic Auth sends credentials Base64-encoded (not encrypted).
- **Usage**: `curl -u admin:password https://host/ca/` or `curl -H "Authorization: Basic $(echo -n user:pass | base64)" https://host/ca/`.

## Environment Variables
- `SECRET_KEY` - Flask secret key
- `MASTER_PASSPHRASE` - Master passphrase for key encryption
- `DATABASE_URL` - SQLAlchemy database URI
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` - Seed the **first** admin only (when no users exist); a change is forced on first login, after which `ADMIN_PASSWORD` is unused and removable from `.env`
- `MIN_PASSWORD_LENGTH` - Minimum length for a new password on the change-password page (default: 12)
- `SERVER_NAME_FOR_OCSP` - Hostname for OCSP/CRL URLs (default: localhost:5000). When at default, auto-detected from `request.host`
- `SESSION_LIFETIME_MINUTES` - Session timeout in minutes (default: 30)
- `RATE_LIMIT_ENABLED` - Per-IP rate limiting (default: **true**; Flask-Limiter is now a pinned dependency). Initialised **before** the Basic-Auth hook so a flood is 429'd before the password-hash/audit write; `/health` is exempt. Set false to disable.
- `RATE_LIMIT_DEFAULT` - Default rate limit when enabled (default: 60/minute)
- `CERT_EXPIRY_WARNING_DAYS` - Days-before-notAfter to flag a cert/CA "expiring soon" (default: 30) — dashboard counts, badges, JSON API, `flask certs expiring`
- `CRL_VALIDITY_DAYS` - nextUpdate window stamped into generated CRLs (default: 7); cron `flask crl refresh` to keep them fresh
- `OCSP_RESPONSE_CACHE_TTL_SECONDS` - Cache signed OCSP responses per (CA, serial, status) this long (default: 60, 0 disables); status is in the key, so a revoked cert is never served GOOD from cache
- `BASIC_AUTH_ENABLED` - Enable HTTP Basic Auth (default: true)
- `BASIC_AUTH_REALM` - Basic Auth realm name (default: cert-manager)
- `BASIC_AUTH_CACHE_TTL_SECONDS` - In-memory cache TTL for verified Basic Auth credentials (default: 60, 0 disables)
- `OCSP_URL_SCHEME` - URL scheme for OCSP AIA URLs in certificates (default: http, use https in production)
- `SESSION_COOKIE_SECURE` - Send session cookie only over HTTPS (default: **true**; the HTTP reference compose overrides to false)
- `TRUSTED_PROXY_COUNT` - Trusted reverse-proxy hop count for ProxyFix (default: 0 = directly exposed; do not trust XFF)
- `MAX_CONTENT_LENGTH_BYTES` - Max request body size (default: 1048576)
- `MAX_CERT_VALIDITY_DAYS` / `MAX_CA_VALIDITY_DAYS` - Issuance validity caps (default: 825 / 7305); certs are also clamped to the issuing CA's expiry
- `MIN_RSA_KEY_SIZE` - Minimum RSA key size accepted (default: 2048)
- `OCSP_KEY_CACHE_TTL_SECONDS` - In-memory TTL for the decrypted CA signing key used by OCSP (default: 300, 0 disables)
- `UPDATE_CHECK_ENABLED` - Footer "Update available" badge vs the latest GitHub release (default: **true**; set false for an air-gapped CA to make no outbound call)
- `UPDATE_CHECK_REPO` / `UPDATE_CHECK_INTERVAL_SECONDS` - Repo to check (default `guidorugo/cert-manager`) and cache TTL (default 21600 = 6h)
- `KEY_BACKEND` - Default signing-key backend for new CAs: `software` (default) or `softhsm`. SoftHSM is wired up by default in `docker-compose.yml`, so HSM is offered per-CA even while new CAs stay `software`
- `PKCS11_MODULE` - PKCS#11 library path (default: `/usr/lib/softhsm/libsofthsm2.so`)
- `PKCS11_TOKEN_LABEL` - Token label (default: `cert-manager`)
- `PKCS11_USER_PIN` / `PKCS11_SO_PIN` - Token PINs (support the `_FILE` secret convention)
- `SOFTHSM2_CONF` - SoftHSM config path; when set, the entrypoint creates the token dir and inits the token
- `MASTER_PASSPHRASE_FILE` / `SECRET_KEY_FILE` / `ADMIN_PASSWORD_FILE` - Read the secret from a file (Docker/systemd secret) instead of the env var
- `LDAP_ENABLED` - Enable LDAP login (default: false)
- `LDAP_SERVER_URI` - Directory URI(s), comma-separated for failover (e.g. `ldaps://dc01:636`)
- `LDAP_USE_STARTTLS` / `LDAP_TLS_VERIFY` / `LDAP_CA_CERT_FILE` - TLS options (verify defaults to true)
- `LDAP_USER_DN_TEMPLATE` - Direct-bind DN template with `{username}` placeholder
- `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` / `LDAP_USER_SEARCH_BASE` / `LDAP_USER_FILTER` - Search+bind mode
- `LDAP_ADMIN_GROUP_DN` / `LDAP_REQUESTER_GROUP_DN` - Group-to-role mapping DNs
- `LDAP_GROUP_MEMBER_ATTR` - Group membership attribute (default: memberOf)
- `LDAP_TIMEOUT_SECONDS` - Directory connect/receive timeout (default: 5)
