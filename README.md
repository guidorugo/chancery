# Chancery

A web-based X.509 Certificate Authority management application built with Python and Flask.

> **Formerly `cert-manager`** (renamed in 2.12.0, no relation to the Kubernetes project). Old GitHub URLs redirect; container images now publish to `ghcr.io/guidorugo/chancery`. Two on-disk identifiers deliberately keep the old name so existing deployments upgrade in place: the default SQLite filename (`cert-manager.db`) and the SoftHSM token label (`PKCS11_TOKEN_LABEL=cert-manager`).

## Features

- **CA Management**: Create root and intermediate Certificate Authorities with RSA or EC keys, or import existing ones — PEM (single certificate or full chain), PKCS#12 bundles, encrypted private keys, and certificate-only imports for offline roots — and export them back out (chain bundle, private key, password-protected PKCS#12)
- **Certificate Issuance**: Generate certificates with SANs, key usage, extended key usage, and CRL Distribution Points
- **Certificate Detail View**: Full certificate details including Key Usage, Extended Key Usage, subject DN fields, requester, issuer (who signed/created it), and SANs
- **Advanced Certificate Settings**: Collapsible UI with certificate profile presets (Web Server, Client Auth, Email/S-MIME, Code Signing), Key Usage and Extended Key Usage checkboxes, and editable CRL Distribution Points (auto-populated from hostname, user-overridable)
- **CSR Management**: Create or import Certificate Signing Requests, sign or reject them — the signing user is recorded and shown on the CSR and certificate
- **Revocation**: Revoke certificates with standard reasons, generate CRLs
- **OCSP Responder**: Built-in OCSP endpoint for real-time certificate status checks
- **Public Endpoints**: Unauthenticated access to CRL downloads and CA certificates
- **Monitoring**: `/health` liveness probe and an opt-in Prometheus `/metrics` endpoint (dedicated bearer token, minimal exposure)
- **Role-Based Access Control**: Admin and CSR User roles with enforced separation of duties
- **Audit Logging**: Every sensitive action logged with user, timestamp, IP, and details
- **User Management**: Admin UI for creating users, assigning roles, and managing accounts
- **HTTP Basic Auth**: Stateless API access via `curl -u user:pass` for scripts and automation, alongside session-based browser auth
- **Dark Theme**: Light/dark mode toggle with OS-preference default and per-browser persistence
- **Security**: Private keys encrypted at rest with Fernet (PBKDF2-derived key, 600k iterations), session hardening, insecure-default rejection
- **Minimal hardened image**: Alpine-based (~123 MB), digest-pinned, runs as non-root with all capabilities dropped; no `pip`, `bash`, or package manager extras in the runtime — scanned clean (0 known CVEs) at the v2.8.0 release
- **Forced first-login password change**: The bootstrap admin seeded from `ADMIN_PASSWORD` must set a new password before using the app, so the seed credential can't become permanent; self-service change-password for any local user
- **Hardware-backed keys (SoftHSM/PKCS#11)**: Enabled by default — CA signing keys can be held in a PKCS#11 token so they never enter application memory and cannot be exported; selectable per-CA (software stays the default backend), with a one-way migration for existing CAs and a drop-in path to a real hardware HSM
- **LDAP Login**: Optional LDAP/Active Directory authentication with group-to-role mapping and automatic user provisioning — configurable from the admin UI (Preferences → LDAP, with a live connection test) or via environment variables
- **Dual control (four-eyes)**: Opt-in mode (`DUAL_CONTROL_ENABLED`) where no single admin can both request and approve issuance — direct certificate creation is disabled in favour of the CSR flow, a CSR's creator cannot sign it, and a new CA must be approved by a different admin before it can issue anything; kicks in automatically once the instance is genuinely multi-user (or LDAP is enabled), with the bootstrap `admin` account exempt from all three restrictions as break-glass (so e.g. an LDAP outage can never block issuance)
- **Webhook notifications**: POST selected audit events (certificate issued/revoked, CSR signed, CA created/approved, logins, …) as JSON to any HTTP endpoint (e.g. an n8n workflow) — configurable from the admin UI (Preferences → Webhooks, with a test button) or via `WEBHOOK_*` environment variables; optional HMAC-SHA256 body signature, fire-and-forget delivery that never blocks a request
- **Version & update awareness**: The footer shows the running version; a cached, server-side check (on by default, disable for air-gapped deployments) flags in the footer when a newer GitHub release is available

## PKCS Standards

The application implements the core PKCS (Public-Key Cryptography Standards) used in CA operations:

| Standard | Role in Chancery |
|----------|----------------------|
| **PKCS #1** | RSA keys and PKCS#1 v1.5 signatures (`sha256WithRSAEncryption`) |
| **PKCS #5** | PBKDF2-HMAC-SHA256 key derivation (600k iterations) for private-key encryption at rest |
| **PKCS #8** | Private-key serialization format for stored and exported keys |
| **PKCS #9** | Attributes embedded in CSRs and PKCS#12 bundles |
| **PKCS #10** | Certificate Signing Requests — creation, upload, and signing |
| **PKCS #11** | Hardware token interface — the SoftHSM key backend (drop-in path to a real HSM) |
| **PKCS #12** | Password-protected import/export bundles for CAs and certificates |

Fun fact: no software can claim *all* fifteen PKCS standards — #2 and #4 were
withdrawn in the 1980s (merged into #1), and #13 (elliptic-curve cryptography)
and #14 (pseudo-random number generation) were never published; ECC and PRNG
standardization happened in ANSI X9 / SEC / NIST documents instead.

## Quick Start

### Docker (recommended)

```bash
# 1. Generate local secrets + .env (master passphrase, a strong SECRET_KEY, a
#    random admin password, and the SoftHSM token PINs). Safe to re-run — it
#    never overwrites existing values.
./scripts/init-secrets.sh

# 2. (Optional) review .env for other settings, then build and run
docker compose up --build
```

The script prints the generated admin password (also saved as `ADMIN_PASSWORD`
in `.env`). Open `http://localhost:5000` and log in as `admin` with that
password — the app **requires you to set a new password on first login**. After
that the admin's password lives only in the database, so `ADMIN_PASSWORD` is
unused and can be deleted from `.env` (it is re-read only if the database is
reset to zero users). The app also **refuses to start** with the shipped
placeholder credentials, so this bootstrap step is required — a bare
`docker compose up` on a fresh clone fails on the missing
`secrets/master_passphrase` mount.

> **Back up `secrets/master_passphrase`.** It encrypts every CA private key — if
> you lose it, the keys are unrecoverable. Keep the same value across restarts
> and any hosts that share the data volume.

### Pre-built Image (GHCR)

A pre-built image is published to GitHub Container Registry on each `v*` release tag — **cosign-signed** (keyless, via GitHub OIDC) with **SLSA provenance** and an **SBOM**.

```bash
# Pull the latest image
docker pull ghcr.io/guidorugo/chancery:latest

# Run with required environment variables
docker run -d \
  -p 5000:5000 \
  -v ./data:/app/data \
  -e SECRET_KEY=your-secret-key \
  -e MASTER_PASSPHRASE=your-passphrase \
  ghcr.io/guidorugo/chancery:latest
```

You can also use the pre-built image with docker compose by commenting out the `build` line and uncommenting the `image` line in `docker-compose.yml`.

**Verify a release image** (signature + provenance/SBOM):

```bash
# Verify the keyless cosign signature (signed by the release workflow).
# Signatures are stored in the legacy tag format, so any cosign version works.
cosign verify ghcr.io/guidorugo/chancery:2.12.0 \
  --certificate-identity-regexp 'https://github.com/guidorugo/chancery/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Inspect the SLSA provenance / SBOM (BuildKit in-toto attestations in the index)
docker buildx imagetools inspect ghcr.io/guidorugo/chancery:2.12.0 --format '{{ json .Provenance }}'
docker buildx imagetools inspect ghcr.io/guidorugo/chancery:2.12.0 --format '{{ json .SBOM }}'
```

### Local Development

```bash
pip install -r requirements.txt
export SECRET_KEY=dev-secret
export MASTER_PASSPHRASE=dev-passphrase
flask --app "app:create_app()" run --debug
```

## Updating

Your data (`./data` — SQLite DB, encrypted CA keys, SoftHSM token) and secrets (`./secrets/`) live in volumes and **survive an update**. **Schema changes apply automatically on startup** (idempotent `ALTER TABLE`), so upgrading is just: fetch the new version and restart. Back up first:

```bash
cp -a data data.bak && cp -a secrets secrets.bak
```

**Docker (built from source):**

```bash
git pull
docker compose up -d --build      # rebuild; schema auto-migrates on boot
```

**Pre-built image (GHCR)** — if `docker-compose.yml` uses `image:` instead of `build:`:

```bash
docker compose pull
docker compose up -d
```

The footer shows an **"Update available"** badge when a newer GitHub release exists (on by default; set `UPDATE_CHECK_ENABLED=false` to disable the outbound check). Check the [release notes](https://github.com/guidorugo/chancery/releases) for any **one-time commands** a version needs — e.g. after upgrading to **2.5.0**, correct the stored expiry on certificates issued by older versions:

```bash
docker compose exec app flask certs recompute-expiry
```

Similarly, after upgrading to **2.11.0**, populate the new signer/issuer fields on
pre-existing CSRs and certificates from the audit log (idempotent, optional):

```bash
docker compose exec app flask certs backfill-issuers --dry-run   # preview
docker compose exec app flask certs backfill-issuers
```

Upgrading to **2.6.0** raises the auto-generated SoftHSM token PINs to 32 characters for *new* deployments; existing tokens keep their current PINs. To rotate an existing deployment to the stronger length, follow the **SoftHSM PIN migration** guide in the [v2.6.0 release notes](https://github.com/guidorugo/chancery/releases/tag/v2.6.0) — the user PIN rotates in place; the SO PIN needs a freshly-initialised token when it holds non-extractable keys.

## Running behind TLS (production)

The app serves plain HTTP; **terminate TLS with a reverse proxy** (finding E1). A ready-to-use Caddy example is in `deploy/`:

```bash
# 1. Set your hostname (a LAN-only name? see deploy/Caddyfile -> `tls internal`)
echo "PUBLIC_HOSTNAME=ca.example.com" >> .env

# 2. Bring it up: Caddy terminates HTTPS on 443; the app no longer exposes 5000
docker compose -f docker-compose.yml -f deploy/docker-compose.tls.yml up -d --build
```

The overlay enables `SESSION_COOKIE_SECURE=true`, `OCSP_URL_SCHEME=https`, `TRUSTED_PROXY_COUNT=1`, and pins `SERVER_NAME_FOR_OCSP` to your hostname (so issued certs' OCSP/CRL URLs are correct — see C4).

**TLS certificate — three options in `deploy/Caddyfile`:**
- **Public DNS name** (default): Caddy auto-provisions a Let's Encrypt certificate.
- **LAN-only name**: uncomment `tls internal` for Caddy's self-signed CA.
- **Bring your own**: put `cert.pem` (full chain, leaf first) + `key.pem` (unencrypted) in `deploy/tls/` (gitignored), uncomment the `tls /etc/caddy/tls/cert.pem /etc/caddy/tls/key.pem` line in `deploy/Caddyfile` and the matching `./deploy/tls` volume in `deploy/docker-compose.tls.yml`, then recreate. You own renewals — replace the files and `docker compose -f docker-compose.yml -f deploy/docker-compose.tls.yml restart caddy`.

## Usage

### 1. Create a Root CA

Go to **CAs > Create CA**, fill in the subject details, choose key type (RSA 2048/4096 or EC 256/384), and set validity.

### 2. Issue a Certificate

Go to **Certificates > Create Certificate**, select the issuing CA, fill in subject and SANs. Expand **Advanced Settings** to choose a certificate profile (Web Server, Client Auth, Email/S-MIME, Code Signing) or manually configure Key Usage and Extended Key Usage. CRL Distribution Points are auto-populated based on the selected CA and can be manually overridden. The hostname is auto-detected from the browser request when `SERVER_NAME_FOR_OCSP` is not explicitly set.

### 3. Manage CSRs

Go to **CSRs > Create CSR** to generate or upload a CSR. Then sign it with a CA from the CSR detail page. The signing form also includes **Advanced Settings** for profile selection and extension customization.

### 4. Revoke & CRL

Revoke a certificate from its detail page. Generate a CRL from the CA detail page.

### 5. Public Endpoints

| Endpoint | Description |
|----------|-------------|
| `/public/ca/<id>.crt` | Download CA certificate (PEM) |
| `/public/crl/<id>.crl` | Download CRL (DER) |
| `/public/crl/<id>.pem` | Download CRL (PEM) |
| `/public/ocsp/<id>` | OCSP responder (POST, DER) |

### OCSP Testing

```bash
openssl ocsp \
  -issuer ca.pem \
  -cert cert.pem \
  -url http://localhost:5000/public/ocsp/1 \
  -resp_text
```

## Hardware-Backed Keys (SoftHSM / PKCS#11)

CA private keys are Fernet-encrypted files by default, but the **SoftHSM
PKCS#11 backend is enabled out of the box** so keys can instead live in a token
where they **never enter application memory** and are **non-exportable** — the
strongest protection for a trust anchor, and the same code path works with a
real hardware HSM later.

The Docker image bundles SoftHSM 2 (BSD-licensed), `docker-compose.yml` wires
up the PKCS#11 settings, and `scripts/init-secrets.sh` generates the two token
PINs (`secrets/pkcs11_user_pin`, `secrets/pkcs11_so_pin`); the entrypoint
initialises the token on first boot. So after the standard bootstrap step
nothing else is needed — the *Create CA* form simply offers HSM per-CA.

- **Per-CA choice**: with the token configured, the *Create CA* form shows a
  **Key Protection** selector (Software vs HSM). Leave `KEY_BACKEND=software`
  (default) to keep new CAs software-backed while still offering HSM per-CA, or
  set `KEY_BACKEND=softhsm` to make new CAs HSM-backed by default.
- **The CA detail page** shows the **Key Protection** row (Software / HSM) and
  hides the key/PKCS#12 export for HSM CAs (they cannot be exported).
- **Migrate existing CAs** into the token (one-way — back up any key you might
  need to export first; import a CA in software then migrate if you want it in
  the HSM):

  ```bash
  docker compose exec app flask keys migrate-to-hsm --dry-run   # preview
  docker compose exec app flask keys migrate-to-hsm             # migrate all
  docker compose exec app flask keys migrate-to-hsm --ca-id 3   # just one
  ```

## Subscriber keys & escrow

> **How private keys are handled.** *Create Certificate* generates the subscriber keypair **server-side** and **escrows** it — stored **encrypted at rest** (Fernet + PBKDF2-HMAC-SHA256, 600k iterations, per-record salt; never plaintext, not cached in memory) and re-downloadable. Convenient for server/TLS certificates you operate yourself.
>
> For **client-auth, S/MIME email, and code-signing** certificates — where the subscriber should be the *only* holder of the key — use **Sign CSR** instead: generate the key on the subscriber's side (ideally in their own token/HSM) and submit a CSR; the app signs it **without ever seeing the private key**.
>
> The **SoftHSM** backend protects the **CA signing key**, not subscriber/leaf keys, so it does not remove escrow — CSR-based issuance is the escrow-free path.

## API Reference

Chancery is a web application with form-based (HTML) endpoints. All authenticated routes use session cookies set at login. Public endpoints require no authentication.

### Authentication

#### HTTP Basic Auth (recommended for scripts/automation)

All authenticated endpoints support HTTP Basic Auth — no session or CSRF token needed:

```bash
# Simple access with Basic Auth
curl -u admin:admin http://localhost:5000/ca/

# POST requests work without CSRF tokens
curl -u admin:admin -X POST http://localhost:5000/ca/1/crl
```

Basic Auth works for local and LDAP accounts alike. To keep the per-request cost low, successfully verified credentials are cached in process memory for a short TTL (`BASIC_AUTH_CACHE_TTL_SECONDS`, default 60 seconds; set `0` to disable). A cache hit skips the LDAP bind / password-hash check but still re-reads the user record, so deactivations apply immediately.

#### JSON responses (content negotiation)

Data endpoints return **JSON** when the caller is an API client — it authenticated with **Basic Auth**, or sent **`Accept: application/json`** — and HTML otherwise, so the same URLs back the web UI and a JSON API.

- **Reads** — `GET /ca/`, `/ca/<id>`, `/certificates/`, `/certificates/<id>`, `/csr/`, `/csr/<id>`, `/users/`, `/users/audit-log`, `/` — return the resource(s) as JSON.
- **Writes** — `POST /ca/create`, `/ca/<id>/approve`, `/ca/<id>/revoke`, `/ca/<id>/crl`, `/certificates/create`, `/certificates/<id>/revoke`, `/csr/create`, `/csr/<id>/sign`, `/csr/<id>/reject` — take the same form fields and return the created/updated resource (`201`/`200`); validation and not-found errors return `{"error": "..."}` with a `4xx` status.

```bash
# Basic Auth implies JSON
curl -u admin:PASSWORD http://localhost:5000/ca/

# ...or force JSON with an Accept header
curl -u admin:PASSWORD -H "Accept: application/json" http://localhost:5000/certificates/1

# Create a CA — form fields in, JSON out
curl -u admin:PASSWORD -H "Accept: application/json" \
  -d "mode=generate&name=api-root&cn=API Root&key_type=EC&key_size=256&ca_type=root&validity_days=3650" \
  http://localhost:5000/ca/create
```

Request bodies stay form-encoded (`-d field=value`); only the *response* is negotiated. Downloads (`/ca/<id>/download`, `/public/...`) always return the certificate/CRL/PKCS#12 bytes, and secret fields (private keys, password hashes) are never included in JSON. User-management writes remain form-based (admin console).

#### Session Cookies (browser / legacy)

Alternatively, authenticate via session cookie:

```bash
# Login and save session cookie
curl -c cookies.txt -X POST http://localhost:5000/auth/login \
  -d "username=admin&password=admin"

# Use session cookie for subsequent requests
curl -b cookies.txt http://localhost:5000/ca/
```

### Roles

| Role | Access |
|------|--------|
| `admin` | Full access: CAs, certificates, CSR signing/rejection, user management, audit log |
| `csr_requester` | Create/upload CSRs, view own CSRs and certificates issued from them |

### Public Endpoints (no authentication)

These endpoints are designed for automated consumption by PKI clients, browsers, and OCSP validators.

| Method | Endpoint | Content-Type | Description |
|--------|----------|-------------|-------------|
| GET | `/public/ca/<ca_id>.crt` | `application/x-pem-file` | Download CA certificate (PEM) |
| GET | `/public/crl/<ca_id>.crl` | `application/pkix-crl` | Download CRL (DER) |
| GET | `/public/crl/<ca_id>.pem` | `application/x-pem-file` | Download CRL (PEM) |
| POST | `/public/ocsp/<ca_id>` | `application/ocsp-response` | OCSP responder (send DER-encoded OCSP request) |

```bash
# Download a CA certificate
curl -O http://localhost:5000/public/ca/1.crt

# Download a CRL
curl -O http://localhost:5000/public/crl/1.crl

# OCSP query with OpenSSL
openssl ocsp \
  -issuer ca.pem -cert cert.pem \
  -url http://localhost:5000/public/ocsp/1 \
  -resp_text
```

### Authenticated Endpoints

All authenticated endpoints support HTTP Basic Auth or session cookies (see [Authentication](#authentication) above). CSRF tokens are required for session-based POST requests but are not needed when using Basic Auth.

#### CA Management (admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ca/` | List all Certificate Authorities |
| GET, POST | `/ca/create` | Create or import a CA |
| POST | `/ca/detect-parent` | Detect parent CA for an imported certificate (JSON response) |
| GET | `/ca/<ca_id>` | View CA details |
| POST | `/ca/<ca_id>/crl` | Generate a new CRL |
| GET, POST | `/ca/<ca_id>/download` | Export CA. `pem`/`chain` via GET; `key`/`pkcs12` are **POST-only** (private-key material). `pkcs12` needs a `password` **form** field |

#### Certificate Management (admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/certificates/` | List all certificates |
| GET, POST | `/certificates/create` | Issue a new certificate |
| GET | `/certificates/<cert_id>` | View certificate details |
| GET, POST | `/certificates/<cert_id>/revoke` | Revoke a certificate |
| GET | `/certificates/<cert_id>/download` | Download certificate (`?format=pem\|der\|pkcs12`) |
| GET | `/certificates/<cert_id>/download-key` | Download private key (PEM) |

```bash
# Download a certificate in PEM format
curl -b cookies.txt -O http://localhost:5000/certificates/1/download?format=pem

# Download in DER format
curl -b cookies.txt -O http://localhost:5000/certificates/1/download?format=der

# Download as PKCS#12 bundle
curl -b cookies.txt -O "http://localhost:5000/certificates/1/download?format=pkcs12&password=changeit"

# Download private key
curl -b cookies.txt -O http://localhost:5000/certificates/1/download-key
```

#### CSR Management (all authenticated users)

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| GET | `/csr/` | Any | List CSRs (admin sees all, CSR users see own) |
| GET, POST | `/csr/create` | Any | Create or import a CSR |
| GET | `/csr/<csr_id>` | Any | View CSR details (CSR users can only view own) |
| GET, POST | `/csr/<csr_id>/sign` | Admin | Sign a pending CSR |
| POST | `/csr/<csr_id>/reject` | Admin | Reject a pending CSR |

#### User Management (admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users/` | List all users |
| GET, POST | `/users/create` | Create a new user |
| GET, POST | `/users/<user_id>/edit` | Change user role |
| POST | `/users/<user_id>/toggle-active` | Activate or deactivate a user |
| GET, POST | `/users/<user_id>/reset-password` | Reset a user's password |
| GET | `/users/audit-log` | View audit log (paginated, `?page=N`) |
| GET, POST | `/users/ldap` | View/save LDAP settings (POST `action=test` runs a live connection test) |
| POST | `/users/ldap/reset` | Remove saved LDAP settings (revert to env config) |
| GET, POST | `/users/webhooks` | View/save webhook notification settings (POST `action=test` sends a test event) |
| POST | `/users/webhooks/reset` | Remove saved webhook settings (revert to env config) |

#### Dashboard & Auth

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| GET | `/` | Any | Dashboard (role-conditional stats) |
| GET, POST | `/auth/login` | None | Login page |
| POST | `/auth/logout` | Any | Logout (POST-only, CSRF-protected) |

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Monitoring & Metrics

`GET /health` is an unauthenticated liveness probe (cheap `SELECT 1` → `200`/`503`, JSON only) wired to the Docker healthcheck.

`GET /metrics` exposes Prometheus metrics. It is **off by default** (returns `404`); enable with `METRICS_ENABLED=true`. When enabled it requires a **dedicated bearer token** — distinct from any user account, valid only for `/metrics`, with a required name and expiry, individually revocable, and stored only as a hash:

```bash
# The secret is printed ONCE — store it now.
docker compose exec app flask metrics-token create --name prometheus --expires-in-days 90
docker compose exec app flask metrics-token list
docker compose exec app flask metrics-token revoke prometheus
```

Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: chancery
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: cmt_xxxxxxxx_your_token_here
    static_configs:
      - targets: ["chancery.example.com:5000"]
```

Exposure is **minimal by default**: certificate/CA counts by state, per-CA expiry and **CRL `nextUpdate`** timestamps (keyed by opaque `ca_id`), CSR/user/audit gauges, and `chancery_build_info`. CA names, subject CNs, and key details are **not** exposed unless you set `METRICS_INCLUDE_CA_DETAILS=true` (adds `chancery_ca_info`). For an isolated network, `METRICS_ALLOW_UNAUTHENTICATED=true` skips the token. Authenticate scrapes with the **bearer token**, never HTTP Basic auth (a Basic credential is rejected, and would otherwise cost a password hash per scrape).

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-secret-key` | Flask session secret |
| `MASTER_PASSPHRASE` | `dev-passphrase` | Key encryption passphrase |
| `DATABASE_URL` | `sqlite:///cert-manager.db` | Database URI |
| `ADMIN_USERNAME` | `admin` | Default admin username |
| `ADMIN_PASSWORD` | `admin` | Seeds the **first** admin only (when no users exist); a change is forced on first login, after which it is unused and can be removed |
| `MIN_PASSWORD_LENGTH` | `12` | Minimum length when setting a new password on the change-password page |
| `SERVER_NAME_FOR_OCSP` | `localhost:5000` | Server hostname for OCSP/CRL URLs. When at default, auto-detected from request |
| `SESSION_LIFETIME_MINUTES` | `30` | Session timeout in minutes |
| `RATE_LIMIT_ENABLED` | `false` | Enable rate limiting (requires Flask-Limiter) |
| `RATE_LIMIT_DEFAULT` | `60/minute` | Default rate limit when enabled |
| `BASIC_AUTH_ENABLED` | `true` | Enable HTTP Basic Auth for programmatic access |
| `BASIC_AUTH_REALM` | `chancery` | Basic Auth realm name in `WWW-Authenticate` header |
| `BASIC_AUTH_CACHE_TTL_SECONDS` | `60` | In-memory cache TTL for verified Basic Auth credentials (`0` disables) |
| `OCSP_URL_SCHEME` | `http` | URL scheme for OCSP AIA URLs in certificates (`https` recommended for production) |
| `SESSION_COOKIE_SECURE` | `true` | Send session cookie only over HTTPS (the plain-HTTP reference compose overrides to `false`) |
| `TRUSTED_PROXY_COUNT` | `0` | Trusted reverse-proxy hops for `ProxyFix` (0 = directly exposed; set to 1 behind one TLS proxy) |
| `MAX_CONTENT_LENGTH_BYTES` | `1048576` | Maximum request body size |
| `MAX_CERT_VALIDITY_DAYS` | `825` | Cap on issued leaf-cert validity (also clamped to the CA's expiry) |
| `MAX_CA_VALIDITY_DAYS` | `7305` | Cap on issued CA validity |
| `MIN_RSA_KEY_SIZE` | `2048` | Minimum accepted RSA key size |
| `OCSP_KEY_CACHE_TTL_SECONDS` | `300` | In-memory TTL for the decrypted CA key used by OCSP (`0` disables) |
| `UPDATE_CHECK_ENABLED` | `true` | Show a footer "Update available" badge when a newer GitHub release exists (makes an outbound call; set `false` for an air-gapped CA) |
| `METRICS_ENABLED` | `false` | Expose the Prometheus `/metrics` endpoint (opt-in; returns 404 until enabled) |
| `METRICS_ALLOW_UNAUTHENTICATED` | `false` | Serve `/metrics` without a bearer token (isolated networks only) |
| `METRICS_INCLUDE_CA_DETAILS` | `false` | Add a `chancery_ca_info` metric with CA names/CNs/key details (default: opaque `ca_id` + counts only) |
| `UPDATE_CHECK_REPO` | `guidorugo/chancery` | Repository to check for the latest release |
| `UPDATE_CHECK_INTERVAL_SECONDS` | `21600` | Cache TTL for the update check (6h) |
| `MASTER_PASSPHRASE_FILE` / `SECRET_KEY_FILE` / `ADMIN_PASSWORD_FILE` | – | Read the secret from a file (Docker/systemd secret) instead of the env var |
| `DUAL_CONTROL_ENABLED` | `false` | Four-eyes issuance: once another active user besides `ADMIN_USERNAME` exists (or LDAP is enabled), direct cert creation is disabled, CSR creators cannot sign their own CSRs, and new CAs need approval by a different admin (`POST /ca/<id>/approve`). The bootstrap admin account is exempt |
| `WEBHOOK_ENABLED` | `false` | POST selected audit events as JSON to `WEBHOOK_URL`. Also configurable in the admin UI (Preferences → Webhooks) — settings saved there override all `WEBHOOK_*` variables until removed |
| `WEBHOOK_URL` | – | Webhook POST target (e.g. an n8n webhook trigger) |
| `WEBHOOK_SECRET` | – | Optional signing secret: requests carry `X-Chancery-Signature: sha256=<HMAC-SHA256 of the body>` (`_FILE` convention supported) |
| `WEBHOOK_EVENTS` | – | CSV of audit action names to notify on (e.g. `sign_csr,create_ca`); empty = none, `all` = every action |
| `WEBHOOK_TIMEOUT_SECONDS` | `5` | Delivery timeout for the background POST |
| `LDAP_ENABLED` | `false` | Enable LDAP authentication for the web login. Alternatively configure LDAP in the admin UI (Preferences → LDAP) — settings saved there override all `LDAP_*` variables until removed |
| `LDAP_SERVER_URI` | – | LDAP server URI(s), e.g. `ldaps://dc01:636` (comma-separated for failover) |
| `LDAP_USE_STARTTLS` | `false` | Upgrade `ldap://` connections with StartTLS |
| `LDAP_TLS_VERIFY` | `true` | Verify the directory's TLS certificate |
| `LDAP_CA_CERT_FILE` | – | CA bundle for verifying the directory's certificate |
| `LDAP_USER_DN_TEMPLATE` | – | Direct-bind DN template, e.g. `uid={username},ou=people,dc=example,dc=com` |
| `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` | – | Service account for search+bind mode |
| `LDAP_USER_SEARCH_BASE` | – | Search base for search+bind mode |
| `LDAP_USER_FILTER` | `(uid={username})` | User search filter (`(sAMAccountName={username})` for AD) |
| `LDAP_ADMIN_GROUP_DN` | – | Members of this group get the `admin` role |
| `LDAP_REQUESTER_GROUP_DN` | – | Members get `csr_requester`; when set, membership in one of the groups is required |
| `LDAP_GROUP_MEMBER_ATTR` | `memberOf` | Attribute holding the user's group DNs |
| `LDAP_TIMEOUT_SECONDS` | `5` | Connect/receive timeout for directory operations |

### LDAP Authentication

When `LDAP_ENABLED=true`, the web login checks the local database first (so the bootstrap admin always works, even with the directory down) and then falls back to LDAP. Directory users are auto-provisioned on first login with a role derived from group membership, re-synced on every login. Notes:

- Choose **one** mode: direct bind (`LDAP_USER_DN_TEMPLATE`) or search+bind (`LDAP_BIND_DN` + `LDAP_USER_SEARCH_BASE`). The app refuses to start with both or neither.
- Locally deactivating an LDAP user blocks them regardless of directory state.
- LDAP accounts have no local password: password reset is disabled for them. HTTP Basic Auth works for LDAP accounts too; if the directory is unreachable, LDAP-backed Basic Auth requests receive `503`.
- Empty passwords are rejected before any bind (prevents the LDAP anonymous-bind pitfall), and usernames are escaped against LDAP filter injection.
- The provided `docker-compose.yml` passes all `LDAP_*` variables through from `.env` — enable LDAP by uncommenting them there, no compose edits needed. When they are unset, LDAP stays disabled.

## Architecture

```
Flask App Factory
├── Models (SQLAlchemy)
│   ├── User            (roles: admin, csr_requester)
│   ├── CertificateAuthority
│   ├── Certificate
│   ├── CertificateSigningRequest
│   └── AuditLog
├── Services
│   ├── crypto_utils    (Fernet key encryption)
│   ├── ca_service      (CA creation)
│   ├── cert_service    (certificate signing/export)
│   ├── csr_service     (CSR generation/import)
│   ├── crl_service     (revocation/CRL)
│   ├── ocsp_service    (OCSP responder)
│   └── audit_service   (audit logging)
└── Routes (Blueprints)
    ├── auth            (login/logout)
    ├── dashboard       (role-conditional stats)
    ├── ca              (CA CRUD - admin only)
    ├── certificates    (cert CRUD - admin only)
    ├── csr             (CSR CRUD - ownership enforced)
    ├── users           (user management - admin only)
    └── public          (CRL/CA/OCSP - no auth)
```
