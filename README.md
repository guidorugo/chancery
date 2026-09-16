# Chancery

A web-based X.509 Certificate Authority management application built with Python and Flask.

> **Formerly `cert-manager`** (renamed in 2.12.0, no relation to the Kubernetes project). Old GitHub URLs redirect; container images now publish to `ghcr.io/guidorugo/chancery`. Two on-disk identifiers deliberately keep the old name so existing deployments upgrade in place: the default SQLite filename (`cert-manager.db`) and the SoftHSM token label (`PKCS11_TOKEN_LABEL=cert-manager`).

## Features

- **CA Management**: Create root and intermediate Certificate Authorities with RSA or EC keys, or import existing ones — PEM (single certificate or full chain), PKCS#12 bundles, encrypted private keys, and certificate-only imports for offline roots — and export them back out (chain bundle, private key, password-protected PKCS#12)
- **Certificate Issuance**: Generate certificates with SANs (DNS, IP, email, URI, and Microsoft UPN), key usage, extended key usage, and CRL Distribution Points
- **Search, filter and pagination**: The certificate, CSR and CA lists take a search box and status/CA/profile filters (CAs: type and key protection), page 50 rows at a time, and the dashboard counters link straight into the matching filtered view; the JSON API accepts the same `q`, `status`, `ca_id`, `profile`, `page` and `per_page` parameters
- **Certificate Detail View**: Full certificate details including Key Usage, Extended Key Usage, subject DN fields, requester, issuer (who signed/created it), and SANs
- **Certificate profiles**: Stored, server-enforced issuance policies (Preferences → Profiles). A profile fixes Key Usage / Extended Key Usage and can bound validity, key type and size, and SAN types; the built-ins (Web Server, Client Auth, Email/S-MIME, Code Signing, Custom) are editable, requesters can ask for one on a CSR, and each CA can be restricted to a set of profiles. Enforced for the API as well as the forms
- **Advanced Certificate Settings**: Collapsible UI with the profile selector, Key Usage and Extended Key Usage checkboxes (editable for the Custom profile), and editable CRL Distribution Points (auto-populated from hostname, user-overridable)
- **CSR Management**: Create or import Certificate Signing Requests, sign or reject them — the signing user is recorded and shown on the CSR and certificate
- **Revocation**: Revoke certificates with standard reasons, generate CRLs
- **Renewal and re-key**: One click (or `POST /certificates/<id>/renew`) issues a successor with the same subject, SANs, usages and profile — keeping the escrowed key so deployed material keeps working, or generating a fresh one; optionally revokes the old certificate as *superseded*. Successors are linked (`renewed_from_id`), the old certificate is flagged *Superseded*, and expiry reminders move to the successor
- **OCSP Responder**: Built-in OCSP endpoint for real-time certificate status checks; optionally signs responses with a short-lived **delegated responder certificate** (`OCSP_DELEGATED_RESPONDER`) so the CA key is used once a month instead of per request — the scheduler renews responders, the CA page shows their status with a *Rotate responder* button
- **Automatic CRL refresh**: A built-in scheduler regenerates every CA's CRL before it expires (no cron needed), an expired CRL is regenerated on the fly when downloaded, and CRL responses carry proper caching headers
- **Public Endpoints**: Unauthenticated access to CRL downloads and CA certificates
- **Monitoring**: `/health` liveness probe and an opt-in Prometheus `/metrics` endpoint (dedicated bearer token, minimal exposure)
- **Role-Based Access Control**: Admin and CSR User roles with enforced separation of duties
- **Audit Logging**: Every sensitive action logged with user, timestamp, IP, and details
- **User Management**: Admin UI for creating users, assigning roles, and managing accounts
- **Scoped API tokens**: `Authorization: Bearer chy_api_…` credentials for scripts and automation, created per user (Preferences → API Tokens, or `flask api-token`), with a subset of scopes (`read`, `issue`, `revoke`, `admin`), a mandatory expiry and one-click revocation — never more than the owner's role. Prefer them over Basic Auth for anything automated
- **Two-factor login (TOTP)**: Any user (local or LDAP) can enrol an authenticator app (RFC 6238, QR code or manual key) at *Two-factor* in the navbar; the login then asks for a 6-digit code after the password, with eight single-use recovery codes as the fallback. Codes are replay-protected and failed codes count toward the login lockout. `REQUIRE_2FA_FOR_ADMINS=true` forces every administrator to enrol before doing anything else; an admin (or `flask users reset-2fa`) can clear a lost authenticator. Password changes, admin resets and any 2FA change log the account out of all other sessions
- **HTTP Basic Auth**: Stateless API access via `curl -u user:pass` for scripts and automation, alongside session-based browser auth
- **Dark Theme**: Light/dark mode toggle with OS-preference default and per-browser persistence
- **Security**: Private keys encrypted at rest with Fernet (PBKDF2-derived key, 600k iterations), session hardening, per-IP rate limiting and per-account login lockout (both on by default), insecure-default rejection plus a startup warning for short `SECRET_KEY` / `MASTER_PASSPHRASE` / PKCS#11 PIN values
- **Minimal hardened image**: Alpine-based (~123 MB), digest-pinned, runs as non-root with all capabilities dropped; no `pip`, `bash`, or package manager extras in the runtime — scanned clean (0 known CVEs) at the v2.8.0 release
- **Forced first-login password change**: The bootstrap admin seeded from `ADMIN_PASSWORD` must set a new password before using the app, so the seed credential can't become permanent; the same applies to passwords an admin sets for other users (create / reset), which must also meet `MIN_PASSWORD_LENGTH`; self-service change-password for any local user
- **CA certificate re-issue and cross-signing**: Re-issue a CA's certificate for the *same* key (new serial and validity, identical subject, key identifier and extensions — every certificate it ever issued keeps validating), or have another CA cross-sign it so relying parties that trust the other hierarchy can validate yours too. Previous and cross-signed certificates are kept as alternates, served at `/public/ca/<id>/alt/<alt_id>.crt`, and chains can be exported via either path (`?via=<alt_id>`). Externally issued cross-certificates can be imported. Both operations are CA-creation events under dual control
- **Name Constraints**: A root or intermediate CA can carry an RFC 5280 Name Constraints extension (critical) — permitted and excluded subtrees as `DNS:example.com`, `IP:10.0.0.0/8`, `EMAIL:example.com`, `URI:example.com` — set at creation (Advanced) or read from an imported CA certificate. Chancery enforces them at issuance for the whole chain (SANs and a hostname-like Common Name; excluded wins), so a constrained CA can never sign a certificate that clients would reject
- **Certificate Policies**: A CA can declare the policy OIDs it issues under, each with an optional CPS URL (Advanced → *Certificate policies*, or read from an imported CA certificate). They are stamped on the CA certificate and inherited by every certificate it issues; a certificate profile can declare its own list, which then wins. Shown on the CA and certificate pages and in the JSON API
- **Key algorithms**: RSA (2048–8192), EC P-256/P-384/P-521, and — new in 2.20.0 — **Ed25519 / Ed448** for CAs, certificates and CSRs, in software or in the PKCS#11 token (EdDSA). Ed25519/Ed448 are for mTLS between modern stacks (Go, OpenSSL 3, rustls), SSH-style use and code signing; browsers and Windows Schannel do not accept them for TLS server certificates, and the forms say so. Any other algorithm (DSA, other curves) is refused everywhere — generation, CSR upload, signing and CA import. Signature digests can be matched to the key (`SIGNATURE_HASH_POLICY=match-curve`: SHA-384 for P-384, SHA-512 for P-521, a configurable digest for RSA)
- **Hardware-backed keys (SoftHSM/PKCS#11)**: Enabled by default — CA signing keys can be held in a PKCS#11 token so they never enter application memory and cannot be exported; selectable per-CA (software stays the default backend), with a one-way migration for existing CAs and a drop-in path to a real hardware HSM
- **LDAP Login**: Optional LDAP/Active Directory authentication with group-to-role mapping and automatic user provisioning — configurable from the admin UI (Preferences → LDAP, with a live connection test) or via environment variables
- **Dual control (four-eyes)**: Opt-in mode (`DUAL_CONTROL_ENABLED`) where no single admin can both request and approve issuance — direct certificate creation is disabled in favour of the CSR flow, a CSR's creator cannot sign it, and a new CA must be approved by a different admin before it can issue anything; kicks in automatically once the instance is genuinely multi-user (or LDAP is enabled), with the bootstrap `admin` account exempt from all three restrictions as break-glass (so e.g. an LDAP outage can never block issuance); a CA awaiting approval is shown as **Pending approval** rather than *Active* until a second admin approves it
- **Webhook notifications**: POST selected audit events (certificate issued/revoked, CSR signed, CA created/approved, logins, …) as JSON to any HTTP endpoint (e.g. an n8n workflow) — configurable from the admin UI (Preferences → Webhooks, with a test button) or via `WEBHOOK_*` environment variables; optional HMAC-SHA256 body signature, fire-and-forget delivery that never blocks a request
- **Expiry events**: A daily scheduler pass reports each certificate and CA once as it enters the `CERT_EXPIRY_WARNING_DAYS` window (`certificate_expiring` / `ca_expiring`) and once more when it expires (`certificate_expired` / `ca_expired`) — audit-logged and delivered through the webhook like any other event, so a renewal reminder needs no external cron or polling
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

# Run with the required environment variables
docker run -d \
  -p 5000:5000 \
  -v ./data:/app/data \
  -e SECRET_KEY=your-secret-key \
  -e MASTER_PASSPHRASE=your-passphrase \
  -e ADMIN_PASSWORD=your-initial-admin-password \
  -e DATABASE_URL=sqlite:////app/data/cert-manager.db \
  -e SESSION_COOKIE_SECURE=false \
  ghcr.io/guidorugo/chancery:latest
```

All five variables matter for a bare `docker run`: the app refuses to start with the placeholder `SECRET_KEY`/`MASTER_PASSPHRASE`, and with the placeholder `ADMIN_PASSWORD` when it would seed the first admin; `DATABASE_URL` must point inside the `/app/data` volume (the process runs as uid 1000 and cannot write anywhere else in the image); and `SESSION_COOKIE_SECURE` defaults to `true`, so drop that line once a TLS proxy is in front. This bare form does not wire up the SoftHSM backend — use `docker-compose.yml` for that (it sets all of the above for you).

You can also use the pre-built image with docker compose by commenting out the `build` line and uncommenting the `image` line in `docker-compose.yml`.

**Verify a release image** (signature + provenance/SBOM):

```bash
# Verify the keyless cosign signature (signed by the release workflow).
# Signatures are stored in the legacy tag format, so any cosign version works.
cosign verify ghcr.io/guidorugo/chancery:2.12.3 \
  --certificate-identity-regexp 'https://github.com/guidorugo/chancery/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Inspect the SLSA provenance / SBOM (BuildKit in-toto attestations in the index)
docker buildx imagetools inspect ghcr.io/guidorugo/chancery:2.12.3 --format '{{ json .Provenance }}'
docker buildx imagetools inspect ghcr.io/guidorugo/chancery:2.12.3 --format '{{ json .SBOM }}'
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

The footer shows an **"Update available"** badge when a newer GitHub release exists (on by default; set `UPDATE_CHECK_ENABLED=false` to disable the outbound check). Check the [release notes](https://github.com/guidorugo/chancery/releases) for any **one-time commands** a version needs (run them as the `app` user — see [CLI Commands](#cli-commands)) — e.g. after upgrading to **2.5.0**, correct the stored expiry on certificates issued by older versions:

```bash
docker compose exec -u app app flask certs recompute-expiry
```

Similarly, after upgrading to **2.11.0**, populate the new signer/issuer fields on
pre-existing CSRs and certificates from the audit log (idempotent, optional):

```bash
docker compose exec -u app app flask certs backfill-issuers --dry-run   # preview
docker compose exec -u app app flask certs backfill-issuers
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

Go to **CAs > Create CA**, fill in the subject details, choose the key type (RSA 2048/3072/4096, EC P-256/P-384/P-521, or Ed25519/Ed448), and set validity.

### 2. Issue a Certificate

Go to **Certificates > Create Certificate**, select the issuing CA, fill in subject and SANs. Expand **Advanced Settings** to choose a certificate profile (Web Server, Client Auth, Email/S-MIME, Code Signing) or manually configure Key Usage and Extended Key Usage. CRL Distribution Points are auto-populated based on the selected CA and can be manually overridden. The hostname is auto-detected from the browser request when `SERVER_NAME_FOR_OCSP` is not explicitly set.

### 3. Manage CSRs

Go to **CSRs > Create CSR** to generate or upload a CSR. Then sign it with a CA from the CSR detail page. The signing form also includes **Advanced Settings** for profile selection and extension customization.

### 4. Revoke & CRL

Revoke a certificate from its detail page. Generate a CRL from the CA detail page. Revoking refreshes the issuing CA's CRL immediately; if that refresh fails (token unreachable, passphrase mismatch) the revocation itself still stands and is audited — the page shows a warning and JSON clients get a `warning` field, and you regenerate the CRL from the CA page. A revoked CA publishes one final CRL that stays valid until the CA certificate expires, so old leaves keep validating as *revoked* rather than *CRL expired*.

### 5. Public Endpoints

| Endpoint | Description |
|----------|-------------|
| `/public/ca/<id>.crt` | Download CA certificate (PEM) |
| `/public/crl/<id>.crl` | Download CRL (DER) |
| `/public/crl/<id>.pem` | Download CRL (PEM) |
| `/public/ocsp/<id>` | OCSP responder (POST, DER) |
| `/public/ocsp/<id>/<base64-request>` | OCSP responder, RFC 6960 GET form (URL-encoded base64 of the DER request) |

### OCSP Testing

```bash
openssl ocsp \
  -issuer ca.pem \
  -cert cert.pem \
  -url http://localhost:5000/public/ocsp/1 \
  -resp_text
```

Both the POST form and the RFC 6960 GET form (`GET /public/ocsp/1/<url-encoded base64 request>`, what Windows CryptoAPI uses for small requests) are served. A request that is not valid DER gets an OCSP `malformedRequest` response at HTTP 200, not an HTTP error.

## Rotating the master passphrase

Every stored private key and secret (software CA keys, escrowed leaf keys, the LDAP bind password, the webhook secret) is wrapped under `MASTER_PASSPHRASE`. To move to a new passphrase without exporting anything:

```bash
# 1. generate the new value next to the old one (never on a command line)
openssl rand -base64 24 > secrets/master_passphrase.new && chmod 600 secrets/master_passphrase.new

# 2. re-wrap every ciphertext in one transaction (verifies the current passphrase first,
#    and each re-wrapped blob afterwards); add --dry-run to rehearse
docker compose exec -T -u app app flask keys rotate-passphrase --new-file - < secrets/master_passphrase.new

# 3. swap the secret file and recreate the container — do this right away: between
#    steps 2 and 3 the running app still holds the OLD passphrase and cannot decrypt
mv secrets/master_passphrase.new secrets/master_passphrase
docker compose up -d --force-recreate

# 4. confirm
docker compose exec -u app app flask keys check-passphrase
```

`check-passphrase` also tells you, after a restore from backup, whether the running secret matches the database. HSM-backed CA keys live in the token and are not affected by the passphrase.

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
  docker compose exec -u app app flask keys migrate-to-hsm --dry-run         # preview
  docker compose exec -u app app flask keys migrate-to-hsm                   # migrate all (interactive confirmation)
  docker compose exec -u app app flask keys migrate-to-hsm --ca-id 3 --yes   # just one, unattended
  ```

## Subscriber keys & escrow

> **How private keys are handled.** *Create Certificate* generates the subscriber keypair **server-side** and **escrows** it — stored **encrypted at rest** (Fernet + PBKDF2-HMAC-SHA256, 600k iterations, per-record salt; never plaintext, not cached in memory) and re-downloadable. Convenient for server/TLS certificates you operate yourself.
>
> For **client-auth, S/MIME email, and code-signing** certificates — where the subscriber should be the *only* holder of the key — use **Sign CSR** instead: generate the key on the subscriber's side (ideally in their own token/HSM) and submit a CSR; the app signs it **without ever seeing the private key**.
>
> The **SoftHSM** backend protects the **CA signing key**, not subscriber/leaf keys, so it does not remove escrow — CSR-based issuance is the escrow-free path.

## API Reference

Authenticate programmatic clients with a **scoped API token** (`Authorization: Bearer chy_api_…`, Preferences → API Tokens) rather than Basic Auth: a token carries only the scopes it was given (`read`, `issue`, `revoke`, `admin`), expires, and can be revoked without touching the account password. Basic Auth keeps working — except for an account with two-factor authentication enabled, which is refused with a JSON 403 pointing at API tokens (a bare password must not open an account that asks for a second factor in the browser).

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

#### Listing: search, filter, pagination

The three list endpoints (`GET /ca/`, `GET /certificates/`, `GET /csr/`) accept the same query parameters as the pages:

| Parameter | Applies to | Values |
|-----------|------------|--------|
| `q` | all | substring of common name / serial / SAN (CAs: name / common name / serial) |
| `status` | certificates | `active`, `revoked`, `expiring`, `expired` |
| `status` | CSRs | `pending`, `approved`, `rejected` |
| `status` | CAs | `active`, `revoked`, `expired`, `pending`, `cert-only` |
| `ca_id`, `profile` | certificates, CSRs | issuing CA id; profile key or id |
| `type`, `backend` | CAs | `root`/`intermediate`; `software`/`softhsm` |
| `page`, `per_page` | all | pagination (default 50 per page, max 500) |

Without `page`/`per_page` the JSON response stays a bare array (unchanged for existing scripts); with either, it is `{"items": [...], "page": 1, "per_page": 50, "total": 123, "pages": 3}`.

```bash
curl -u admin:PASSWORD "http://localhost:5000/certificates/?status=expiring&page=1&per_page=25"
```

#### CA Management (admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ca/` | List all Certificate Authorities |
| GET, POST | `/ca/create` | Create or import a CA; `nc_permitted` / `nc_excluded` (one `DNS:`/`IP:`/`EMAIL:`/`URI:` entry per line) set Name Constraints; `certificate_policies` (one `OID [CPS URL]` per line) sets Certificate Policies |
| POST | `/ca/detect-parent` | Detect parent CA for an imported certificate (JSON response) |
| GET | `/ca/<ca_id>` | View CA details |
| POST | `/ca/<ca_id>/approve` | Approve a pending CA (dual control); while the mode is active the approver must not be the CA's creator |
| POST | `/ca/<ca_id>/ocsp-responder/rotate` | Admin | Issue a new delegated OCSP responder certificate now (F7) |
| POST | `/ca/<ca_id>/reissue` | Admin | Re-issue the CA certificate for the same key (`validity_days` optional; F11). Pending under dual control |
| POST | `/ca/<ca_id>/cross-sign` | Admin | Cross-certificate for this CA's key issued by `issuer_ca_id` (`validity_days` optional). Pending under dual control |
| POST | `/ca/<ca_id>/certificates/import` | Admin | Attach an externally issued cross-certificate for this CA's key (`cert_pem`) |
| POST | `/ca/<ca_id>/certificates/<alt_id>/approve`, `…/delete` | Admin | Approve (different admin under dual control) or remove an alternate certificate |
| GET | `/public/ca/<ca_id>/alt/<alt_id>.crt` | Public | An approved alternate CA certificate (previous primary or cross-certificate) |
| GET, POST | `/ca/<ca_id>/revoke` | Revoke a CA (also the way to discard an unwanted pending CA) |
| POST | `/ca/<ca_id>/crl` | Generate a new CRL |
| GET, POST | `/ca/<ca_id>/download` | Export CA. `pem`/`chain` via GET; `key`/`pkcs12` are **POST-only** (private-key material). `pkcs12` needs a `password` **form** field; `format=chain&via=<alt_id>` builds the chain through an alternate certificate |

#### Certificate Management

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| GET | `/certificates/` | Any | List certificates (admin sees all, CSR users see those issued from their own CSRs) |
| GET, POST | `/certificates/create` | Admin | Issue a new certificate (disabled while dual control is active — use the CSR flow) |
| GET | `/certificates/<cert_id>` | Any | View certificate details (CSR users: own only) |
| GET, POST | `/certificates/<cert_id>/revoke` | Admin | Revoke a certificate |
| GET, POST | `/certificates/<cert_id>/renew` | Admin | Issue a successor (F9): form/JSON fields `validity_days` (default: the original window), `rekey` (escrowed-key certificates only), `revoke_old` (reason `superseded`), `force` (renew again although a renewal exists — otherwise 409); JSON answers 201 with the new certificate plus `old_id`. Under dual control a CSR-lineage renewal counts as signing (requester ≠ renewer) and an escrowed-key renewal as direct creation |
| GET, POST | `/certificates/<cert_id>/download` | Any (own) | Download certificate: `?format=pem\|der\|fullchain\|chain` via GET (`fullchain` = leaf → intermediates → root, `chain` = issuers only); `pkcs12` is **POST-only** with a `password` form field, so key material never appears in a URL; `fullchain`/`chain` accept `via=<alt_id>` to route through a cross-signed CA certificate |
| POST | `/certificates/<cert_id>/download-key` | Admin | Download the escrowed private key (PEM, **POST-only**) |

```bash
# Download a certificate in PEM / DER format
curl -u admin:PASSWORD -o cert.pem "http://localhost:5000/certificates/1/download?format=pem"
curl -u admin:PASSWORD -o cert.der "http://localhost:5000/certificates/1/download?format=der"

# Full chain (leaf + issuers) or just the issuing chain
curl -u admin:PASSWORD -o fullchain.pem "http://localhost:5000/certificates/1/download?format=fullchain"
curl -u admin:PASSWORD -o chain.pem "http://localhost:5000/certificates/1/download?format=chain"

# PKCS#12 bundle and private key are POST-only (Basic Auth needs no CSRF token)
curl -u admin:PASSWORD -X POST -d "format=pkcs12&password=changeit" -o cert.p12 http://localhost:5000/certificates/1/download
curl -u admin:PASSWORD -X POST -o cert.key http://localhost:5000/certificates/1/download-key
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
| POST | `/users/<user_id>/reset-2fa` | Clear a user's second factor (lost authenticator) and log out their sessions; 409 if not enabled |
| GET | `/users/audit-log` | View audit log (paginated, `?page=N`) |
| GET, POST | `/users/ldap` | View/save LDAP settings (POST `action=test` runs a live connection test) |
| POST | `/users/ldap/reset` | Remove saved LDAP settings (revert to env config) |
| GET, POST | `/users/webhooks` | View/save webhook notification settings (POST `action=test` sends a test event) |
| GET, POST | `/users/api-tokens` | Any | List (admins: all) or create API tokens; a created token's secret is returned once (`token` in the JSON body) |
| POST | `/users/api-tokens/<id>/revoke` | Any (own) / Admin | Revoke an API token |
| POST | `/users/webhooks/reset` | Remove saved webhook settings (revert to env config) |

#### Dashboard & Auth

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| GET | `/` | Any | Dashboard (role-conditional stats) |
| GET, POST | `/auth/login` | None | Login page |
| GET, POST | `/auth/change-password` | Any (local accounts) | Self-service password change; forced on first login for the seeded admin |
| GET, POST | `/auth/2fa` | — | Second step of the login for a 2FA-enabled account (TOTP or recovery code; the pending step expires after 5 minutes) |
| GET, POST | `/auth/2fa/setup` | Any | Enrol an authenticator (QR / manual key, confirm one code, recovery codes shown once) or view the status |
| POST | `/auth/2fa/disable` | Any | Turn 2FA off (password for local accounts + a current code or recovery code) |
| POST | `/auth/2fa/recovery-codes` | Any | Regenerate the recovery codes (a current code is required; the old codes stop working) |
| POST | `/auth/logout` | Any | Logout (POST-only, CSRF-protected) |

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

The SoftHSM differential tests need `softhsm2` on the host (`apt install softhsm2`) and skip cleanly without it; CI installs it. The Docker image runs Python 3.14, so for full parity run the suite inside the pinned `python:3.14-alpine` base image rather than a host interpreter.

## CLI Commands

Operational commands run through the Flask CLI inside the container. Run them **as the `app` user**: the container starts as root only to fix the data volume's ownership and then drops to `app` (uid 1000); with all capabilities dropped, root cannot read the `0600` secret files, so a plain `docker compose exec app flask …` fails with `PermissionError: … /run/secrets/master_passphrase`.

| Command | Purpose |
|---------|---------|
| `flask certs expiring [--days N] [--json]` | List certificates and CAs expiring within N days (default `CERT_EXPIRY_WARNING_DAYS`), including already-expired ones — cron/monitoring friendly |
| `flask certs recompute-expiry [--dry-run]` | One-time backfill of the stored `not_after` for certificates issued before 2.5.0 |
| `flask certs backfill-issuers [--dry-run]` | One-time backfill of CSR signer / certificate issuer from the audit log (2.11.0) |
| `flask scheduler status` / `flask scheduler tick [--force]` | Show the scheduler lease, each job's last run and the config, or run one pass now (`--force` also runs the daily expiry-events pass regardless of when it last ran) |
| `flask crl refresh [--all]` | Regenerate stale CRLs (or all of them) by hand — the built-in scheduler does this automatically |
| `flask ocsp rotate-responders [--ca-id N] [--force]` | Issue/renew delegated OCSP responder certificates (the scheduler does this hourly when `OCSP_DELEGATED_RESPONDER` is on) |
| `flask profiles list` / `export` / `import <file> [--replace]` | List certificate profiles, dump them as JSON, or import (upsert by key) |
| `flask keys check-passphrase` | Verify the running `MASTER_PASSPHRASE` opens every kind of stored ciphertext |
| `flask keys rotate-passphrase --new-file <path\|-> [--dry-run] [--yes]` | Re-wrap every stored key and secret under a new passphrase in one transaction (see *Rotating the master passphrase*) |
| `flask keys migrate-to-hsm [--ca-id N] [--dry-run] [--yes]` | Move software-backed CA keys into the SoftHSM token (one-way). `--yes` skips the prompt only together with `--ca-id`; if the token fails the post-import signing check, the token object is removed and the software key is left untouched |
| `flask users unlock <username>` | Clear a login lockout / failed-attempt counter from the shell — for when the locked account is the only admin and nobody can unlock it from the Users page |
| `flask users reset-2fa <username>` | Clear a user's TOTP second factor (lost authenticator) and log out their sessions; they can enrol again. Break-glass for a locked-out sole admin (audited `totp_reset`) |
| `flask metrics-token create --name <n> --expires-in-days <N>` / `list` / `revoke <name-or-id>` | Manage bearer tokens for `/metrics` |
| `flask api-token create --user <u> --name <n> --scopes read,issue --expires-in-days <N>` / `list [--user <u>]` / `revoke <id> [--yes]` | Scoped API tokens (F12); the secret is printed once |

```bash
docker compose exec -u app app flask certs expiring --days 14
# CRLs are kept fresh by the built-in scheduler; force a pass or a full regeneration by hand:
docker compose exec -u app app flask scheduler tick
docker compose exec -u app app flask crl refresh --all
```

## Monitoring & Metrics

`GET /health` is an unauthenticated liveness probe (cheap `SELECT 1` → `200`/`503`, JSON only) wired to the Docker healthcheck.

`GET /metrics` exposes Prometheus metrics. It is **off by default** (returns `404`); enable with `METRICS_ENABLED=true`. When enabled it requires a **dedicated bearer token** — distinct from any user account, valid only for `/metrics`, with a required name and expiry, individually revocable, and stored only as a hash:

```bash
# The secret is printed ONCE — store it now.
docker compose exec -u app app flask metrics-token create --name prometheus --expires-in-days 90
docker compose exec -u app app flask metrics-token list
docker compose exec -u app app flask metrics-token revoke prometheus
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
| `DATABASE_URL` | `sqlite:///cert-manager.db` | Database URI (the compose file sets `sqlite:////app/data/cert-manager.db` — the data volume is the only path the uid-1000 process can write to) |
| `ADMIN_USERNAME` | `admin` | Default admin username |
| `ADMIN_PASSWORD` | `admin` | Seeds the **first** admin only (when no users exist); a change is forced on first login, after which it is unused and can be removed |
| `MIN_PASSWORD_LENGTH` | `12` | Minimum length when setting a new password on the change-password page |
| `SERVER_NAME_FOR_OCSP` | `localhost:5000` | Server hostname for OCSP/CRL URLs. When at default, auto-detected from request |
| `SESSION_LIFETIME_MINUTES` | `30` | Session timeout in minutes |
| `RATE_LIMIT_ENABLED` | `true` | Per-IP rate limiting (Flask-Limiter is a pinned dependency); `/health` is exempt. Set `false` to disable |
| `RATE_LIMIT_DEFAULT` | `60/minute` | Default rate limit when enabled |
| `LOGIN_LOCKOUT_THRESHOLD` | `5` | Failed logins per local account before a temporary lock (`0` disables). The last active admin is never hard-locked, so an attacker cannot lock everyone out |
| `LOGIN_LOCKOUT_MINUTES` | `15` | Lock duration once the threshold is hit; cleared early by an admin or `flask users unlock <username>` |
| `REQUIRE_2FA_FOR_ADMINS` | `false` | Force every administrator to enrol a TOTP second factor before using the app (same gate as the first-login password change; logout and the enrolment page stay reachable) |
| `TOTP_ISSUER` | `Chancery` | Issuer name shown in authenticator apps for enrolled accounts |
| `BASIC_AUTH_ENABLED` | `true` | Enable HTTP Basic Auth for programmatic access |
| `BASIC_AUTH_REALM` | `chancery` | Basic Auth realm name in `WWW-Authenticate` header |
| `API_TOKEN_MAX_DAYS` | `365` | Longest lifetime an API token may be given |
| `BASIC_AUTH_CACHE_TTL_SECONDS` | `60` | In-memory cache TTL for verified Basic Auth credentials (`0` disables) |
| `OCSP_URL_SCHEME` | `http` | URL scheme for OCSP AIA URLs in certificates (`https` recommended for production) |
| `SESSION_COOKIE_SECURE` | `true` | Send session cookie only over HTTPS (the plain-HTTP reference compose overrides to `false`) |
| `TRUSTED_PROXY_COUNT` | `0` | Trusted reverse-proxy hops for `ProxyFix` (0 = directly exposed; set to 1 behind one TLS proxy) |
| `MAX_CONTENT_LENGTH_BYTES` | `1048576` | Maximum request body size |
| `MAX_CERT_VALIDITY_DAYS` | `825` | Cap on issued leaf-cert validity (also clamped to the CA's expiry) |
| `MAX_CA_VALIDITY_DAYS` | `7305` | Cap on issued CA validity |
| `MAX_RSA_KEY_SIZE` | `8192` | Largest RSA key accepted for generation and in CSRs |
| `PROFILES_REQUIRE_SELECTION` | `false` | Refuse issuance requests that name no certificate profile (otherwise they use the unrestricted `custom` profile) |
| `MIN_RSA_KEY_SIZE` | `2048` | Minimum accepted RSA key size |
| `SIGNATURE_HASH_POLICY` | `legacy` | Digest for new signatures (certificates, CRLs, OCSP responses, generated CSRs): `legacy` = SHA-256 for every RSA/EC key; `match-curve` = SHA-256/SHA-384/SHA-512 for P-256/P-384/P-521 (as the CA/Browser Forum and RFC 5759 profiles expect) and `RSA_SIGNATURE_HASH` for RSA. Ed25519/Ed448 never take a separate digest. Existing objects are untouched. The default flips to `match-curve` in 3.0 |
| `RSA_SIGNATURE_HASH` | `sha256` | Digest for RSA signatures under `match-curve`: `sha256`, `sha384` or `sha512` |
| `OCSP_KEY_CACHE_TTL_SECONDS` | `300` | In-memory TTL for the decrypted CA key used by OCSP (`0` disables) |
| `OCSP_RESPONSE_CACHE_TTL_SECONDS` | `60` | Cache signed OCSP responses per (CA, serial, status) for this long (`0` disables); the status is part of the key, so a revoked certificate is never served `good` from cache |
| `OCSP_DELEGATED_RESPONDER` | `false` | Sign OCSP responses with a delegated responder certificate (EKU OCSPSigning, id-pkix-ocsp-nocheck) issued by each CA instead of the CA key; responders are renewed by the scheduler and lazily on the request path. Note: every CA's OCSP responder ID changes when this flips. Default flips to `true` in 3.0 |
| `OCSP_RESPONDER_VALIDITY_DAYS` | `30` | Validity of a delegated responder certificate (capped at the CA's expiry) |
| `OCSP_RESPONDER_RENEW_BEFORE_DAYS` | `7` | Renew a responder once it expires within this many days |
| `SCHEDULER_ENABLED` | `true` | Built-in scheduler that keeps CRLs fresh (one worker holds a lease; safe with any worker count) |
| `SCHEDULER_TICK_SECONDS` | `60` | Scheduler pass interval (CRL refresh runs every pass; the expiry-events job once a day) |
| `CRL_REFRESH_BEFORE_DAYS` | `2` | Regenerate a CRL once it expires within this many days |
| `PUBLIC_RATE_LIMIT` | `600/minute` | Per-IP rate limit for the public CRL/OCSP endpoints |
| `CRL_VALIDITY_DAYS` | `7` | `nextUpdate` window stamped into generated CRLs; the scheduler regenerates each CRL before it expires |
| `CERT_EXPIRY_WARNING_DAYS` | `30` | Days before `notAfter` at which a certificate/CA is flagged *expiring soon* (dashboard counts, badges, JSON, `flask certs expiring`) and the daily `certificate_expiring` / `ca_expiring` webhook event fires |
| `UPDATE_CHECK_ENABLED` | `true` | Show a footer "Update available" badge when a newer GitHub release exists (makes an outbound call; set `false` for an air-gapped CA) |
| `METRICS_ENABLED` | `false` | Expose the Prometheus `/metrics` endpoint (opt-in; returns 404 until enabled) |
| `METRICS_ALLOW_UNAUTHENTICATED` | `false` | Serve `/metrics` without a bearer token (isolated networks only) |
| `METRICS_INCLUDE_CA_DETAILS` | `false` | Add a `chancery_ca_info` metric with CA names/CNs/key details (default: opaque `ca_id` + counts only) |
| `UPDATE_CHECK_REPO` | `guidorugo/chancery` | Repository to check for the latest release |
| `UPDATE_CHECK_INTERVAL_SECONDS` | `21600` | Cache TTL for the update check (6h) |
| `UPDATE_CHECK_TIMEOUT_SECONDS` | `4` | HTTP timeout for the update check |
| `APP_VERSION` | – | Override the version shown in the footer (e.g. a git SHA for an untagged build) |
| `MASTER_PASSPHRASE_FILE` / `SECRET_KEY_FILE` / `ADMIN_PASSWORD_FILE` | – | Read the secret from a file (Docker/systemd secret) instead of the env var |
| `KEY_BACKEND` | `software` | Default signing-key backend for **new** CAs: `software` (Fernet-encrypted, exportable) or `softhsm` (PKCS#11 token, non-exportable). HSM is offered per-CA in the create form whenever the token is configured |
| `PKCS11_MODULE` | `/usr/lib/softhsm/libsofthsm2.so` | PKCS#11 library path |
| `PKCS11_TOKEN_LABEL` | `cert-manager` | Token label (kept from the old project name — an existing token cannot be relabelled without destroying its keys) |
| `PKCS11_USER_PIN` / `PKCS11_SO_PIN` | – | Token PINs (`_FILE` convention supported; the compose file reads them from `secrets/`) |
| `SOFTHSM2_CONF` | – | SoftHSM config path; when set, the entrypoint creates the token store and initialises the token on first boot |
| `DUAL_CONTROL_ENABLED` | `false` | Four-eyes issuance: once another active user besides `ADMIN_USERNAME` exists (or LDAP is enabled), direct cert creation is disabled, CSR creators cannot sign their own CSRs, and new CAs need approval by a different admin (`POST /ca/<id>/approve`). The bootstrap admin account is exempt |
| `WEBHOOK_ENABLED` | `false` | POST selected audit events as JSON to `WEBHOOK_URL`. Also configurable in the admin UI (Preferences → Webhooks) — settings saved there override all `WEBHOOK_*` variables until removed |
| `WEBHOOK_URL` | – | Webhook POST target (e.g. an n8n webhook trigger) |
| `WEBHOOK_SECRET` | – | Optional signing secret: requests carry `X-Chancery-Signature: sha256=<HMAC-SHA256 of the body>` (`_FILE` convention supported) |
| `WEBHOOK_EVENTS` | – | CSV of audit action names to notify on (e.g. `sign_csr,create_ca,certificate_expiring`); empty = none, `all` = every action. Time-based events: `certificate_expiring`, `certificate_expired`, `ca_expiring`, `ca_expired` (daily, once per object), `crl_refreshed`, `crl_refresh_failed`, `scheduler_error` |
| `WEBHOOK_TIMEOUT_SECONDS` | `5` | Delivery timeout for the background POST |
| `LDAP_ENABLED` | `false` | Enable LDAP authentication for the web login. Alternatively configure LDAP in the admin UI (Preferences → LDAP) — settings saved there override all `LDAP_*` variables until removed |
| `LDAP_SERVER_URI` | – | LDAP server URI(s), e.g. `ldaps://dc01:636` (comma-separated for failover) |
| `LDAP_USE_STARTTLS` | `false` | Upgrade `ldap://` connections with StartTLS |
| `LDAP_TLS_VERIFY` | `true` | Verify the directory's TLS certificate |
| `LDAP_CA_CERT_FILE` | – | CA bundle for verifying the directory's certificate |
| `LDAP_ALLOW_PLAINTEXT` | `false` | Allow a cleartext `ldap://` URI without StartTLS — startup refuses it otherwise (not recommended) |
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
Flask App Factory (app/__init__.py)
├── Models (SQLAlchemy)
│   ├── User                       (roles: admin, csr_requester; local or LDAP-provisioned; lockout counters)
│   ├── CertificateAuthority       (key_backend software|softhsm; approval_status for dual control)
│   ├── Certificate                (issued_by; escrowed private key)
│   ├── CertificateSigningRequest  (signed_by)
│   ├── AuditLog
│   ├── MetricsToken               (hashed bearer tokens for /metrics)
│   ├── LdapSettings               (single row; overrides LDAP_* env when saved)
│   └── WebhookSettings            (single row; overrides WEBHOOK_* env when saved)
├── Services
│   ├── crypto_utils               (Fernet/PBKDF2 key + secret encryption)
│   ├── keybackend/                (software | softhsm PKCS#11 signing backends)
│   ├── ca_service                 (CA creation, import/export, chains)
│   ├── cert_service               (issuance, CSR signing, bundles, PKCS#12)
│   ├── csr_service                (CSR generation/import)
│   ├── crl_service                (revocation, CRL generation/refresh)
│   ├── ocsp_service               (OCSP responder + response cache)
│   ├── policy                     (server-side key-strength / validity policy)
│   ├── auth_service               (local + LDAP login, Basic Auth, lockout)
│   ├── ldap_service / ldap_settings_service
│   ├── dual_control_service       (four-eyes rules)
│   ├── webhook_service            (audit-event notifications)
│   ├── audit_service              (audit logging → webhook hook)
│   ├── metrics_service / metrics_token_service
│   └── update_service             (cached "update available" check)
└── Routes (Blueprints)
    ├── auth            (login/logout/change-password)
    ├── dashboard       (role-conditional stats)
    ├── ca              (CA management + approval - admin only)
    ├── certificates    (issuance/revocation - admin; details/downloads owner-visible)
    ├── csr             (CSR lifecycle - ownership enforced)
    ├── users           (users, audit log, LDAP & webhook settings - admin only)
    ├── public          (CRL/CA/OCSP - no auth)
    ├── health          (/health liveness probe - no auth)
    └── metrics         (/metrics Prometheus - bearer token)
```
