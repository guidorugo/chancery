# Security Assessment — cert-manager (X.509 CA Management Platform)

> Application security & PKI review of the `cert-manager` Flask application.
> Assessment date: 2026-07-10. Method: source and repository/filesystem inspection (no live exploitation).

## Scope Statement

This review covers the `cert-manager` Flask application in its entirety: cryptographic and PKI logic (`app/services/`), authentication/authorization (`app/routes/auth.py`, `app/decorators.py`, `app/models/user.py`), key and secret management (`crypto_utils.py`, `Config`, env handling), the public unauthenticated interface (`app/routes/public.py`), data storage (SQLite models, on-disk permissions), the container/compose runtime, the GitHub Actions pipeline, dependencies (`requirements.txt`), and the repository's own hygiene (`.git`, history). Analysis was performed by source inspection and repository/filesystem inspection; no live exploitation was performed. Where a conclusion depends on deployment specifics (reverse proxy, TLS termination, network exposure), the precondition is stated in the finding. Assumptions are called out inline.

**Threat model assumed:** the app is published as a public GitHub repo and public GHCR image intended for real deployment as a working CA; adversaries include unauthenticated network clients (can reach `/public/*` and `/auth/login`), authenticated low-privilege users (`csr_requester`), a malicious/compromised operator (`admin`), a host-level reader (backup theft, container escape, `/proc` access), and supply-chain actors (dependency, base image, CI action).

### Findings at a glance

| # | Severity | Finding | Layer |
|---|---|---|---|
| A1 | **Critical** | All CA private keys protected only by one env-var passphrase; no HSM; single point of compromise | Key Mgmt |
| A2 | High | SQLite DB (encrypted keys, password hashes, audit log) is world-readable on host | Storage |
| A3 | High | Live Forgejo credentials committed in `.git/config` working tree | Secrets |
| A4 | Medium | Insecure defaults in code / `.env.example` (`admin/admin`, `dev-*`) | Secrets |
| A5 | Medium | Subscriber private-key escrow (server generates + stores + serves keys) | Key Mgmt |
| A6 | Low | `venv/` committed to git history | Supply chain |
| B1 | **High** | No CSR proof-of-possession — signature never verified | PKI/Crypto |
| B2 | **High** | Revocation does not propagate to CRL (stale cached CRL) | PKI/Crypto |
| B3 | High | Revoked intermediate CAs never appear in parent CRL | PKI/Crypto |
| B4 | Medium | No issuance policy limits (validity, path length, name constraints) | PKI/Crypto |
| B5 | Medium | Weak key sizes accepted (RSA <2048, incl. by low-priv users) | PKI/Crypto |
| B6 | Low | OCSP is direct CA-key responder, no nonce (replayable) | PKI/Crypto |
| C1 | **High** | Unauthenticated OCSP forces CA-key decryption (600k PBKDF2) per request → DoS | API/DoS |
| C2 | Medium | No `MAX_CONTENT_LENGTH` — unbounded request bodies | API/DoS |
| C3 | Medium | PKCS#12 export password passed via GET query string; weak default | API |
| C4 | Low-Med | Host-header injection into issued-cert OCSP/CRL URLs | API |
| C5 | Low-Med | Open-redirect bypass via backslash in `next` | API |
| D1 | Medium | No rate limiting / lockout / MFA on login or Basic Auth | AuthN |
| D2 | Medium | Migration grants `role='admin'` to all pre-existing users | AuthZ |
| D3 | Medium | Basic Auth default-on over plaintext HTTP; failed attempts flood audit log | AuthN |
| D4 | Low | No multi-party authorization for CA operations | AuthZ |
| D5 | Low | Default-admin creation race; ADMIN_PASSWORD not rotated after first boot | AuthN |
| E1 | High | No TLS in shipped stack; secure-cookie/OCSP-scheme default to insecure | Transit |
| E2 | Low | Runtime CDN dependency; no CSP (SRI present) | Transit |
| F1 | Medium | Key material not zeroizable; resident in memory/swap/core dumps | Runtime |
| F2 | Medium | Debug mode exposes Werkzeug debugger and bypasses insecure-default checks | Runtime |
| F3 | Low | CRL number increment race across workers | Runtime |
| G1 | Medium | Audit log not tamper-evident; no anomaly alerting | Logging |
| G2 | Low | `remote_addr` without `ProxyFix` — wrong client IP in logs/limits | Logging |
| H1 | Medium | Container runs as root; no hardening in compose | Container |
| H2 | Low-Med | Base image pinned by mutable tag; no image vuln scan | Container |
| I1 | Medium | No dependency hash/lockfile integrity pinning | Supply chain |
| I2 | Low-Med | No SCA/vulnerability scanning in CI | Supply chain |
| J1 | Medium | CI actions pinned by mutable tags, not commit SHAs | CI/CD |
| J2 | Medium | No image signing / provenance / SBOM | CI/CD |
| L1 | Info | Consolidated CA/Browser Forum & NIST/RFC compliance gaps | Compliance |

---

## A. Secrets & Key Management

### [CRITICAL] — A1: All CA private keys are protected only by a single environment-variable passphrase

| Field | Details |
|---|---|
| **Severity** | Critical |
| **Affected Component** | `crypto_utils.py`, `Config.MASTER_PASSPHRASE`, all `*_service.py` |
| **Vulnerability Type** | Insufficient key protection / no key isolation (CWE-320, CWE-522) |
| **Description** | Every CA and escrowed certificate private key is Fernet-encrypted with a key derived from one process-wide `MASTER_PASSPHRASE` (`app/config.py:7`). That passphrase is read from an environment variable and lives in the process for its entire lifetime. Any actor who can read the environment (`/proc/<pid>/environ`, `docker inspect`, a crash dump, an SSRF/LFI primitive, or the compose `.env`) obtains the single secret that decrypts **all** CA keys. There is no HSM/KMS, no per-CA key wrapping, no key hierarchy, and no split knowledge. |
| **Who Can Exploit & Why It Works** | A host-level reader (container escape, backup theft, another container on the host, a co-tenant, or an operator with shell) — because "encryption at rest" and the decryption secret are co-located. The passphrase is not itself protected (no KMS envelope, no OS keyring). |
| **Potential Impact** | Full CA compromise: forge arbitrary certificates for any identity, sign rogue sub-CAs, impersonate every relying party in the trust chain. This is total loss of the trust anchor. |
| **Evidence / Indicators** | `passphrase = current_app.config["MASTER_PASSPHRASE"]` in every route; `_derive_key()`/`Fernet` in `crypto_utils.py`; `MASTER_PASSPHRASE` in `docker-compose.yml` env. |
| **References** | NIST SP 800-57 Pt.1/2 (key storage & CA key protection), CA/B BR §6.2 (private key protection, FIPS 140-2/3 Level 3 for CA keys), OWASP ASVS V6, CWE-320. |
| **Remediation** | Move CA key operations behind a KMS/HSM (SoftHSM/PKCS#11 at minimum; cloud KMS or YubiHSM for production) so plaintext keys never enter the app. If that is out of scope near-term: (1) derive per-CA wrapping keys from the master via HKDF with a per-CA salt so one leaked derived key ≠ all keys; (2) source the master from a secrets manager (Vault, cloud KMS) fetched at runtime, not a static env var; (3) require passphrase re-entry for signing rather than holding it resident. Document an offline-root architecture (see L). |

### [HIGH] — A2: Application database is world-readable on the host

| Field | Details |
|---|---|
| **Severity** | High |
| **Affected Component** | `data/cert-manager.db`, Docker volume, `instance/cert-manager.db` |
| **Vulnerability Type** | Incorrect file permissions (CWE-732) |
| **Description** | `data/cert-manager.db` is mode `0644` owned by `root`; `instance/cert-manager.db` is `0664`. This single file contains the Fernet-encrypted CA private keys, user password hashes, and the entire audit log. World-readable permissions mean any local user (or any process/container mounting the path) can copy it. Combined with A1, an attacker who also reads the environment gets cleartext keys; even without the passphrase they get password hashes for offline cracking and the full audit trail. |
| **Who Can Exploit & Why It Works** | Any unprivileged local account or co-located container. The SQLite file has no OS-level access control restricting it to the service account. |
| **Potential Impact** | Offline attack surface for all key material and credentials; audit-log disclosure; feeds A1 to full CA compromise. |
| **Evidence / Indicators** | `ls -l data/cert-manager.db` → `-rw-r--r-- root`. |
| **References** | CWE-732, CIS Benchmarks (file permissions), NIST SP 800-57 (storage protection). |
| **Remediation** | `chmod 0600` the DB and its directory; own it by a dedicated non-root service user (see H1). In Docker, create the data dir owned by that UID and `chmod 700`. Enable SQLite at-rest encryption (SQLCipher) or full-disk/volume encryption. Restrict backups similarly and encrypt them. |

### [HIGH] — A3: Live Forgejo credentials committed in `.git/config`

| Field | Details |
|---|---|
| **Severity** | High |
| **Affected Component** | `.git/config` (`forgejo` remote) |
| **Vulnerability Type** | Cleartext embedded credentials (CWE-798/CWE-256) |
| **Description** | The `forgejo` remote URL embeds a username/password in cleartext: `http://<user>:<password>@<forgejo-host>/...`. Anyone with read access to the working tree, a filesystem backup, or a leaked developer image obtains valid Forgejo credentials in plaintext, transmitted over HTTP (unencrypted) on every fetch/push. |
| **Who Can Exploit & Why It Works** | A host reader or backup thief; also passive network observers since the remote is `http://`. The secret is stored and transmitted without protection. |
| **Potential Impact** | Compromise of the Forgejo git forge account, enabling repository tampering (malicious commits that flow into the Docker image build), and — given the n8n PR-review pipeline in the environment — a pivot into the automation. |
| **Evidence / Indicators** | `.git/config` `url = http://<user>:<password>@<forgejo-host>/...`. |
| **References** | CWE-798, OWASP A07:2021, NIST SP 800-53 IA-5. |
| **Remediation** | **Rotate this password now** (it is exposed in cleartext on disk). Replace the embedded-credential remote with SSH or a git credential helper (`git config credential.helper`), and switch the Forgejo remote to HTTPS. Purge the credential from any shared images/backups. |

### [MEDIUM] — A4: Insecure default secrets shipped in code and `.env.example`

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `app/config.py`, `.env.example`, `docker-compose.yml` |
| **Vulnerability Type** | Use of hard-coded/weak default credentials (CWE-1188, CWE-798) |
| **Description** | Defaults are `SECRET_KEY="dev-secret-key"`, `MASTER_PASSPHRASE="dev-passphrase"`, `ADMIN_PASSWORD="admin"`; `.env.example` ships `ADMIN_USERNAME=admin`/`ADMIN_PASSWORD=admin` and `change-me-*` secrets; `docker-compose.yml` uses `ADMIN_PASSWORD=${ADMIN_PASSWORD:-admin}`. The `_check_security()` startup guard (`app/__init__.py:105`) rejects the three exact insecure defaults — but **only** when not in testing/debug (see F2), matches only the exact string (a weak-but-different passphrase passes), and only covers first-boot admin creation (rotating `ADMIN_PASSWORD` later does not re-hash the stored admin). |
| **Who Can Exploit & Why It Works** | An external attacker if the app ever runs in debug or with a near-default secret; the guard is bypassable and non-comprehensive. A predictable `SECRET_KEY` allows session-cookie forgery (full auth bypass). |
| **Potential Impact** | Session forgery, key-passphrase guessing, default-admin takeover. |
| **Evidence / Indicators** | `_INSECURE_*` constants; `.env.example`; `:-admin` in compose. |
| **References** | CWE-1188, OWASP A05:2021, A07:2021. |
| **Remediation** | Remove real-looking defaults; require all secrets with no fallback (fail closed). Enforce a minimum entropy/length check on `SECRET_KEY`/`MASTER_PASSPHRASE` rather than exact-match denylisting. Do not ship `ADMIN_PASSWORD=admin` in examples — generate a random password on first boot and print a "must change" one-time token instead. Audit and rotate the current `.env`. |

### [MEDIUM] — A5: Subscriber private-key escrow

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `cert_service.create_certificate()`, `certificates.download_key`, `csr_service.create_csr()` |
| **Vulnerability Type** | Unnecessary retention of private keys / key escrow (CWE-522) |
| **Description** | When certificates are generated server-side, the subscriber's private key is generated by the CA, stored encrypted in the DB (`Certificate.private_key_enc`), and downloadable indefinitely via `/certificates/<id>/download-key` (admin) or bundled into PKCS#12. A CA holding subscriber private keys concentrates risk and breaks non-repudiation. CSR-generated keys are shown once and not stored (good), but the create-certificate flow escrows keys. |
| **Who Can Exploit & Why It Works** | A malicious/compromised admin or anyone who reads the DB + passphrase — every escrowed subscriber key is recoverable. |
| **Potential Impact** | Mass impersonation of subscribers; loss of non-repudiation; larger blast radius on DB/passphrase compromise. |
| **Evidence / Indicators** | `private_key_enc` set in `create_certificate`; `download_key` route decrypts and returns cleartext PEM. |
| **References** | NIST SP 800-57, CA/B BR §6.1.2 (subscriber key generation), CWE-522. |
| **Remediation** | Prefer CSR-based issuance where the subscriber holds the key. If server-side generation is offered, deliver the key once and do not persist it (mirror the CSR flow), or make escrow opt-in with explicit audit and a retention/destruction policy. |

### [LOW] — A6: `venv/` committed to git history

| Field | Details |
|---|---|
| **Severity** | Low |
| **Affected Component** | Git history (`1d2fcb1 First commit`) |
| **Vulnerability Type** | Repository hygiene / dependency surface exposure (CWE-1104) |
| **Description** | The initial commit added the entire `venv/` (interpreter, pip, site-packages). It is now gitignored, but history still carries pinned third-party binaries and bloats the clone. The real `.env` was **not** committed (verified) — only `.env.example`. |
| **Who Can Exploit & Why It Works** | Not directly exploitable; increases audit surface and can pin an old vulnerable dependency snapshot in history. |
| **Potential Impact** | Minor: information about exact toolchain; repo bloat. |
| **Evidence / Indicators** | `git show --stat 1d2fcb1` lists `venv/...`. |
| **References** | CWE-1104. |
| **Remediation** | Keep `venv/` ignored (already done). Optionally rewrite history to drop it; not urgent since no secret was included. |

---

## B. Cryptographic Implementation & PKI Correctness

### [HIGH] — B1: CSR proof-of-possession is never verified before signing

| Field | Details |
|---|---|
| **Severity** | High |
| **Affected Component** | `cert_service.sign_csr()`, `csr_service.import_csr()/parse_csr()` |
| **Vulnerability Type** | Missing cryptographic verification (CWE-347) |
| **Description** | `x509.load_pem_x509_csr()` parses a CSR but does **not** verify its self-signature; the code never checks `csr.is_signature_valid` (confirmed: no occurrence in `app/`). The CA therefore issues certificates from CSRs without confirming the requester controls the private key corresponding to the embedded public key (proof-of-possession, RFC 2986 §4 / RFC 4211). |
| **Who Can Exploit & Why It Works** | Any user who can submit/import a CSR (a `csr_requester` can upload arbitrary CSR PEM). They can craft a CSR embedding a third party's public key with a bogus signature; the CA signs it because signature validity is never enforced. |
| **Potential Impact** | Mis-issuance: binding of arbitrary subjects/SANs to public keys the requester does not control, undermining the CA's core assurance and enabling downstream confusion/deputy attacks; pollutes issuance policy assumptions. |
| **Evidence / Indicators** | Absence of `is_signature_valid`; `load_pem_x509_csr(...)` used directly in `sign_csr` and `parse_csr`. |
| **References** | RFC 2986, RFC 4211 §4 (POP), CA/B BR §4.1.2, CWE-347. |
| **Remediation** | In `import_csr`/`sign_csr`, reject any CSR where `csr.is_signature_valid` is `False`. Enforce minimum key strength at the same point (B5). |

### [HIGH] — B2: Certificate revocation does not propagate to the published CRL

| Field | Details |
|---|---|
| **Severity** | High |
| **Affected Component** | `crl_service.revoke_certificate()`, `get_crl_pem/der()`, `routes/public.py` |
| **Vulnerability Type** | Security-control bypass / stale state (CWE-672) |
| **Description** | `revoke_certificate()` only flips DB flags; it does not regenerate or invalidate the cached `ca.crl_pem`. The public endpoints return the cached CRL whenever present (`if ca.crl_pem: return ...`). Consequently, after a revocation the publicly served CRL remains stale until an admin manually POSTs `/ca/<id>/crl`. Relying parties that use CRLs will continue to trust a revoked certificate. (OCSP is computed live, which mitigates for OCSP-checking clients but not CRL-checking ones — an inconsistent, partial revocation.) |
| **Who Can Exploit & Why It Works** | An attacker holding a certificate that the operator believes they revoked — the revocation silently fails to reach CRL consumers because the cache is never busted. |
| **Potential Impact** | Revoked (possibly key-compromised) certificates remain trusted by CRL-based validators; defeats the primary revocation mechanism. |
| **Evidence / Indicators** | `revoke_certificate` has no CRL call; `get_crl_pem` short-circuits on cached `crl_pem`; no cache invalidation anywhere. |
| **References** | RFC 5280 §5, CA/B BR §4.9 (revocation), CWE-672. |
| **Remediation** | On any revocation (cert or CA), regenerate the affected CA's CRL (and set an appropriate `next_update`), or invalidate `crl_pem` so the next fetch regenerates. Auto-regenerate on a schedule and before `next_update` expiry. Ensure `next_update` is honored and short enough. |

### [HIGH] — B3: Revoked intermediate CAs are never listed in the parent's CRL

| Field | Details |
|---|---|
| **Severity** | High |
| **Affected Component** | `crl_service.generate_crl()`, `revoke_ca()` |
| **Vulnerability Type** | Incomplete revocation (CWE-672) |
| **Description** | `generate_crl()` enumerates only `Certificate` rows (`Certificate.query.filter_by(ca_id=..., is_revoked=True)`). Revoked **sub-CAs** are stored as `CertificateAuthority` rows and are never added to the parent CA's CRL. When an intermediate CA is revoked (e.g., key compromise), relying parties checking the parent CRL will not see it. |
| **Who Can Exploit & Why It Works** | An attacker in control of a compromised intermediate — its revocation is invisible to CRL consumers because CA rows are excluded from CRL generation. |
| **Potential Impact** | A compromised intermediate CA continues to be trusted; every certificate under it stays valid to CRL validators. Highest-impact revocation failure in a hierarchy. |
| **Evidence / Indicators** | `generate_crl` builds revoked entries only from `Certificate`; `revoke_ca` sets CA flags but adds nothing to any CRL. |
| **References** | RFC 5280, CA/B BR §4.9, CWE-672. |
| **Remediation** | Include revoked child CAs (by serial) in the issuing CA's CRL, and regenerate the parent CRL when a sub-CA is revoked. Consider OCSP responses for CA certificates as well. |

### [MEDIUM] — B4: No issuance policy limits (validity, path length, name constraints)

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `cert_service`, `ca_service`, issuance routes |
| **Vulnerability Type** | Missing security policy enforcement (CWE-693) |
| **Description** | `validity_days` is taken from the form with no maximum (TLS certs can exceed the CA/B 398-day limit; a cert can be issued to outlive its issuing CA). Intermediate CAs are created with no `NameConstraints` and default `path_length=None` (unlimited sub-CA chaining). There is no policy tying issued EKUs/validity to a profile enforced server-side beyond the checkbox UI. |
| **Who Can Exploit & Why It Works** | A compromised/careless operator can mint over-broad or over-long certificates and unconstrained intermediates; no server-side ceiling stops it. |
| **Potential Impact** | Non-compliant, long-lived, or overly powerful certificates; unconstrained intermediates widen blast radius on compromise. |
| **Evidence / Indicators** | `int(request.form.get("validity_days", ...))` with no cap; `BasicConstraints(ca=True, path_length=path_length)` with default `None`; no `NameConstraints` added. |
| **References** | CA/B BR §6.3.2 (validity), RFC 5280 §4.2.1.9/§4.2.1.10 (basic/name constraints). |
| **Remediation** | Enforce max validity per profile (e.g., ≤398 days for TLS), reject `not_after > CA.not_after`, set a sane default `path_length` (0 for issuing CAs), and support `NameConstraints` on intermediates. Validate the requested profile server-side, not just in the UI. |

### [MEDIUM] — B5: Weak key sizes accepted from user input

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `_generate_key()` in ca/cert/csr services; issuance routes |
| **Vulnerability Type** | Inadequate cryptographic strength (CWE-326) |
| **Description** | `key_size` is parsed from the form (`int(request.form.get("key_size", "2048"))`) with no minimum. RSA sizes below 2048 (e.g., 512/1024) are accepted by `rsa.generate_private_key`, so a low-privileged `csr_requester` can generate weak-key CSRs and an admin can create weak CAs/certs. (EC is constrained to a safe curve map and errors on unknown sizes.) |
| **Who Can Exploit & Why It Works** | Any CSR creator (low-priv) or operator — no floor is enforced. |
| **Potential Impact** | Issuance of cryptographically weak certificates; factorable RSA-512. |
| **Evidence / Indicators** | No `key_size >= 2048` check anywhere. |
| **References** | NIST SP 800-57 (≥2048 RSA / 224-bit ECC), CA/B BR §6.1.5, CWE-326. |
| **Remediation** | Enforce minimums server-side: RSA ≥ 2048 (prefer 3072/4096 for CAs), EC P-256/384/521 only. Reject anything else with a clear error. |

### [LOW] — B6: OCSP responder signs with the CA key directly and omits nonces

| Field | Details |
|---|---|
| **Severity** | Low (Medium in high-trust deployments) |
| **Affected Component** | `ocsp_service.build_ocsp_response()` |
| **Vulnerability Type** | Weak protocol handling / online root-key use (CWE-347 adjacent) |
| **Description** | OCSP responses are signed directly by the CA private key on every request (no delegated responder certificate with `id-kp-OCSPSigning`), and the request's OCSP nonce (RFC 8954) is not echoed, allowing response replay. Direct signing also means the CA key is used online for anonymous requests (see C1). |
| **Who Can Exploit & Why It Works** | A network attacker can replay a previously "good" response for a now-revoked certificate because there is no nonce binding. |
| **Potential Impact** | Replay of stale status; unnecessary online exposure of the CA key. |
| **Evidence / Indicators** | `builder.sign(ca_key, ...)`; no `OCSPNonce` handling. |
| **References** | RFC 6960/8954, CA/B BR §4.9.10. |
| **Remediation** | Issue a dedicated OCSP-signing delegate certificate and sign with it; echo the request nonce when present; keep short `next_update`. |

---

## C. API & Interface Security / Denial of Service

### [HIGH] — C1: Unauthenticated OCSP endpoint forces CA-key decryption on every request (DoS + online key exposure)

| Field | Details |
|---|---|
| **Severity** | High |
| **Affected Component** | `routes/public.py:ocsp_responder`, `ocsp_service.build_ocsp_response`, `crypto_utils._derive_key` |
| **Vulnerability Type** | Uncontrolled resource consumption / CPU amplification (CWE-400, CWE-770) |
| **Description** | `POST /public/ocsp/<ca_id>` is unauthenticated and `@csrf.exempt`. Each call runs `decrypt_private_key()`, which executes **600,000 PBKDF2-HMAC-SHA256 iterations** to derive the Fernet key, then performs an asymmetric signature — with no caching of the derived/decrypted key and no rate limiting (off by default). With only 2 Gunicorn workers, a trivial volume of anonymous POSTs saturates CPU and takes down the entire application (web UI, issuance, CRL, OCSP). Additionally, the first anonymous `GET /public/crl/<id>.pem` when no CRL is cached triggers `generate_crl()`, which decrypts the CA key **and performs a DB write** (`crl_number += 1`, commit) — an unauthenticated state change plus key decryption. |
| **Who Can Exploit & Why It Works** | Any unauthenticated network client. The expensive KDF is intentionally slow (good for at-rest security) but is placed on a hot, anonymous path with no throttle or key caching, turning a defensive control into an amplification primitive. |
| **Potential Impact** | Reliable unauthenticated DoS of the whole CA service; repeated loading of CA private-key material into memory driven by anonymous input. |
| **Evidence / Indicators** | `PBKDF2_ITERATIONS = 600_000`; `build_ocsp_response` calls `decrypt_private_key` unconditionally; no `app.limiter` by default; `get_crl_*` triggers `generate_crl` on cache miss. |
| **References** | CWE-400/770, OWASP API4:2023 (Unrestricted Resource Consumption), RFC 6960. |
| **Remediation** | Cache the decrypted CA key / derived Fernet key in memory (or better, keep it in an HSM/KMS so no per-request KDF is needed). Add strict rate limiting on `/public/*` (enable Flask-Limiter by default with a shared backend, not `memory://`). Pre-generate CRLs on a schedule so public GETs never trigger generation/writes; make CRL fetch read-only. Add request-size and timeout guards (C2). Put OCSP/CRL behind a cache/CDN. |

### [MEDIUM] — C2: No global request-size limit

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | Flask app config (no `MAX_CONTENT_LENGTH`) |
| **Vulnerability Type** | Uncontrolled resource consumption (CWE-400) |
| **Description** | `MAX_CONTENT_LENGTH` is never set (verified), so Flask accepts arbitrarily large request bodies. The OCSP endpoint reads the full body (`request.get_data()`) before parsing; PEM upload handlers read files into memory and only then apply a 64KB check. Large bodies cause memory pressure across all POST endpoints. |
| **Who Can Exploit & Why It Works** | Unauthenticated (OCSP) or low-priv (CSR upload) clients — no ceiling exists. |
| **Potential Impact** | Memory-exhaustion DoS, amplifying C1. |
| **Evidence / Indicators** | No `MAX_CONTENT_LENGTH`; `request.get_data()` in OCSP; `uploaded.read()` before size check in `ca._get_pem_input`. |
| **References** | CWE-400, OWASP API4:2023. |
| **Remediation** | Set a conservative `MAX_CONTENT_LENGTH` (e.g., 256KB) app-wide; enforce a tight limit specifically on the OCSP body (a few KB). Reject oversized requests before reading. |

### [MEDIUM] — C3: PKCS#12 export password passed via GET query string

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `certificates.download` (`fmt=pkcs12`) |
| **Vulnerability Type** | Sensitive data in URL (CWE-598) |
| **Description** | The PKCS#12 export password is read from `request.args.get("password", "changeit")` — i.e., supplied in the URL query string. Query strings are recorded in server/proxy access logs, browser history, and `Referer` headers, disclosing the bundle password. It also defaults to the well-known weak value `changeit` if omitted. |
| **Who Can Exploit & Why It Works** | Anyone with access to logs, browser history, or referrer traffic obtains the P12 password (which protects an exported private key). |
| **Potential Impact** | Disclosure of the password guarding an exported private key; weak default renders the export near-plaintext. |
| **Evidence / Indicators** | `export_password = request.args.get("password", "changeit")`. |
| **References** | CWE-598, OWASP A09:2021. |
| **Remediation** | Accept the export password via POST body only (never URL), require it (no weak default), enforce minimum length, and consider not logging these routes. |

### [LOW-MEDIUM] — C4: Host-header injection into issued-certificate OCSP/CRL URLs

| Field | Details |
|---|---|
| **Severity** | Low-Medium (deployment-dependent) |
| **Affected Component** | `certificates.create`, `csr.sign` (`request.host` fallback) |
| **Vulnerability Type** | Host header injection (CWE-644) |
| **Description** | When `SERVER_NAME_FOR_OCSP` is at its default (`localhost:5000`), the AIA (OCSP) and CRL-DP URLs embedded into issued certificates are built from `request.host`. If the app trusts a client-supplied `Host` (no `SERVER_NAME` pinning, no proxy normalization), issued certificates can carry attacker-influenced OCSP/CRL URLs. |
| **Who Can Exploit & Why It Works** | An attacker able to influence the `Host` header on an issuance request (e.g., via a permissive proxy) poisons certificate metadata. Precondition: default config and untrusted Host reach the app. |
| **Potential Impact** | Issued certs point relying parties at attacker-controlled revocation endpoints (status spoofing, tracking, or DoS of validation). |
| **Evidence / Indicators** | `if ocsp_server == "localhost:5000": ocsp_server = request.host`. |
| **References** | CWE-644, OWASP "Host header attacks." |
| **Remediation** | Require an explicit `SERVER_NAME_FOR_OCSP` in production and do not fall back to `request.host`; validate `Host` against an allowlist; set Flask `SERVER_NAME` and have the proxy enforce a canonical host. |

### [LOW-MEDIUM] — C5: Open-redirect filter bypass via backslash

| Field | Details |
|---|---|
| **Severity** | Low-Medium |
| **Affected Component** | `auth._is_safe_url()` |
| **Vulnerability Type** | Open redirect (CWE-601) |
| **Description** | `_is_safe_url` allows any target starting with `/` and rejects `//`, but does not account for `/\`. A value like `/\evil.com` passes (`startswith("/")` true, `startswith("//")` false); several browsers normalize `\` to `/`, yielding `//evil.com` → protocol-relative redirect off-site after login. |
| **Who Can Exploit & Why It Works** | A phisher crafts a login link with a crafted `next`; the incomplete filter permits the backslash form. |
| **Potential Impact** | Post-login redirect to attacker site (credential/phishing pivot). |
| **Evidence / Indicators** | `return target.startswith("/") and not target.startswith("//")`. |
| **References** | CWE-601, OWASP A01:2021. |
| **Remediation** | Reject targets containing backslashes and control chars; prefer `urlsplit` and require empty scheme **and** empty netloc; or use Werkzeug's `url_has_allowed_host_and_scheme`. |

---

## D. Authentication & Authorization

### [MEDIUM] — D1: No rate limiting, lockout, or MFA on authentication

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `auth.login`, Basic Auth (`_setup_basic_auth`), rate-limit setup |
| **Vulnerability Type** | Missing brute-force protection (CWE-307) |
| **Description** | Login and Basic Auth have no lockout or throttling. Rate limiting is disabled by default and, when enabled, uses `storage_uri="memory://"` — per-worker and per-process, so limits are inconsistent across the 2 workers and reset on restart. No MFA is available for admins. |
| **Who Can Exploit & Why It Works** | An external attacker can brute-force credentials at network speed; the memory backend cannot enforce a global limit across workers. |
| **Potential Impact** | Credential compromise, especially given no password-complexity policy and default-admin risk (A4). |
| **Evidence / Indicators** | No lockout logic; `RATE_LIMIT_ENABLED=false` default; `storage_uri="memory://"`. |
| **References** | CWE-307, OWASP A07:2021, NIST SP 800-63B. |
| **Remediation** | Enable rate limiting by default with a shared backend (Redis); add progressive delays/lockout on repeated failures per-account and per-IP; add TOTP MFA for admins; enforce a password policy on user create/reset. |

### [MEDIUM] — D2: Schema migration escalates all pre-existing users to admin

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `_migrate_schema()` |
| **Vulnerability Type** | Privilege escalation via unsafe default (CWE-269) |
| **Description** | The role migration runs `ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'admin'`. Any user that existed before roles were introduced is assigned `role='admin'` on upgrade, contradicting the model's `csr_requester` default. An upgrade silently grants every legacy account full CA control. |
| **Who Can Exploit & Why It Works** | Existing low-trust accounts become admin automatically on migration — no operator action, no audit entry. |
| **Potential Impact** | Unintended admins with full CA/user/issuance authority. |
| **Evidence / Indicators** | `ADD COLUMN role ... DEFAULT 'admin'` in `_migrate_schema`. |
| **References** | CWE-269, CWE-1188. |
| **Remediation** | Default the added column to the least-privilege role (`csr_requester`) and require explicit promotion; or backfill roles deliberately with an audited step. Log migration-time role assignments. |

### [MEDIUM] — D3: Basic Auth enabled by default over plaintext; failed attempts flood the audit log

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `_setup_basic_auth`, `authenticate_basic_auth` |
| **Vulnerability Type** | Cleartext transmission / resource consumption (CWE-319, CWE-400) |
| **Description** | `BASIC_AUTH_ENABLED` defaults to true. With no TLS in the shipped stack (E1), Base64 credentials traverse the network in the clear. Separately, `check_basic_auth` runs on **every request**; each failed attempt writes a `basic_auth_failed` audit row and commits, and performs a password-hash (or dummy hash) computation — so an unauthenticated attacker can flood the audit table and the DB with commits, and burn CPU, with no throttle. |
| **Who Can Exploit & Why It Works** | Passive sniffers (plaintext creds) and active attackers (audit/disk/CPU flooding) — Basic Auth is on by default and unthrottled. |
| **Potential Impact** | Credential interception; audit-log flooding that both fills disk and drowns real events; CPU pressure feeding C1. |
| **Evidence / Indicators** | `BASIC_AUTH_ENABLED` default true; per-request `log_action("basic_auth_failed"); db.session.commit()`. |
| **References** | CWE-319, CWE-400, OWASP A02/A09:2021. |
| **Remediation** | Require TLS whenever Basic Auth is enabled (refuse to enable it without `SESSION_COOKIE_SECURE`/HTTPS); rate-limit and coalesce repeated failures; consider logging failed Basic Auth at a sampled rate or to a separate, size-bounded store. |

### [LOW] — D4: No multi-party authorization for sensitive CA operations

| Field | Details |
|---|---|
| **Severity** | Low (High from a compliance standpoint) |
| **Affected Component** | CA create/revoke, CSR sign, key export |
| **Vulnerability Type** | Missing separation of duties (CWE-653) |
| **Description** | Any single `admin` can create/revoke CAs, sign CSRs, and export private keys. There is no dual-control ("m-of-n") for high-impact operations, no distinction between a CA operator and a certificate-issuance operator. |
| **Who Can Exploit & Why It Works** | One compromised or malicious admin account is sufficient for catastrophic actions. |
| **Potential Impact** | Single-actor CA compromise or mass mis-issuance. |
| **Evidence / Indicators** | `@admin_required` gates all sensitive routes with no second approver. |
| **References** | CA/B BR §5 (trusted roles, multi-person control), NIST SP 800-57 Pt.2, CWE-653. |
| **Remediation** | Introduce role separation and dual-control/approval workflows for CA key generation, sub-CA issuance, revocation, and key export. Combine with per-operation re-authentication. |

### [LOW] — D5: Default-admin creation race and non-rotating admin password

| Field | Details |
|---|---|
| **Severity** | Low |
| **Affected Component** | `_create_default_admin`, startup path |
| **Vulnerability Type** | Race condition / operational (CWE-362) |
| **Description** | `create_app()` (run by both `entrypoint.sh` and each Gunicorn worker) does check-then-insert on the admin user; concurrent workers can both see zero users and race on the unique username. Also, `ADMIN_PASSWORD` only seeds the first boot — changing it later does not update the stored hash. |
| **Who Can Exploit & Why It Works** | Not attacker-driven; a startup race can crash a worker, and stale admin credentials persist. |
| **Potential Impact** | Startup flakiness; operators falsely believe rotating the env changes the password. |
| **Evidence / Indicators** | `if User.query.count() == 0: ... add(admin)` without locking; seeding only on empty table. |
| **References** | CWE-362. |
| **Remediation** | Do first-boot seeding in a single init step (entrypoint) guarded by a transaction/unique-constraint catch, not in every worker. Document that `ADMIN_PASSWORD` seeds once; provide a rotation path. |

---

## E. Data in Transit

### [HIGH] — E1: No TLS in the shipped stack; secure-transport defaults are insecure

| Field | Details |
|---|---|
| **Severity** | High (as-shipped) |
| **Affected Component** | `entrypoint.sh` (Gunicorn), `docker-compose.yml`, `Config` |
| **Vulnerability Type** | Cleartext transmission (CWE-319) |
| **Description** | Gunicorn binds plain HTTP on `0.0.0.0:5000`; compose publishes `5000:5000` with no TLS terminator. `SESSION_COOKIE_SECURE` defaults false and `OCSP_URL_SCHEME` defaults `http`. As delivered, sessions, Basic Auth credentials, uploaded private keys (CA import), and downloaded keys traverse the network unencrypted unless the operator adds an external reverse proxy — which is neither provided nor required by the compose. |
| **Who Can Exploit & Why It Works** | Any network-path observer/MITM captures credentials, session cookies, and key material because transport is unencrypted by default. |
| **Potential Impact** | Session hijacking, credential theft, private-key interception. |
| **Evidence / Indicators** | `--bind 0.0.0.0:5000` (no certs); `SESSION_COOKIE_SECURE` default false; `OCSP_URL_SCHEME` default http. |
| **References** | CWE-319, OWASP A02:2021, CA/B BR (repository over HTTPS). |
| **Remediation** | Ship a TLS-terminating reverse proxy (Caddy/nginx) in the compose or document it as mandatory; default `SESSION_COOKIE_SECURE=true` and `OCSP_URL_SCHEME=https` for production; add HSTS. Refuse Basic Auth without HTTPS. |

### [LOW] — E2: Runtime CDN dependency; no Content-Security-Policy

| Field | Details |
|---|---|
| **Severity** | Low |
| **Affected Component** | `templates/base.html`, response headers |
| **Vulnerability Type** | Third-party runtime dependency / missing hardening (CWE-829, CWE-693) |
| **Description** | Bootstrap CSS/JS is loaded from jsDelivr. SRI `integrity` hashes are present and correct, and templates have no `\|safe`/DOM-XSS sinks (the `innerHTML` uses assign constant strings), so client-side risk is low. Residual items are a missing Content-Security-Policy header and a runtime/privacy dependency on an external CDN. |
| **Who Can Exploit & Why It Works** | Defense-in-depth gap; not directly exploitable given autoescaping + SRI. |
| **Potential Impact** | Reduced XSS containment; availability/privacy dependency on a third party. |
| **Evidence / Indicators** | `cdn.jsdelivr.net` `<link>`/`<script>` with `integrity=`; no CSP header set in `_setup_security_headers`. |
| **References** | CWE-829, OWASP A05:2021, MDN CSP. |
| **Remediation** | Add a strict `Content-Security-Policy` (and `Referrer-Policy`, `Permissions-Policy`, HSTS); self-host Bootstrap to remove the external dependency. |

---

## F. Runtime Security

### [MEDIUM] — F1: Sensitive key material is not zeroizable and is memory-resident

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `crypto_utils`, all services handling `passphrase`/decrypted keys |
| **Vulnerability Type** | Sensitive data in memory (CWE-316/CWE-226) |
| **Description** | Passphrase and decrypted private keys are handled as Python `str`/`bytes` (immutable) and cannot be securely wiped; they persist in the heap until GC and may reach swap or core dumps. The master passphrase is resident for the whole process lifetime. Python offers no reliable zeroization, so this is a design constraint to mitigate, not eliminate. |
| **Who Can Exploit & Why It Works** | An attacker with a memory-read primitive, a core dump, or swap access recovers keys/passphrase. |
| **Potential Impact** | CA key/passphrase disclosure via memory forensics. |
| **Evidence / Indicators** | `passphrase.encode()`, `key_pem` bytes, `decrypt_private_key` return values held in locals. |
| **References** | CWE-316, NIST SP 800-57 (key zeroization). |
| **Remediation** | Minimize key lifetime (decrypt just-in-time, drop references promptly); disable core dumps (`RLIMIT_CORE=0`) and swap for the service (or encrypt swap); prefer an HSM/KMS so plaintext keys never enter the Python heap (ties A1). |

### [MEDIUM] — F2: Debug mode exposes the Werkzeug debugger and disables the insecure-default guard

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `_check_security` (`if ... app.debug: return`), documented `flask run --debug` |
| **Vulnerability Type** | Dangerous debug feature (CWE-489) |
| **Description** | `_check_security()` returns early when `app.debug` is true, so running in debug disables rejection of insecure default `SECRET_KEY`/`MASTER_PASSPHRASE`/`ADMIN_PASSWORD`. The documented dev command (`flask --app "app:create_app()" run --debug`) additionally enables the interactive Werkzeug debugger, which permits arbitrary code execution if the console is reachable. |
| **Who Can Exploit & Why It Works** | If a debug instance is ever bound to a non-loopback interface, an attacker reaching it can execute code via the debugger and benefits from unguarded weak secrets. |
| **Potential Impact** | RCE and full compromise in a misdeployed debug instance. |
| **Evidence / Indicators** | Early `return` on `app.debug`; `--debug` in docs. |
| **References** | CWE-489, OWASP A05:2021. |
| **Remediation** | Never bind debug to non-loopback; keep the insecure-default guard active even in debug (or gate strictly on an explicit `FLASK_ENV=development` + loopback assertion). Document that `--debug` is local-only. |

### [LOW] — F3: Non-atomic CRL number increment

| Field | Details |
|---|---|
| **Severity** | Low |
| **Affected Component** | `generate_crl` (`ca.crl_number += 1`) |
| **Vulnerability Type** | Race condition (CWE-362) |
| **Description** | `crl_number` is incremented via read-modify-write in application code; two workers generating a CRL concurrently can produce duplicate or non-monotonic CRL numbers, violating RFC 5280 monotonicity expectations. |
| **Who Can Exploit & Why It Works** | Concurrency (including the unauthenticated cache-miss path in C1) rather than a targeted attacker. |
| **Potential Impact** | CRL numbering anomalies; relying-party confusion. |
| **Evidence / Indicators** | `ca.crl_number += 1` with no atomic update/lock. |
| **References** | RFC 5280 §5.2.3, CWE-362. |
| **Remediation** | Use an atomic DB update (`UPDATE ... SET crl_number = crl_number + 1 RETURNING`) or a row lock; serialize CRL generation. |

---

## G. Logging, Monitoring & Audit Integrity

### [MEDIUM] — G1: Audit log is not tamper-evident, and there is no anomaly alerting

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `AuditLog` model, `audit_service`, storage |
| **Vulnerability Type** | Insufficient log protection (CWE-778/CWE-117) |
| **Description** | Audit entries live in the same writable SQLite DB as operational data with no hash-chaining, signing, append-only/WORM storage, or off-box shipping. An admin (or anyone with DB write access — see A2) can silently modify or delete records, including the very entries that would record CA key exports or mis-issuance. There is no alerting on anomalous signing volume or off-hours issuance. |
| **Who Can Exploit & Why It Works** | A malicious admin or DB-level attacker erases their tracks because logs are mutable and co-located. |
| **Potential Impact** | Undetectable CA misuse; failed forensics; compliance failure for a CA. |
| **Evidence / Indicators** | Plain `AuditLog` table; no integrity fields; no external log sink. |
| **References** | CA/B BR §5.4 / WebTrust (audit log integrity & retention), NIST SP 800-92, CWE-778. |
| **Remediation** | Hash-chain audit records (each row includes a hash of the prior), or sign them; ship logs append-only to an external system (syslog/SIEM) in real time; separate log storage from the app DB; add alerts for high-risk actions (key export, CA revoke, sign spikes). |

### [LOW] — G2: `remote_addr` used without `ProxyFix`

| Field | Details |
|---|---|
| **Severity** | Low |
| **Affected Component** | `audit_service.log_action` (`request.remote_addr`), rate-limit key func |
| **Vulnerability Type** | Inaccurate attribution (CWE-348) |
| **Description** | With no `ProxyFix`/trusted-proxy config, behind a reverse proxy every audit entry and rate-limit key records the proxy's IP (e.g., 127.0.0.1) rather than the real client, blinding both audit trails and per-IP throttling. Naively trusting `X-Forwarded-For` instead would be spoofable — the fix must trust only known proxies. |
| **Who Can Exploit & Why It Works** | Attackers gain anonymity in logs and evade per-IP limits when the app can't see the true source. |
| **Potential Impact** | Weak attribution and ineffective IP-based defenses. |
| **Evidence / Indicators** | `request.remote_addr` used directly; no `ProxyFix` (verified). |
| **References** | CWE-348, Werkzeug `ProxyFix` docs. |
| **Remediation** | Apply `werkzeug.middleware.proxy_fix.ProxyFix` with the correct hop count, and only trust the specific proxy; then derive client IP from the corrected value. |

---

## H. Container & Infrastructure

### [MEDIUM] — H1: Container runs as root with no runtime hardening

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `Dockerfile`, `docker-compose.yml` |
| **Vulnerability Type** | Excessive privilege (CWE-250) |
| **Description** | The Dockerfile defines no `USER`, so Gunicorn and app code run as root inside the container. Compose sets no `read_only`, `cap_drop`, `security_opt: no-new-privileges`, `user:`, or resource limits (`mem_limit`/`pids_limit`/CPU). A code-exec or file-write bug runs with root in-container, and any container breakout starts as root; the DoS in C1 has no cgroup ceiling. |
| **Who Can Exploit & Why It Works** | An attacker who achieves code execution or a write primitive inherits root and an unconstrained resource budget. |
| **Potential Impact** | Easier privilege escalation/breakout; unbounded resource abuse. |
| **Evidence / Indicators** | No `USER` in Dockerfile; no hardening keys in compose. |
| **References** | CIS Docker Benchmark, CWE-250, NIST SP 800-190. |
| **Remediation** | Add a non-root `USER` (create a UID, `chown` `/app/data` to it, `chmod 700`); set `read_only: true` with a tmpfs for scratch, `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]`, and memory/PID/CPU limits. Add a `HEALTHCHECK`. |

### [LOW-MEDIUM] — H2: Base image pinned by mutable tag; no image vulnerability scanning

| Field | Details |
|---|---|
| **Severity** | Low-Medium |
| **Affected Component** | `Dockerfile` (`FROM python:3.13-slim`), CI |
| **Vulnerability Type** | Supply chain / unpatched components (CWE-1104, CWE-1035) |
| **Description** | The base image is referenced by the mutable tag `python:3.13-slim` (not a digest), so builds are non-reproducible and subject to tag drift; there is no Trivy/Grype scan of the resulting image in CI. |
| **Who Can Exploit & Why It Works** | A registry/tag-mutation or upstream-vuln scenario introduces vulnerable OS packages without detection. |
| **Potential Impact** | Shipping known-vulnerable base packages; non-reproducible builds. |
| **Evidence / Indicators** | `FROM python:3.13-slim`; no scan step in `docker-publish.yml`. |
| **References** | CWE-1104, NIST SP 800-190, SLSA. |
| **Remediation** | Pin the base image by digest (`python:3.13-slim@sha256:...`) and update deliberately; add image scanning (Trivy) and dependency review to CI, failing on high/critical. |

---

## I. Dependency & Supply Chain

### [MEDIUM] — I1: No dependency integrity pinning

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `requirements.txt`, Docker build |
| **Vulnerability Type** | Unverified third-party integrity (CWE-494, CWE-829) |
| **Description** | Top-level versions are pinned, but there are no artifact hashes (`--require-hashes`) and no lockfile capturing transitive dependencies (e.g., Werkzeug, Jinja2, click, cffi are unpinned). `pip install` therefore trusts whatever PyPI serves for the resolved transitive set at build time, with no integrity verification. This is the layer most relevant to a PKI system's supply-chain threat model. |
| **Who Can Exploit & Why It Works** | A PyPI compromise, dependency-confusion, or typosquat on a transitive package can inject code into the image, since nothing verifies content hashes. |
| **Potential Impact** | Malicious code in the CA runtime → key theft / mis-issuance. |
| **Evidence / Indicators** | `requirements.txt` has versions but no hashes; no `requirements.lock`/`pip-tools`/`poetry.lock`. |
| **References** | CWE-494/829, OWASP A06:2021, pip hash-checking mode. |
| **Remediation** | Generate a fully pinned, hashed lock (`pip-compile --generate-hashes` or `uv pip compile`) covering transitive deps and build with `--require-hashes`. Enable Dependabot/renovate for controlled updates. |

### [LOW-MEDIUM] — I2: No software-composition/vulnerability scanning in CI

| Field | Details |
|---|---|
| **Severity** | Low-Medium |
| **Affected Component** | CI pipeline |
| **Vulnerability Type** | Missing detection control (CWE-1035) |
| **Description** | The workflow builds and pushes images but runs no `pip-audit`/OSV/Dependabot or container scan, so known-vulnerable dependencies ship undetected. |
| **Who Can Exploit & Why It Works** | Latent known-CVE dependencies remain in the image with no gate to catch them. |
| **Potential Impact** | Latent known-CVE exposure in a high-value system. |
| **Evidence / Indicators** | `docker-publish.yml` has no scanning step. |
| **References** | OWASP A06:2021, NIST SSDF PW.4. |
| **Remediation** | Add `pip-audit`/OSV-Scanner and Trivy jobs; fail on high/critical; schedule periodic re-scans (dependencies gain CVEs after build). |

---

## J. CI/CD Pipeline

### [MEDIUM] — J1: GitHub Actions pinned by mutable tags, not commit SHAs

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | `.github/workflows/docker-publish.yml` |
| **Vulnerability Type** | Supply-chain / mutable dependency (CWE-829) |
| **Description** | Actions are referenced by mutable major tags (`actions/checkout@v4`, `docker/login-action@v3`, `docker/build-push-action@v6`, etc.). Tags can be repointed by a compromised action maintainer, and the job holds `packages: write` and the registry token — so a hijacked action can exfiltrate `GITHUB_TOKEN` or poison the published image. |
| **Who Can Exploit & Why It Works** | A compromised third-party action author or a tag-move; the pipeline trusts tags rather than immutable commit SHAs. |
| **Potential Impact** | Poisoned `ghcr.io/guidorugo/cert-manager` image consumed by deployers → CA runtime compromise. |
| **Evidence / Indicators** | `uses: ...@v4/@v3/@v6` throughout the workflow. |
| **References** | CWE-829, SLSA, GitHub "Security hardening for Actions." |
| **Remediation** | Pin every action to a full commit SHA (with a comment noting the version) and update via Dependabot; set `permissions:` to the minimum per job. |

### [MEDIUM] — J2: No image signing, provenance, or SBOM for published images

| Field | Details |
|---|---|
| **Severity** | Medium |
| **Affected Component** | CI publish step |
| **Vulnerability Type** | Missing artifact integrity/authenticity (CWE-345) |
| **Description** | Published GHCR images are neither signed (cosign) nor accompanied by SLSA provenance or an SBOM, so deployers cannot verify authenticity or contents of `:latest`. |
| **Who Can Exploit & Why It Works** | A registry tamper or man-in-the-middle image swap is undetectable by consumers with no signature to verify. |
| **Potential Impact** | Deployment of tampered images of a trust-critical service. |
| **Evidence / Indicators** | No `cosign`/attestation/SBOM steps. |
| **References** | SLSA v1.0, Sigstore/cosign, NIST SSDF. |
| **Remediation** | Sign images with cosign (keyless OIDC), generate SLSA provenance (`docker/build-push-action` attestations) and an SBOM (syft), and document verification for deployers. Avoid relying on a mutable `:latest` for production. |

> Note (J3): the `packages: write` token scope is appropriate and PR builds are correctly build-only with no push; least-privilege `permissions` per job is still recommended (folded into J1).

---

## K. Error Handling & Information Disclosure

Routes consistently catch broad `Exception`, log full traces server-side via `current_app.logger.exception`, and return generic user-facing messages (no stack traces or internal detail leak to clients) — this is a **positive** control. The residual risk is entirely tied to F2 (debug mode would expose the interactive traceback). No cryptographic-oracle behavior was identified in the OCSP/CRL/Fernet paths (Fernet raises a single opaque `InvalidToken`; the app returns a generic 500). No SQL injection (SQLAlchemy ORM with parameterized queries; the only raw SQL is static DDL in `_migrate_schema`), no `subprocess`/`os.system`, and no `pickle`/`yaml.load` deserialization were found. **Keep debug disabled in production (F2)** and ensure logs don't capture request bodies containing private keys.

---

## L. Compliance Gaps (Consolidated)

| Standard | Gap | Related Findings |
|---|---|---|
| CA/B BR §6.2 / NIST SP 800-57 Pt.2 | No HSM/FIPS-validated key protection; keys protected by env-var passphrase; no offline root, key ceremony, or split knowledge | A1, D4, F1 |
| CA/B BR §4.9 / RFC 5280 §5 | Revocation not reliably published (stale CRL; sub-CAs absent from CRL); OCSP replay/no nonce | B2, B3, B6 |
| RFC 2986 / RFC 4211 | Proof-of-possession not enforced on CSR signing | B1 |
| CA/B BR §6.3.2 / §7.1 | Validity not capped (>398d possible); no Name Constraints; unlimited path length | B4 |
| CA/B BR §6.1.5 / NIST SP 800-57 | Weak key sizes accepted | B5 |
| CA/B BR §5.4 / WebTrust | Audit log not tamper-evident, not externally retained, no anomaly monitoring | G1 |
| CA/B BR §5 | No separation of duties / multi-person control for CA operations | D4 |

**Remediation:** define and enforce a Certificate Policy/CPS, adopt an offline root with an online issuing intermediate, move CA keys to an HSM/KMS, enforce POP and issuance-profile limits server-side, make revocation publication reliable and monitored, and implement tamper-evident, externally-retained audit logging with role separation.

---

## Positive Controls Observed

The application shows real security investment; these controls are working and should be preserved:

- 600k-iteration PBKDF2-HMAC-SHA256 key derivation with per-encryption random salt; Fernet (AES-128-CBC + HMAC-SHA256) for key-at-rest.
- Insecure-default startup guard (`_check_security`) for `SECRET_KEY`/`MASTER_PASSPHRASE`/`ADMIN_PASSWORD` (with the debug caveat, F2).
- Role-based access control with ownership enforcement (`csr_requester` sees only its own CSRs/certs) and last-admin guards on demote/deactivate.
- CSRF protection (with a deliberate, documented bypass only for valid Basic Auth).
- Login timing-attack mitigation (dummy hash for nonexistent users) and username-in-log sanitization.
- Security headers (`X-Content-Type-Options`, `X-Frame-Options`); SRI on CDN assets; open-redirect protection (partial, see C5).
- Parameterized ORM access (no SQL injection); no `subprocess`/`pickle`/`yaml.load`; Jinja autoescaping on with no `|safe` sinks.
- Correct X.509 construction: 160-bit random serials, SHA-256 signatures, `BasicConstraints`/`KeyUsage` set correctly for leaf (`ca=False`, no `key_cert_sign`) vs CA; import validates key/cert match and CA basic constraints; PEM size guards on import.

---

## Executive Risk Summary

The cert-manager application shows real security investment — 600k-iteration PBKDF2 key derivation, Fernet encryption of keys at rest, an insecure-default startup guard, role-based access with ownership checks and last-admin guards, CSRF protection, login timing-attack mitigation, parameterized ORM access (no SQL injection), autoescaped templates (low XSS), and generic error handling. However, for a system whose entire value is the confidentiality of CA private keys and the integrity of issuance and revocation, several structural weaknesses undercut that foundation. The crown-jewel risk is key protection: every CA key is guarded by a single environment-variable passphrase co-located with the process and a world-readable database, so any host-level read primitive yields total CA compromise — with no HSM, key hierarchy, or separation of duties as a backstop. The PKI logic has three high-impact correctness gaps that defeat core controls: CSR signatures are never verified (mis-issuance), and revocation fails to propagate to CRLs for both certificates and intermediate CAs (revoked certs stay trusted). The unauthenticated OCSP endpoint amplifies the deliberately-slow KDF into a trivial denial-of-service against the whole service, and the shipped stack terminates no TLS, exposing credentials and key material in transit. Supply-chain and CI integrity (unpinned actions/base image, no signing, no hash-locked dependencies) leave the published image forgeable. The consequence of inaction is a credible path from a modest foothold — a leaked backup, a co-located container, a network vantage point, or a tampered dependency — to full compromise of the trust anchor and every certificate that depends on it, with a mutable audit log that would not reliably record the abuse.

## Prioritized Remediation Roadmap

### Immediate (0–2 weeks) — critical/blocking
- Rotate the exposed Forgejo credential and remove it from `.git/config`; switch to SSH or a credential helper over HTTPS (A3).
- Lock down storage: `chmod 600` the SQLite DB, own it by a non-root service user, encrypt backups (A2, H1).
- Fix the OCSP/CRL DoS: cache the decrypted CA key, make CRL fetch read-only (pre-generate on a schedule), and enable rate limiting on `/public/*` with a shared backend; add `MAX_CONTENT_LENGTH` and a tight OCSP body cap (C1, C2, F3).
- Enforce CSR proof-of-possession (`is_signature_valid`) and a key-size floor at signing/creation (B1, B5).
- Make revocation reliable: regenerate/invalidate CRLs on cert **and** sub-CA revocation, and include revoked sub-CAs in the parent CRL (B2, B3).
- Require TLS and flip secure defaults for production (`SESSION_COOKIE_SECURE`, `OCSP_URL_SCHEME=https`); refuse Basic Auth without HTTPS (E1, D3).
- Remove insecure defaults / `admin:admin` from examples and compose; require secrets with no fallback and a minimum-entropy check; keep the guard active in debug (A4, F2).

### Short-term (1–3 months) — high severity & foundational hardening
- Fix the migration privilege escalation (default new `role` to least privilege) and audit current role assignments (D2).
- Run the container as non-root with `cap_drop`, `no-new-privileges`, read-only rootfs, and resource limits; add a healthcheck (H1).
- Add rate limiting/lockout by default (shared backend), a password policy, and admin MFA (D1); apply `ProxyFix` for correct client IPs (G2).
- Move export passwords out of URLs; require strong export passwords (C3). Harden the open-redirect filter (C5) and pin `SERVER_NAME_FOR_OCSP` in production (C4). Add CSP/HSTS and self-host Bootstrap (E2).
- Enforce issuance-profile limits server-side: max validity (≤398d for TLS), `not_after ≤ CA.not_after`, sane path length, optional Name Constraints (B4).
- Stop escrowing subscriber private keys by default (A5).

### Medium-term (3–6 months) — systematic improvements & tooling
- Introduce KMS/HSM-backed CA key operations (SoftHSM/PKCS#11 → hardware HSM), or at minimum per-CA HKDF-derived wrapping keys sourced from a secrets manager (A1, F1).
- Make audit logging tamper-evident (hash-chaining/signing), ship it to an external append-only store, and add anomaly alerting on high-risk actions (G1).
- Harden the supply chain: hash-locked dependencies with `--require-hashes`, digest-pinned base image, SHA-pinned CI actions, image signing (cosign) + SLSA provenance + SBOM, and Trivy/pip-audit gates (I1, I2, H2, J1, J2).
- Add a delegated OCSP-signing certificate with nonce support (B6).

### Long-term (ongoing) — continuous practices & compliance
- Adopt an offline-root / online-issuing-intermediate architecture with documented key-ceremony, split-knowledge, and disaster-recovery procedures; implement separation of duties and dual-control for CA key generation, sub-CA issuance, revocation, and key export (D4, L).
- Formalize a Certificate Policy/CPS aligned to CA/Browser Forum BRs, RFC 5280, and NIST SP 800-57; schedule periodic dependency/image re-scans, key-rotation drills, revocation tests, and audit-log reviews.

---

*Two live-secret items should be rotated regardless of code changes: the Forgejo password in `.git/config` and the values in `.env`.*
