# Chancery v2.12.3 — Independent Security & Correctness Assessment

> **Assessment date:** 2026-08-29 · **Target:** `guidorugo/chancery` at `db182cd` (v2.12.3, `master`) + live instance `http://10.0.0.82:5000` (`chancery-app-1`, image built from HEAD on 2026-08-27).
> **Method:** full read of every file in all 25 areas (7,791 app lines, 26 templates, 42 test modules, infra/CI/docs/prior reports), read-only live inspection (`docker inspect/top/exec -u app`, SQLite opened `mode=ro`, `openssl` verification of live CRL/OCSP/chains), executable PoCs against an **in-memory** app instance (nothing on the live box was mutated), full test-suite run, OSV + Trivy scans. Every "Confirmed" finding below was either reproduced or read verbatim in the cited lines.
> **Independence caveat:** produced by Claude (Fable 5) on the owner's request; the code was also AI-assisted. Not a third-party audit.

---

## Phase 0 — Scope confirmation & blocking questions

**Repo access:** confirmed. Working tree clean except two untracked dev files (`scripts/seed_demo.py`, `scripts/seed_demo.sh`). 240 commits, tags through `v2.12.3`.

**Live access:** confirmed. `GET /health` → 200; container `Up 18h (healthy)`.

**Deployment facts verified on the box (these supersede the pre-answered assumptions where they differ):**

| Item | Verified value |
|---|---|
| Gunicorn | `--workers 2 --timeout 120`, sync workers, no `--preload` (`entrypoint-app.sh:52-56`, `docker top`) |
| Process identity | PID 1 = gunicorn, uid 1000 (`/proc/1/status`); `cap_drop ALL` + `CHOWN,SETUID,SETGID`; `no-new-privileges`; rootfs **rw** |
| Network | `0.0.0.0:5000` and `[::]:5000` published; plain HTTP; no proxy (`TRUSTED_PROXY_COUNT=""` → 0) |
| Security env | `SESSION_COOKIE_SECURE=false`, `SERVER_NAME_FOR_OCSP=localhost:5000` (**default → Host auto-detect active**), `OCSP_URL_SCHEME` default `http`, `RATE_LIMIT_ENABLED=true`, Basic Auth on (default), `DUAL_CONTROL_ENABLED=false`, `LDAP_ENABLED=false`, `WEBHOOK_ENABLED=false`, `METRICS_ENABLED=true` (bearer token required; 1 active token), `UPDATE_CHECK_ENABLED=true`, `KEY_BACKEND=software` |
| Secrets | `MASTER_PASSPHRASE_FILE`, `PKCS11_USER_PIN_FILE`, `PKCS11_SO_PIN_FILE` via Docker secrets (host files 0600 uid 1000; **14 / 32 / 8 bytes** respectively); `SECRET_KEY` (24 chars) and `ADMIN_PASSWORD` (14 chars) as **env literals** |
| Data | `data/` 0700, DB 0600 uid 1000; SoftHSM token dir 0700, exactly one `cert-manager` token; 4 `cert-manager.db.bak-*` files in `data/` |
| DB contents | 13 CAs (3 HSM-backed: `test 4`, `home inter`, `Demo HSM Issuing CA`; 3 revoked), 20 certs (18 with escrowed keys, 6 revoked), 6 CSRs, **1 user (`admin`, scrypt, password already rotated)**, 107 audit rows, 0 LDAP/webhook rows |
| Runtime versions | Python **3.14.7** (profile said 3.13), SQLAlchemy **2.0.52**, cryptography 50.0.0, Flask 3.1.3, gunicorn 26.2.0 |
| Prior assessments | **three** on disk (10-07, 05-08, 08-08), not two; reconciled against all three in Phase 2 §F |

**Blocking questions:** none — every §12 item was pre-answered and could be verified. Owner-knowledge questions that change a severity are consolidated in Phase 2 §C (chiefly: the entropy source of the pre-generator master passphrase / `SECRET_KEY`, and whether any relying party actually performs CRL/OCSP checks).

---

## Phase 1 — Per-area passes (risk order: 4, 5, 6, 7, 8, then 1–3, 9–25)

Finding IDs are `G<area>-<n>`. Severity uses the CA-calibrated rubric from the mandate.

### Area 4 — Crypto & PKI core

Files read in full: `app/services/{crypto_utils,policy,ca_service,cert_service,csr_service,crl_service,ocsp_service}.py` plus their call sites.

**Checklist verdicts (verified, cited):**
- KDF/at-rest: `PBKDF2HMAC(SHA256, length=32, salt, iterations=600_000)` (`crypto_utils.py:13-20`), 16-byte `os.urandom` salt per encryption stored as prefix (`:9,:33-37`), Fernet (authenticated); wrong passphrase → opaque `InvalidToken`. No key material appears in any log/exception string (grepped `print/logger` sites: only the three FATAL messages, values never printed).
- Serials: `x509.random_serial_number()` everywhere (`ca_service.py:74,178`; `cert_service.py:84,265`) — pyca 159-bit positive random; leaf serials `unique=True` (`models/certificate.py:11`).
- Signature digest: SHA-256 only (`software.py:22-23`; HSM `softhsm.py:94,97-99`).
- Leaf constraints: `BasicConstraints(ca=False)` critical and `key_cert_sign=False, crl_sign=False` hard-coded on **both** KU branches (`cert_service.py:94-97,121-122,136-137,275-278,302-303,317-318`). Only `csr.subject`/`csr.public_key()` are consumed (`:88-90`); CSR-requested extensions are never copied → a CSR asking `CA:TRUE`/`keyCertSign` cannot obtain it.
- CSR proof-of-possession: `if not csr.is_signature_valid: raise ValueError(...)` at the signing call site (`cert_service.py:73-74`); the route calls that function (`csr.py:234`). Tampered-CSR test exists (`tests/test_hardening_1_1_0.py:39-62`).
- Validity: `bounded_not_after` rejects `<1`, caps at `MAX_*_VALIDITY_DAYS`, clamps to issuer `notAfter` (`policy.py:48-68`); expired-issuer refusal (`cert_service.py:80-82,261-263`); stored `not_after` is the real clamped value (`:226,:390`).
- Revocation propagation: cert revoke → commit → `refresh_crl` (`crl_service.py:44-52`); CA revoke cascades, then refreshes the **parent** CRL and each revoked CA's CRL (`:63-98`); parent CRL lists revoked sub-CAs (`:151-154`); OCSP resolves sub-CA rows (`ocsp_service.py:114-118`). Live: `Demo Compromised CA` CRL has 1 entry; `Demo Issuing CA` CRL has 3.
- CRL number: atomic SQL increment then re-read inside the same transaction (`crl_service.py:117-124`); SQLite's single-writer lock serialises the two workers, so numbers are monotonic (test `test_hardening_quickwins.py:86-98`).
- OCSP: request parsed and subject looked up **before** any key use (`ocsp_service.py:105-122`); keyless/pending/unknown → unsigned `UNAUTHORIZED` (`:91-95,:102-103,:121-122`); CertID hash mirrored from the request with an allow-list (`:57-76`); responder byKey; response cache keyed on `(ca, serial, is_revoked, alg)` (`:127`). Live: software CA `Home` and HSM CA 13 both answer `Response verify OK` (see Area 5).
- Encoding/injection: subject built through pyca `NameAttribute` with field-named validation (`policy.py:88-113`); `DNSName` is ASCII-only in pyca; IPs via `ipaddress` (`cert_service.py:34-36`); nothing user-controlled reaches DER unescaped.

```
[ID]  G4-1
Title:            Published CRLs expire 7 days after generation with no in-app refresh — every live CRL is expired today
Category:         Both
Severity:         High — revocation via CRL is non-functional cluster-wide right now; strict validators hard-fail, lenient ones ignore revocation
Confidence:       Confirmed (code + live)
Status vs prior:  Regressed — 08-08 PKI-1 was closed by adding `flask crl refresh` "cron-friendly"; the cron half was never deployed
Location:         crl_service.py:129-130  `.last_update(now)` / `.next_update(now + timedelta(days=validity_days))`
                  config.py:73            `CRL_VALIDITY_DAYS = int(os.environ.get("CRL_VALIDITY_DAYS") or "7")`
                  public.py:29-37         serves `ca.crl_pem` verbatim, never regenerates
                  cli.py:237-268          `crl refresh` is the only refresh path (a CLI)
Preconditions:    none (observed live)
Description:      The app stamps nextUpdate = now+7d and has no scheduler; the only refresh is an operator cron running the CLI.
                  On the live box: all 12 CRLs show nextUpdate 2026-08-24 12:07Z (CA 5: 08-13, CA 12: 08-18) against now = 2026-08-29;
                  last regeneration was a one-off on 2026-08-17. `crontab -l`, `/etc/cron.d`, `systemctl list-timers` contain no chancery job.
Impact / attack:  Every issued cert carries a CDP pointing at these CRLs. OpenSSL-style validators return X509_V_ERR_CRL_HAS_EXPIRED
                  (outage); soft-fail validators skip revocation entirely (a revoked leaf keeps working). OCSP is unaffected (24 h fresh).
Reproduction:     curl -s http://10.0.0.82:5000/public/crl/3.crl | openssl crl -inform DER -noout -nextupdate  →  nextUpdate=Aug 24 12:07:46 2026 GMT
Recommended fix:  Now: `docker compose exec -u app app flask crl refresh --all` and a host cron/systemd timer (note `-u app`, see G20-1).
                  Code: regenerate lazily on the public serve path when now ≥ nextUpdate − margin (single-flight via a DB flag so one worker
                  signs), or a background refresher; raise the default window; alert on the existing
                  `chancery_ca_crl_next_update_timestamp_seconds` metric (Prometheus is already scraping it).
Open questions:   Which relying parties consume the CRLs? Was a cron ever intended on this host?
```

```
[ID]  G4-2
Title:            A sub-CA can be created under a REVOKED parent; the child is signing-capable and issues leaves
Category:         Both
Severity:         Medium — issuance continues under a revoked hierarchy (admin-only, and validators that walk to the parent's CRL still catch it)
Confidence:       Confirmed (PoC)
Status vs prior:  New
Location:         ca.py:186-199      `parent_ca = db.session.get(CertificateAuthority, parent_ca_id)` … `if not parent_ca:` (only existence)
                  ca_service.py:147-150  `if not parent_ca.has_signing_key: raise …` / `if parent_ca.approval_status == "pending": raise …`
                  (contrast certificates.py:92-93 and csr.py:194-195, which do check `ca.is_revoked`)
                  models/ca.py:82-85 `signing_capable()` filters only the child's own `is_revoked`
Preconditions:    admin credentials (or a stolen admin session — see G6-1)
Description:      Neither the route nor the service checks `parent_ca.is_revoked` (nor expiry, see G4-6). The UI dropdown hides revoked
                  parents (`_create_page_context`, ca.py:46-50) but the server accepts any `parent_id`.
Impact / attack:  PoC: revoke root R1 → POST /ca/create parent_id=R1 → 201; child.is_revoked=False, in signing_capable(); POST
                  /certificates/create from child → 201. New leaves' AIA/CDP point at the new intermediate, whose OCSP says GOOD.
                  A CA-compromise response ("revoke the CA") therefore does not stop issuance by whoever holds admin.
Reproduction:     scratchpad PoC-1 (in-memory app) — output: `POST /ca/create parent=revoked -> 201 … leaf issued … -> 201`
Recommended fix:  In `create_intermediate_ca` raise if `parent_ca.is_revoked` or `parent_ca.not_after <= now`; in `ca.create` resolve the
                  parent through `CertificateAuthority.signing_capable().filter_by(id=…)`; apply the same to explicit `parent_id` on import.
Open questions:   none
```

```
[ID]  G4-3
Title:            Public-key strength floor silently accepts non-RSA/EC CSR keys (DSA-1024, Ed25519 signed as key_type "Unknown")
Category:         Both
Severity:         Low — needs an admin to sign; result is a cert over a below-policy or undescribed key
Confidence:       Confirmed (PoC)
Status vs prior:  New
Location:         policy.py:35-45   `if isinstance(public_key, rsa.RSAPublicKey): … elif isinstance(public_key, ec.EllipticCurvePublicKey): …`  (no else)
                  cert_service.py:199-208  `else: key_type = "Unknown"; key_size = 0`
Preconditions:    none
Description:      `enforce_public_key_strength` returns silently for DSA/EdDSA keys; `sign_csr` then builds the cert with that key.
Impact / attack:  PoC: DSA-1024 CSR → "floor passed; sign_csr -> ISSUED key_type='Unknown' key_size=0"; Ed25519 likewise.
                  UI/JSON show "Unknown 0"; a 1024-bit DSA leaf violates MIN_RSA_KEY_SIZE's intent.
Reproduction:     scratchpad PoC-4
Recommended fix:  Add `else: raise ValueError("Unsupported public-key algorithm (RSA/EC only)")` (or an explicit allow-list incl. Ed25519 if
                  wanted); reject at `import_csr` as well.
Open questions:   Should Ed25519 be supported deliberately?
```

```
[ID]  G4-4
Title:            EC curve accepted by size not identity; EC leaves get keyEncipherment; SAN prefixes other than IP:/EMAIL: become DNS names
Category:         Correctness
Severity:         Low — interop/profile correctness, no trust impact
Confidence:       Confirmed (read code)
Status vs prior:  New
Location:         policy.py:44-45   `if public_key.curve.key_size not in (256, 384, 521): raise ValueError("Unsupported EC curve; use P-256, P-384, or P-521.")`
                  cert_service.py:129-142  default KU `key_encipherment=True` regardless of key type
                  cert_service.py:28-44    `_build_san`: anything not `IP:`/`EMAIL:` → `x509.DNSName(san)` (a `URI:` entry becomes a DNS SAN)
                  csr_service.py:87-98     `parse_csr` silently drops URI/otherName/dirName SANs from uploaded CSRs
Preconditions:    none
Description:      secp256k1 / brainpoolP256r1 keys pass the "P-256/384/521" check; ECDSA leaves are issued with keyEncipherment (RFC 5480 §3
                  says not to); unknown SAN prefixes are misclassified rather than rejected.
Impact / attack:  Policy message lies about what is accepted; profile-strict validators may reject EC leaves; an admin typing `URI:` gets a DNS SAN.
Reproduction:     `policy.enforce_public_key_strength(ec.generate_private_key(ec.SECP256K1()).public_key())` returns None.
Recommended fix:  `isinstance(curve, (SECP256R1, SECP384R1, SECP521R1))`; choose default KU by key type; reject unknown SAN prefixes with a 400.
Open questions:   none
```

```
[ID]  G4-5
Title:            Cross-reference — revocation is committed before the CRL refresh; a refresh failure loses the audit row (see G10-1)
```

```
[ID]  G4-6
Title:            Intermediate creation under an EXPIRED parent is refused only by pyca's builder error (PKI-4 guard not applied there)
Category:         Correctness
Severity:         Info
Confidence:       Confirmed (PoC-2)
Status vs prior:  New
Location:         ca_service.py:175-177  `not_after = bounded_not_after(now, validity_days, parent_ca.not_after, is_ca=True)` (clamps to a past date)
Preconditions:    none
Description:      Outcome is a 400 "The not valid after date must be after the not valid before date." — safe, but not the explicit refusal that
                  cert_service.py:80-82 gives.
Recommended fix:  Add the same expired-issuer check to `create_intermediate_ca`.
```

```
[ID]  G4-7
Title:            Single-certificate import links to a parent by subject-name match / explicit parent_id without signature verification
Category:         Correctness
Severity:         Info — admin error only; bundle imports do verify
Confidence:       Confirmed (read code)
Status vs prior:  New
Location:         ca_service.py:261-270 `_find_parent_by_issuer` (name equality), :376-384 (explicit `parent_id` accepted as-is); contrast :433-436
                  `current.verify_directly_issued_by(parent)` for bundles
Recommended fix:  Verify `cert.verify_directly_issued_by(parent_cert)` whenever a parent is chosen.
```

```
[ID]  G4-8
Title:            A revoked CA's own CRL can never be regenerated, so it expires
Category:         Correctness
Severity:         Info
Confidence:       Confirmed (read code)
Location:         ca.py:438-442 (`Cannot generate CRL for a revoked CA`), cli.py:254 (`filter_by(is_revoked=False)`)
Description:      Harmless for trust (its leaves are revoked and the parent lists it) but validators of an old leaf see "CRL expired" instead of
                  "revoked". Consider allowing regeneration for revoked CAs.
```

Open questions (Area 4): CRL consumers on the LAN; Ed25519 policy; CRL window vs cron cadence.

---

### Area 5 — Key backends / HSM

Files read in full: `app/services/keybackend/{base,__init__,software,softhsm,pkcs11_session}.py`, `tests/test_softhsm.py`, `tests/test_keybackend.py`.

**Checklist verdicts:**
- **Byte parity (certs/CRLs):** `_reassemble` keeps `tbs_*` and `signature_algorithm` from the throwaway-signed object and swaps only the signature (`softhsm.py:101-111`); RSA uses `CKM_SHA256_RSA_PKCS` (`:94`), deterministic PKCS#1 v1.5 → identical DER. Asserted literally: `assert hsm_der == soft_der` (`test_softhsm.py:95`) and `assert soft == hsm` for CRLs (`:184`). The tests are not skipped in CI (`docker-publish.yml:35-38` installs `softhsm2`; latest runs green) — they **do** skip on this host (no `softhsm2-util`), see Area 22.
- **EC path:** SHA-256 digest then raw `CKM_ECDSA` (`softhsm.py:97-98`); `encode_ecdsa_signature` (python-pkcs11) splits `r‖s` at `len//2` and DER-encodes two INTEGERs — correct for P-256/384/521 (66+66 for P-521), leading-zero padding handled by asn1crypto's minimal INTEGER encoding. Test asserts TBS identity and `verify_directly_issued_by` (`:113-118`).
- **OCSP over HSM:** CertID lifted from a throwaway pyca request (`:258-262`), responder `by_key` = SKI (`:264-269`), whole-second GeneralizedTime (`:117-124`), revoked reason names map 1:1 to asn1crypto `CRLReason` (`:126-137`). AlgorithmIdentifier: asn1crypto `sha256_rsa` encodes **with** NULL params (`300d06092a864886f70d01010b0500` — verified in the venv), `sha256_ecdsa` without — identical to pyca. Semantic-parity test (`:202-234`) plus signature verification against the CA key.
- **Live confirmation:** `home inter` (HSM, id 7) chains to `Home` (id 3) — `openssl verify: OK`; CRL of `test 4` (HSM) — `verify OK`; OCSP via HSM CA 13 — `Response verify OK`, GOOD, byKey; HSM-issued leaf `root(8) → 13 → leaf` — `OK`.
- **Session management:** one logged-in session per process guarded by an `RLock` for the whole operation, closed and dropped on any exception (`pkcs11_session.py:16-21,48-72`); gunicorn runs without `--preload`, so `C_Initialize` happens post-fork in each worker; sync workers are single-threaded. No race found.
- **PINs:** `_read_secret("PKCS11_USER_PIN")` / `SO_PIN` (`config.py:87-88`) from `/run/secrets/*` (compose `:48-49`); never logged (grep). `hsm_available()` requires the user PIN (`keybackend/__init__.py:53-68`).
- **Key attributes:** generate: `TOKEN=True, PRIVATE=True, SENSITIVE=True, EXTRACTABLE=False, SIGN=True` (`softhsm.py:149-153,164-168`); import: same (`:205-211`). Export refused: `is_exportable` false for softhsm (`models/ca.py:66-70`), `_refuse_if_not_exportable` (`ca_service.py:539-546`), buttons hidden (`ca/detail.html:27-35,122`); tested (`test_softhsm.py:322-332`).
- **Cross-backend intermediates:** child key in the child's backend, parent's backend signs (`ca_service.py:153-159,239-240`); tests `:281-312`.
- **Migration:** `verify_signing_key` signs a nonce and verifies against the CA cert **before** `private_key_enc = b""` (`cli.py:66-72`, `softhsm.py:219-236`).

```
[ID]  G5-1
Title:            SoftHSM SO PIN is 8 bytes (pre-INFRA-1 value) — at-rest strength of the 3 HSM-backed CA keys is bounded by it
Category:         Security
Severity:         Medium (conditional on an attacker obtaining data/softhsm/tokens — backup theft, host read; then offline)
Confidence:       Confirmed (length) / Plausible (crack rate)
Status vs prior:  Carried — 08-08 INFRA-1 "SO-PIN half deferred"
Location:         secrets/pkcs11_so_pin = 8 bytes (2026-08-06); secrets/pkcs11_user_pin = 32 bytes (2026-08-10)
                  scripts/init-secrets.sh:85-91 now writes `rand_alnum 32` for new deployments only
Preconditions:    possession of the token store (it lives inside the `./data` volume that backups capture)
Description:      SoftHSM2 wraps the token's object-encryption key under both PINs (C_InitPIN by the SO re-wraps it), so an offline attacker
                  with the token files needs only the weaker PIN. 8 digits ≈ 2^26.6 candidates; SoftHSM's PIN KDF is fast.
Impact / attack:  Recovery of the HSM CA private keys from a stolen volume, negating the "non-exportable" property for `test 4`, `home inter`,
                  `Demo HSM Issuing CA`. (The user PIN is now 32 chars, so the SO PIN is the weakest link.)
Reproduction:     `wc -c secrets/pkcs11_so_pin` → 8. Offline: brute-force SoftHSM token files with candidate SO PINs (not attempted).
Recommended fix:  Initialise a new token with a 32-char SO PIN and re-key/re-issue the three HSM CAs (HSM keys cannot be moved), or accept and
                  document; exclude `data/softhsm` from ordinary backups / encrypt backups (also covers G16-1).
Open questions:   Is re-keying the three HSM CAs acceptable now? Are backups of `data/` encrypted?
```

```
[ID]  G5-2
Title:            Minor backend nits: CKA_ID mismatch between key pair objects, `key_label=None` lookup, per-signature throwaway RSA keygen
Category:         Correctness
Severity:         Info
Confidence:       Confirmed (read code)
Status vs prior:  New
Location:         softhsm.py:148,163 (`id=label.encode()[:32]` on both objects) vs :180-185 (only the *public* object's ID re-tagged with the SKI);
                  :88-90 `session.get_key(object_class=PRIVATE_KEY, label=ca.key_label)` matches any private key if label is None (no path sets it);
                  :67-71 fresh RSA-2048 generated for every cert/CRL signature; models/ca.py:64 `has_signing_key` is unconditional for softhsm
                  (a wiped token surfaces only as 500s at signing time)
Recommended fix:  Set the same CKA_ID on both objects; guard `key_label` non-empty; cache one throwaway key per process.
```

```
[ID]  G5-3
Title:            EC CAs on P-384/P-521 sign with SHA-256 (ecdsa-with-SHA256) in both backends
Category:         Correctness
Severity:         Info — honest and interoperable, lower margin than customary for P-521
Location:         software.py:22-23; softhsm.py:97-99,113-115
```

Open questions (Area 5): re-keying HSM CAs; intended hash for P-521.

---

### Area 6 — Authentication

Files read in full: `auth_service.py`, `ldap_service.py`, `ldap_settings_service.py`, `routes/auth.py`, `models/user.py`, `extensions.py`, relevant parts of `__init__.py`, `routes/users.py`.

**Checklist verdicts:**
- Hashing: Werkzeug `generate_password_hash` default → live rows are `scrypt:32768:8:1$…` (`models/user.py:48-49`; DB). Never serialised (`to_dict` allow-list `:63-73`; test asserts `set(u) <= allowed`). `UNUSABLE_PASSWORD="!"` short-circuits `check_password` (`:55-61`).
- Local-first: local rows never fall through to LDAP (`auth_service.py:55-66`); LDAP only when the *effective* config enables it (`:68-71`); local deactivation wins for LDAP users (`:90-92`).
- Empty/anonymous bind: rejected before any bind (`ldap_service.py:55`); DN/filter escaping (`:62,:141-143`); `auto_referrals=False`, TLS verify default (`:88,:118`). LDAP is **disabled** here.
- Basic Auth cache: HMAC(random per-process key, `user\0pass`) (`:242,:250-252`), `compare_digest` (`:267`), hit re-reads the `User` row and re-checks username + active (`:311-313`); TTL 60 s, 256 entries.
- Lockout: per-account, DB-backed, applies to Basic and session (`:57-66,:116-139`); the **sole active admin is never hard-locked** (`:128-133`, DoS-2 design) — the live box has exactly one admin.
- `next`: `_is_safe_url` rejects scheme/netloc/`//`/backslash/control chars (`auth.py:11-29`) — correct (but see G6-3).
- Sessions: `HttpOnly`, `SameSite=Lax`, secure flag from config (`config.py:40-45`), 30-min sliding lifetime (`:91-95`, `__init__.py:452-454`); logout is POST+CSRF (`auth.py:120-127`). Live header: `Set-Cookie: session=…; HttpOnly; Path=/; SameSite=Lax` — no `Secure` (consistent with HTTP).
- **Deactivation/demotion of a live session (checked, positive):** Flask-Login 0.6's `UserMixin.is_authenticated` returns `self.is_active`, which the model overrides with `is_active_user` (`models/user.py:32-34`) → a deactivated user's existing session is refused on the next request; role is re-read per request. PoC: after `toggle-active`, the victim's session got 302 and a write attempt created nothing; demotion applied immediately.

```
[ID]  G6-1
Title:            Live deployment is plain HTTP on the LAN — credentials, session cookies, exported CA keys and one-time CSR keys travel in cleartext
Category:         Security
Severity:         High — any LAN-path attacker captures the admin session (= full CA control incl. key export) or a CA key PEM (= permanent compromise)
Confidence:       Confirmed (live)
Status vs prior:  Carried — 10-07 E1 (High) → 05-08 "Mitigated" by the `deploy/` TLS overlay; the overlay is not applied on this deployment
Location:         docker-compose.yml:6-7 `ports: - "5000:5000"`, :28 `SESSION_COOKIE_SECURE=${SESSION_COOKIE_SECURE:-false}`;
                  live `docker port`: 0.0.0.0:5000 / [::]:5000; config.py:135 Basic Auth on by default;
                  ca.py:333-362 (CA key/PKCS#12 export), certificates.py:310-338 (leaf key), csr.py:97-110 + csr/detail.html:73-80 (one-time key)
                  all served over the same channel; `__init__.py:388-390` HSTS is emitted but browsers ignore HSTS over HTTP
Preconditions:    attacker on the LAN path (ARP/DNS spoofing, rogue AP, compromised LAN host)
Description:      Nothing in the app protects the transport; the shipped TLS overlay (deploy/docker-compose.tls.yml + Caddyfile) would.
Impact / attack:  Sniff `Cookie: session=…` → replay for ≤30 min sliding (no server-side invalidation, G6-4); sniff `Authorization: Basic` →
                  permanent creds; sniff a `format=key` response → CA private key.
Reproduction:     `curl -sD - http://10.0.0.82:5000/auth/login | grep Set-Cookie` (no Secure; transport is HTTP).
Recommended fix:  Deploy `deploy/docker-compose.tls.yml` (`tls internal` for a LAN name) — it also pins `SERVER_NAME_FOR_OCSP` (G8-3), sets
                  `SESSION_COOKIE_SECURE=true` and `TRUSTED_PROXY_COUNT=1`, and drops the host port. Defense-in-depth: refuse key/PKCS#12
                  export unless `request.is_secure`.
Open questions:   Is the LAN considered a trusted network for this deployment?
```

```
[ID]  G6-2
Title:            Admin-created and admin-reset passwords bypass MIN_PASSWORD_LENGTH and are not flagged for rotation
Category:         Security
Severity:         Low
Confidence:       Confirmed (read code; PoC-9 created an admin with an arbitrary password)
Status vs prior:  New
Location:         users.py:27-33 `password = request.form.get("password", "")` … `if not username or not password:` (only emptiness), :44-46
                  `user.set_password(password)`; :132-138 (reset); contrast auth.py:101 `elif len(new_password) < min_len`;
                  `must_change_password` only set at `__init__.py:619`
Recommended fix:  Enforce `MIN_PASSWORD_LENGTH` in both admin routes; set `must_change_password=True` on admin-set passwords.
```

```
[ID]  G6-3
Title:            The post-login `next` redirect is never honoured (unauthorized handler passes an absolute URL that `_is_safe_url` rejects)
Category:         Correctness
Severity:         Low
Confidence:       Confirmed (live + PoC-7)
Status vs prior:  New
Location:         __init__.py:234 `return redirect(url_for(login_manager.login_view, next=request.url))`;
                  auth.py:23-29 `not parts.scheme and not parts.netloc and target.startswith("/")`
Reproduction:     live: `GET /` → `Location: /auth/login?next=http://10.0.0.82:5000/`; PoC: after login `Location = /` (expected `/ca/`)
Recommended fix:  Pass `request.full_path` (or `request.script_root + request.full_path`) instead of `request.url`.
```

```
[ID]  G6-4
Title:            No server-side session invalidation on password change/reset — a stolen cookie survives credential rotation
Category:         Security
Severity:         Low (design limit of client-side sessions; amplifies G6-1)
Confidence:       Confirmed (read code)
Status vs prior:  New
Location:         auth.py:108-115 (hash replaced only); users.py:138-145; Flask cookie sessions, `session.permanent=True` (`__init__.py:452-454`)
Recommended fix:  Store a per-user `session_version`/`password_changed_at` and reject sessions issued before it (Flask-Login `user_loader`).
```

```
[ID]  G6-5
Title:            Single-admin posture: sole admin never locks, cache honours a rotated password for ≤60 s, locked accounts skip the burn-hash
Category:         Security
Severity:         Info
Confidence:       Confirmed (read code)
Location:         auth_service.py:128-133 (no hard lock for the last admin — the live box has one admin), :224-291 (cache TTL),
                  :58-59 (`_is_locked` returns before `_burn_hash`, :97-99 → timing distinguishes locked accounts)
Description:      Brute force against `admin` is bounded only by the memory-backed limiter (60/min per worker → ~120/min) and password strength.
Recommended fix:  Optional: per-account throttle (progressive delay) for the exempt admin; invalidate cache entries on password change.
```

```
[ID]  G6-6
Title:            Basic-Auth CSRF exemption depends on `Sec-Fetch-Site` (absent in legacy browsers) — accepted residual of API-3
Category:         Security
Severity:         Info
Location:         extensions.py:24-31
```

LDAP (disabled here) — code-correctness note (Info): the admin "Test connection" sends the **stored** bind password to whatever URI/TLS settings are in the form (`users.py:200-215`, `ldap_service.py:202-266`); a malicious admin can exfiltrate it. See G7-6.

Open questions (Area 6): LAN trust; whether a second admin will exist (changes lockout/dual-control behaviour).

---

### Area 7 — HTTP routes / JSON API

Files read in full: `routes/{ca,certificates,csr,dashboard,users,auth,health,metrics}.py`, `responses.py`, `serialization.py`, all `to_dict()`.

**Checklist verdicts:**
- Serializers: CA (`models/ca.py:103-136`) omits `private_key_enc`, `key_label`, `crl_pem`; Certificate (`certificate.py:52-79`) omits `private_key_enc`; CSR (`csr.py:26-43`) exposes only public `csr_pem`; User (`user.py:63-73`) omits `password_hash`; MetricsToken omits hash; AuditLog `details` never contain secrets (Area 10). Tests assert allow-lists (`test_json_api.py:138-172`). CSR one-time key: returned once (`csr.py:97-101` JSON / `:107-110` HTML), `enc_key` discarded (`_`), CSR model has no key column (`models/csr.py:10-20`).
- Authz parity: ownership/role checks precede every `wants_json()` branch (`certificates.py:177-184,248-250`; `csr.py:132-139`; `decorators.py`). JSON 401/403 for API clients (`__init__.py:212-229`, `decorators.py:18-19,33-34`); live: unauthenticated `Accept: application/json` → `401 {"error":"Authentication required."}`, bad Basic → `401` + `WWW-Authenticate: Basic realm="chancery"`.
- CSRF: enforced for sessions; skipped only for **valid** Basic Auth and not when `Sec-Fetch-Site: cross-site` (`extensions.py:24-31`); OCSP is the only `@csrf.exempt` (`public.py:75`). An `Accept: application/json` browser request still needs the token.
- Input validation: ints parsed with clear 400s (`certificates.py:77-82`, `csr.py:75-78`, `ca.py:169-174`); subject validated server-side (`policy.build_subject`); CA selection re-checked for revoked (`certificates.py:92-93`, `csr.py:194-195`) and keyless/pending in the service.
- Uploads: 64 KB after read (`ca.py:19-30`, `ca_service.py:22,512-519,602-603`) under the 1 MiB body cap.
- CA export: `pem`/`chain` GET; `key`/`pkcs12` POST-only with the password from `request.form` only (`ca.py:317-362`); audited; refuses cert-only and HSM (`ca_service.py:539-546`). Tests `test_ca_export.py:124-152`.
- Headers: nosniff / frame-deny / CSP / Referrer-Policy / HSTS on every response (`__init__.py:360-391`); `Content-Disposition` sanitised (`_safe_filename`) — see G8-1 for the encoding gap.

```
[ID]  G7-1
Title:            CSR generation accepts any RSA key size — an authenticated low-privilege user can pin both workers with RSA-16384 keygen (and 1024-bit CSRs are accepted)
Category:         Security
Severity:         Medium — DoS of the whole app incl. OCSP/CRL by any account (csr_requester suffices); rate limiting does not help
Confidence:       Confirmed (PoC + timing)
Status vs prior:  New (DoS-1 covered only unauthenticated paths)
Location:         csr.py:75-78 `key_size = int(request.form.get("key_size", "2048"))` (no bounds) → :90-94 →
                  csr_service.py:13-19 `_generate_key` — **no** `enforce_key_strength` (unlike cert_service.py:18-19, ca_service.py:45-46) →
                  `rsa.generate_private_key(public_exponent=65537, key_size=key_size)`; OpenSSL accepts up to 16384
                  entrypoint-app.sh:52-56 `--workers 2 --timeout 120`; docker-compose.yml:95 `cpus: 2`
Preconditions:    any authenticated account (session or Basic Auth)
Description:      Measured on this host: RSA-8192 ≈ 1.8–3.9 s, RSA-16384 ≈ 16.5 s per request (PoC-3: `key_size=8192 -> 201 in 3.9s`;
                  `key_size=1024 -> 201`). Two concurrent requests occupy both sync workers; 7 req/min sustains it under the 60/min limit.
Impact / attack:  UI, issuance, OCSP and CRL endpoints unavailable while the loop runs; worker kill/restart churn every 120 s.
                  Weak 1024-bit CSRs are stored (rejected only later at signing, cert_service.py:75).
Reproduction:     `curl -u req:pw -d 'mode=generate&cn=x&key_type=RSA&key_size=16384' http://10.0.0.82:5000/csr/create` ×2 in parallel, loop.
Recommended fix:  Call `enforce_key_strength` in `csr_service._generate_key` and add an allow-list ceiling (RSA {2048,3072,4096}, EC {256,384,521})
                  in all three generation paths; optionally a per-user concurrency limit and `--max-requests`.
Open questions:   none
```

```
[ID]  G7-2
Title:            `csr.sign` and `csr.create` (upload) swallow ValueError — policy refusals return a generic 500
Category:         Correctness
Severity:         Low — operators cannot distinguish policy refusal from outage; JSON clients get 500 for a 400 condition
Confidence:       Confirmed (PoC-8)
Status vs prior:  New
Location:         csr.py:246-248 `except Exception: logger.exception("Error signing CSR"); return _err("An unexpected error …", 500)` (no ValueError
                  branch, unlike certificates.py:150-153 and ca.py:218-221); csr.py:62-64 same for import
Description:      PoP failure (cert_service.py:74), weak key (:75), expired CA (:82), validity cap (policy.py:59), bad IP SAN all become
                  "unexpected error" + a traceback in the log.
Reproduction:     PoC-8: validity_days=99999 → `500 {"error": "An unexpected error occurred while signing the CSR."}`
Recommended fix:  Add `except ValueError as e: return _err(str(e))` before the generic handler in both routes.
```

```
[ID]  G7-3
Title:            Unvalidated inputs: negative `path_length` → 500; free-text revocation `reason` persisted
Category:         Correctness
Severity:         Low
Confidence:       Confirmed (PoC-5 / read code)
Status vs prior:  New
Location:         ca.py:172 `path_length = int(path_length_str)` → ca_service.py:85/189 `BasicConstraints(ca=True, path_length=-1)` → pyca TypeError →
                  `except Exception` → 500; certificates.py:220 / ca.py:388 `reason = request.form.get("reason", "unspecified")` stored raw
                  (`String(50)` unenforced by SQLite), mapped to `unspecified` in CRL/OCSP (crl_service.py:162, ocsp_service.py:150) while
                  DB/UI/JSON show the raw text
Recommended fix:  Validate `path_length >= 0`; validate `reason in REVOCATION_REASONS`.
```

```
[ID]  G7-4
Title:            CSR signing is check-then-act — two workers can double-issue from one CSR
Category:         Correctness
Severity:         Info (requires an admin racing themselves)
Location:         csr.py:155-159 (status check) vs cert_service.py:236-241 (status set after signing, no conditional UPDATE)
Recommended fix:  `UPDATE csr SET status='signing' WHERE id=? AND status='pending'` guard before signing.
```

```
[ID]  G7-5
Title:            `ca_type=intermediate` with an empty `parent_id` silently creates a root CA
Category:         Correctness
Severity:         Info
Location:         ca.py:186 `if ca_type == "intermediate" and parent_id:` … `else: create_root_ca(...)` (:200-206)
```

```
[ID]  G7-6
Title:            Admin-configurable outbound URLs (webhook target, LDAP test) permit SSRF to LAN/localhost and exfiltration of the stored LDAP bind password
Category:         Security
Severity:         Info — malicious/compromised admin only; LDAP not configured here
Location:         webhook_service.py:251-253,312-315 (`urllib.request.urlopen(req…)` to any http(s) URL, `validate` :158-175 checks scheme only);
                  ldap_service.py:202-266 with `users.py:200-215` (stored bind password reused for a test against an admin-typed URI, TLS verify togglable)
Recommended fix:  Optionally deny loopback/link-local/private targets for webhooks; require re-entering the bind password for tests against a changed URI.
```

Open questions (Area 7): none blocking.

---

### Area 8 — Public unauthenticated surface

File read in full: `routes/public.py` (+ `ocsp_service.py`, `crl_service.py`, config).

**Checklist verdicts:**
- CRL/CA-cert download: strictly read-only — serve `ca.crl_pem`/`certificate_pem`; `404` when no CRL (`public.py:20-71`). `get_crl_pem/der` (which *could* regenerate) are dead code (no callers). No signing/decrypting on the public path ✔. Live headers: `Content-Type: application/pkix-crl`, `Content-Disposition: attachment; filename="Home.crl"`.
- OCSP: parse → lookup → cache → sign (`ocsp_service.py:105-170`); body capped by `MAX_CONTENT_LENGTH` 1 MiB; rate-limited 60/min/IP (limiter exempts only health/metrics, `__init__.py:63-65`). Live: GOOD for `dns.home`, `WARNING: no nonce in response` (accepted PKI-5), 24 h window.
- IDs: integer `ca_id` enumeration by design (public material); serials are 159-bit random.
- Host header: see G8-3.

```
[ID]  G8-1
Title:            Non-latin-1 CA/certificate names break every download for that object — including the public CRL and CA-cert endpoints
Category:         Correctness (revocation availability)
Severity:         Medium — a CA named "Łódź Root", "Zürich-Ost" is fine but "Łódź", Cyrillic, Greek, CJK names get an unreachable CRL/CA URL
Confidence:       Confirmed (code path) / Plausible (no such name exists on the live box today)
Status vs prior:  New
Location:         public.py:12-15 `safe = re.sub(r'[^\w.\-]', '_', name)` (`\w` is Unicode-aware in Python 3); used at :36 (CRL DER), :54, :70;
                  same helper in certificates.py:21-24 and ca.py:33-36;
                  gunicorn `http/wsgi.py:418` `util.write(self.sock, util.to_bytestring(header_str, "latin-1"))` (HTTP/1.x header bytes)
Preconditions:    a CA/cert name containing any character outside ISO-8859-1
Description:      Demonstrated: `re.sub(r'[^\w.\-]', '_', 'Łódź 测试')` → `'Łódź_测试'`; `.encode('latin-1')` → UnicodeEncodeError on 'Ł'.
                  gunicorn raises while writing headers → 500/aborted response. Flask's test client does not go through this path, so the
                  test suite cannot catch it.
Impact / attack:  For such a CA, `/public/crl/<id>.crl|.pem` and `/public/ca/<id>.crt` fail → CRL-checking relying parties fail; admin exports fail.
Reproduction:     create a CA named `Łódź` on a test instance; `curl -I http://host/public/crl/<id>.crl` → 500 (gunicorn), traceback in log.
Recommended fix:  ASCII-only sanitiser (`[^A-Za-z0-9._-]`) plus RFC 5987 `filename*=UTF-8''…`, or use `ca.id` in public filenames.
Open questions:   none
```

```
[ID]  G8-2
Title:            OCSP: malformed request → HTTP 500 (not an OCSP malformedRequest response); GET form (RFC 6960 §A.1) unsupported
Category:         Correctness
Severity:         Low — clients that use GET (Windows CryptoAPI default, some appliances) get 404 → OCSP unavailable → fall back to the (expired) CRL
Confidence:       Confirmed (live)
Status vs prior:  New
Location:         public.py:74-89 `methods=["POST"]` … `except Exception: current_app.logger.exception("OCSP responder error"); return "Internal server error", 500`;
                  ocsp_service.py:108 `load_der_ocsp_request` raises ValueError; tests/test_routes.py:203-213 pins the 500 behaviour
Reproduction:     live: `curl -X POST --data-binary garbage /public/ocsp/3` → `HTTP/1.1 500` (text/html); container log:
                  `ERROR in public: OCSP responder error … ValueError: error parsing asn1 value: ParseError { kind: ShortData … }`;
                  `GET /public/ocsp/3/<b64>` → 404
Recommended fix:  Catch ValueError → `OCSPResponseBuilder().build_unsuccessful(MALFORMED_REQUEST)` at 200; add
                  `GET /public/ocsp/<int:ca_id>/<path:b64>`; keep 500 for real failures; lower the log level for parse errors.
```

```
[ID]  G8-3
Title:            AIA/CDP URLs come from the request Host (default config) — live certificates embed http://localhost:5000/…
Category:         Correctness (Security only with a spoofable Host)
Severity:         Medium — for those certificates revocation checking is impossible for their whole lifetime (URLs are immutable)
Confidence:       Confirmed (live)
Status vs prior:  Carried — 10-07 C4 → 05-08 "Mitigated (documented)" → 08-08 API-2 "residual"; now with concrete live harm
Location:         certificates.py:64-66 / csr.py:171-173 `if ocsp_server == "localhost:5000": ocsp_server = request.host`; :103-106 / :199-202 URL build;
                  config.py:34 default; live env `SERVER_NAME_FOR_OCSP=localhost:5000`; scripts/seed_demo.py:120-128 uses the config value verbatim
Preconditions:    `SERVER_NAME_FOR_OCSP` unset (as on the live box)
Description:      Live DB: `dns.home` (CA `Home`), `grugo.me` (CA `test01`) and most demo certificates carry `http://localhost:5000/public/...`
                  as both CDP and AIA; a minority carry `http://10.0.0.82:5000`. Whatever hostname the admin (or the seeder) used got baked in.
Impact / attack:  Relying parties resolve `localhost` to themselves → CRL/OCSP fetch fails silently or hard. The Host-spoofing angle remains
                  Low (only the admin's own Host is used; the value is HTML-escaped inside the template JS string, certificates/create.html:262).
Reproduction:     `openssl x509 -in <dns.home.pem> -noout -text | grep -A1 'Authority Information\|CRL Distribution'`
Recommended fix:  Set `SERVER_NAME_FOR_OCSP=10.0.0.82:5000` (or the TLS hostname) now; refuse to embed a `localhost` URL outside debug/testing;
                  make `seed_demo.py` derive the host explicitly; re-issue `dns.home` if it is in use.
Open questions:   Is `dns.home` (CA 3) a production certificate?
```

```
[ID]  G8-4
Title:            CRL responses have no caching headers; default rate limit applies to public endpoints
Category:         Correctness
Severity:         Info
Location:         public.py:31-37,50-55 (no Cache-Control/Expires/ETag); `__init__.py:63-65` exempts only health/metrics from the 60/min/IP limit
Recommended fix:  `Expires`/`Last-Modified` from the CRL's nextUpdate/thisUpdate; consider exempting or raising the limit for `/public/*`.
```

Open questions (Area 8): CRL/OCSP consumers; `dns.home` usage.

---

### Area 1 — Bootstrap & factory

Files read in full: `app/__init__.py`, `extensions.py`, `_version.py`.

Verdicts: `_check_security` exits for unset/blank/default `SECRET_KEY` and `MASTER_PASSPHRASE` (`:257-267`) unless `TESTING` or `app.debug` (`:239-249`; debug prints a loud warning; gunicorn never enables debug and `FLASK_DEBUG` is absent from the container env). `ADMIN_PASSWORD` is guarded only at seed time (`:610-614`) — consistent with docs. Forced-password-change guard (`:112-133`) exempts Basic Auth (which is separately refused with 403 while flagged, `:204-210`), `public`/`health`/`metrics` blueprints, change-password, logout, static — every state-changing route lives in a gated blueprint, no bypass found. Error handlers (`:394-446`): JSON for API clients, plain `"Internal Server Error"`, Werkzeug default 404/405 pages — no traces (live 404 checked); `CSRFError` handler honours same-host referrers only (`:441-445`). ProxyFix is applied only when `TRUSTED_PROXY_COUNT > 0` (`:17-22`); with 0, `X-Forwarded-*` is ignored — audit IP and limiter key are the TCP peer (correct for this topology). Context processors inject version/update flag/dual-control callable (`:94-109`) — no secrets. Admin seed race handled by the unique constraint (`:621-627`).

```
[ID]  G1-1
Title:            Rate limiter uses `memory://` — per-worker counters (effective limit ≈ 2×, resets on restart)
Category:         Security
Severity:         Info
Location:         __init__.py:466-471 `storage_uri="memory://"`; entrypoint-app.sh:54 `--workers 2`
```

```
[ID]  G1-2
Title:            CSP allows any script from the whole `https://cdn.jsdelivr.net` host
Category:         Security
Severity:         Info — SRI on the two tags mitigates; self-hosting Bootstrap would remove the origin entirely
Location:         __init__.py:372 `script-src 'self' https://cdn.jsdelivr.net 'nonce-…'`
```

```
[ID]  G1-3
Title:            Non-Docker multi-worker first boot can race two `ALTER TABLE`s (Docker avoids it via the pre-start `create_app()`)
Category:         Correctness
Severity:         Info
Location:         __init__.py:479-596 (inspect-then-ALTER per worker); entrypoint-app.sh:43 runs the migration once before gunicorn
```

---

### Area 2 — Config & secrets intake

File read in full: `config.py`.

Verdicts: `_read_secret` (`:5-17`) — `*_FILE` wins over env; missing file → `FileNotFoundError` at import (fail closed); empty file → `""` → rejected by `_check_security` for the two critical secrets; `.strip()` removes the trailing newline (and any deliberate leading/trailing whitespace). Every numeric var uses the empty-safe `or` idiom; non-numeric values crash at import (fail closed). Booleans compare lowercase `"true"`. Defaults judged: cookie secure **true** (`:45`), validity caps 825/7305, `MIN_RSA_KEY_SIZE` 2048, body cap 1 MiB, OCSP key/response caches 300/60 s, `CRL_VALIDITY_DAYS` 7 (only safe with a scheduler — G4-1), lockout 5/15, min password 12, session 30 min, rate limit on 60/min, Basic on, LDAP TLS verify on, metrics off, update check on. No secret is echoed or logged; secrets do live in `app.config` (`MASTER_PASSPHRASE`, PINs) — any future debug/config page would expose them.

```
[ID]  G2-1
Title:            SECRET_KEY and ADMIN_PASSWORD are delivered as env literals (visible in `docker inspect` / `/proc/<pid>/environ`); ADMIN_PASSWORD still set although unused
Category:         Security
Severity:         Low — host-level reader precondition; SECRET_KEY compromise = forge an admin session remotely
Confidence:       Confirmed (live)
Status vs prior:  Carried — 08-08 INFRA-4 was marked "Fixed" but only a comment/`_FILE` option shipped; the reference compose is unchanged
Location:         docker-compose.yml:11 `SECRET_KEY=${SECRET_KEY:?…}`, :23 `ADMIN_PASSWORD=${ADMIN_PASSWORD:-admin}`; live env contains both
                  (SECRET_KEY 24 chars, ADMIN_PASSWORD 14 chars); config.py:21,28 already support `SECRET_KEY_FILE`/`ADMIN_PASSWORD_FILE`
Recommended fix:  Move both to Docker secrets (`secrets/secret_key`), delete `ADMIN_PASSWORD` from `.env`/compose env now (the admin exists).
```

```
[ID]  G2-2
Title:            Update check is on by default (outbound HTTPS to api.github.com from a CA host)
Category:         Security
Severity:         Info — documented; acceptable for this homelab
Location:         config.py:120; update_service.py:51
```

---

### Area 3 — Access control

File read in full: `decorators.py`; every route decorator and ownership check enumerated.

Verdicts: `admin_required`/`role_required` wrap `login_required` (`decorators.py:9-38`); JSON 403 for API clients. Coverage: all `/ca/*`, `/users/*`, `/certificates/create|revoke|download-key`, `/csr/<id>/sign|reject` → `@admin_required`; `/certificates/`, `/certificates/<id>`, `/certificates/<id>/download`, `/csr/`, `/csr/create`, `/csr/<id>`, `/`, `/auth/change-password`, `/auth/logout` → `@login_required` with ownership (`certificates.py:35-37,177-181,248-250`; `csr.py:30-32,132-136`; `dashboard.py:49-69`). Unauthenticated by design: `public`, `health`, `metrics` (bearer), `auth.login`. Basic Auth reaches the same decorators through `request_loader` (`models/user.py:84-87`). IDOR: none found (integer IDs are guarded by owner checks; a requester who owns a CSR-issued cert cannot get PKCS#12 because no `private_key_enc` exists, `cert_service.py:214-232`). `role_required` is unused (dead code).

```
[ID]  G3-1
Title:            Dual control is bypassable by a single admin through user management (create a second admin / reset another admin's password)
Category:         Security
Severity:         Medium when DUAL_CONTROL_ENABLED (off on the live box → Low today) — defeats the stated four-eyes guarantee
Confidence:       Confirmed (PoC-9)
Status vs prior:  New (dual control is a 2.10.0 feature; 05-08 D4 was "Accepted: no dual control")
Location:         users.py:24-52 `create_user` (no dual-control gate; any admin, any role), :120-147 `reset_password` (any user incl. ADMIN_USERNAME);
                  dual_control_service.py:25-31 `is_exempt` = username equality; ca.py:278-285 / csr.py:161-168 compare only creator vs current user
Preconditions:    DUAL_CONTROL_ENABLED=true and a multi-user instance
Description:      PoC: alice creates pending CA → self-approve 403 ✔ → alice creates admin "mallory" (302) → mallory approves alice's CA (200).
                  Alternative: reset the bootstrap `admin` password → log in as the exempt account → sign/approve anything.
Impact / attack:  One malicious admin performs both halves of "four-eyes". The audit log shows `create_user`/`reset_user_password` +
                  `login_success` from the same IP — detectable after the fact, not prevented.
Reproduction:     scratchpad PoC-9 (in-memory app with DUAL_CONTROL_ENABLED=True)
Recommended fix:  While dual control is active: require a second admin's approval for user creation, admin promotion and password resets; refuse
                  resets of ADMIN_USERNAME; refuse approval by an account created/reset by the CA's creator within N hours; document the limit
                  in README "Dual control" until then.
Open questions:   Is dual control planned for this deployment (second admin)?
```

---

### Area 9 — Data models & migration

Files read in full: all `app/models/*.py`, `_migrate_schema()`.

Verdicts: every `ALTER TABLE ADD COLUMN` is guarded by a column-presence check (idempotent; `__init__.py:485-589`); upgrade defaults are safe (`role` → `csr_requester` then promote the configured admin with a bound parameter `:492-497`; `must_change_password DEFAULT 0`; `key_backend DEFAULT 'software'`; `approval_status DEFAULT 'approved'`); single commit (`:596`). Three-state key model is consistent across `signing_capable()` (`models/ca.py:77-85`), `has_signing_key` (`:57-64`), `is_exportable` (`:66-70`), `refresh_crl` (`crl_service.py:32`), OCSP (`ocsp_service.py:102`), CLI (`cli.py:255`), metrics (`metrics_service.py:165`), `backend_for_ca` (`keybackend/__init__.py:46-49`). SQL: ORM everywhere; raw SQL is static DDL plus one bound UPDATE. On disk: DB 0600 in 0700 (host and container); `instance/` neither shipped nor tracked.

```
[ID]  G9-1
Title:            `certificate_authorities.serial_number` has no DB-level uniqueness (import checks in code; generated serials are random)
Category:         Correctness
Severity:         Info
Location:         models/ca.py:13; ca_service.py:366-369
```

```
[ID]  G9-2
Title:            Historical DB backups (`cert-manager.db.bak-v2*`) accumulate inside `data/` (mounted into the container)
Category:         Security
Severity:         Info — 0600, but each holds old key ciphertexts/hashes; define retention
Location:         data/ (4 files, 2026-08-07..12); docker-compose.yml:9 `./data:/app/data`
```

---

### Area 10 — Audit logging

Files read in full: `audit_service.py`, `models/audit_log.py`, every `log_action` call site.

Verdicts: coverage — login success/failure/logout, Basic success/failure, change/reset password, user create/role/activate/deactivate, CA create/import/approve/revoke/CRL/key export/PKCS#12, cert create/revoke/download/key download, CSR create/import/sign/reject, LDAP/webhook settings save/reset/test, metrics-token create/revoke (CLI). `log_action` never commits (`audit_service.py:34-54`); every route commits immediately after (verified at each of the 30+ call sites). IP = `request.remote_addr` (`:43`) — correct without a proxy. No secrets in `details` (`sanitize_username_for_log` `:12-31`; settings routes log booleans/URIs only).

```
[ID]  G10-1
Title:            Revocation is committed before the CRL refresh; if the refresh raises, the state change persists but the audit row is never written (and the caller gets a 500)
Category:         Both
Severity:         Low — needs a signing failure (HSM/token error, passphrase mismatch, DB lock); the revocation itself is visible in the DB
Confidence:       Confirmed (PoC-6)
Status vs prior:  New
Location:         crl_service.py:44-52 `db.session.commit()` … `if passphrase is not None: refresh_crl(certificate.ca, passphrase)`; :90-98 (CA);
                  certificates.py:222-226 / ca.py:390-395 — `log_action(...)` runs only after the service returns; :231-236 `except Exception` → 500
Description:      PoC-6 (generate_crl monkeypatched to raise): `HTTP 500 | cert.is_revoked = True | revoke_certificate audit rows added = 0`.
                  A retry answers "already revoked" (ValueError) → again a generic 500.
Recommended fix:  Write the audit entry inside the same transaction as the revocation (before `refresh_crl`), and surface "revoked; CRL refresh
                  failed: …" as a warning rather than a 500.
```

```
[ID]  G10-2
Title:            CLI mutations are unaudited (`keys migrate-to-hsm`, `users unlock`, `crl refresh`, `certs recompute-expiry`/`backfill-issuers`)
Category:         Security
Severity:         Low
Confidence:       Confirmed (read code)
Status vs prior:  New
Location:         cli.py:21-77, :215-231, :237-268, :118-209 (no AuditLog writes); contrast metrics_token_service.py:30-45 (`username="cli"` rows)
Recommended fix:  Reuse `metrics_token_service._audit`-style rows for every CLI mutation.
```

```
[ID]  G10-3
Title:            Audit-log growth: one `basic_auth_success` row per API request; failures bounded only by the limiter; no retention; mutable SQLite
Category:         Security
Severity:         Info — accepted residuals (05-08 G1, 08-08 DoS-1)
Location:         __init__.py:189-199 (success row per request); live: 24 rows already
```

---

### Area 11 — Update check

File read in full: `update_service.py`.

Clean. Gated by config (`:89-90`); URL fixed to `https://api.github.com/repos/{repo}/releases/latest` (`:51`), `repo` from operator env only; urllib default TLS verification; 4 s timeout; daemon thread with `refreshing` reset in `finally` (`:65-80`); non-dict JSON guarded (`:62`); int-tuple compare (`:33-47`); footer renders `{{ latest_version }}` autoescaped with `rel="noopener noreferrer"` (`base.html:116-119`).

```
[ID]  G11-1
Title:            `UPDATE_CHECK_REPO` is interpolated into the URL unvalidated (operator env only)
Category:         Security
Severity:         Info
Location:         update_service.py:51
```

---

### Area 12 — Templates & static frontend

All 26 templates and `static/js/dashboard.js` read in full.

Clean: autoescape on and no `|safe`/`|urlize`/`autoescape false` anywhere under `app/templates`; every state-changing form (22 counted: login, change-password, CA create ×2, approve, CRL, key, PKCS#12, revoke ×2, cert create, cert PKCS#12/key, CSR create ×2, reject ×2, sign, users create/edit/toggle/reset, LDAP save/reset, webhooks save/reset, logout) carries `csrf_token()`; admin-only controls are gated by `current_user.is_admin` **and** enforced server-side; both CDN assets have SRI + `crossorigin` (`base.html:19,125`); the only `target="_blank"` has `rel="noopener noreferrer"`; inline scripts are nonce'd, no inline handlers (`test_csp_nonce.py`); the one-time CSR key is rendered once and passed to the clipboard via `{{ key_pem|tojson }}` (`csr/detail.html:77-90`); secrets are never echoed in the LDAP/webhook forms (write-only fields with placeholders).

```
[ID]  G12-1
Title:            `{{ ocsp_server }}` is interpolated into a JS string literal without `|tojson`
Category:         Security
Severity:         Info — HTML-escaping blocks breakout today (`'`, `<` escaped); TMPL-2 residual
Location:         certificates/create.html:262; csr/sign.html:162
```

Cosmetic: `<title>` default still "Certificate Manager" (`base.html:6`, `login.html:8`); `text-muted` used in several tables against the project's dark-theme rule.

---

### Area 13 — CLI

File read in full: `cli.py`.

```
[ID]  G13-1
Title:            `keys migrate-to-hsm` is irreversible with `--yes`, unaudited, and leaves an orphaned token object if verification fails after import
Category:         Both
Severity:         Low
Confidence:       Confirmed (read code)
Location:         cli.py:26 (`--yes`), :57-58 (prompt skipped), :66-72 (`import_ca_key` then `verify_signing_key` then scrub — DB stays consistent
                  if verify raises; the imported private object is not destroyed), no AuditLog write
Recommended fix:  Audit each migration; destroy the token object on verification failure; require `--yes` only with `--ca-id`.
```

```
[ID]  G13-2
Title:            No tooling to rotate MASTER_PASSPHRASE (re-encrypt `private_key_enc`/`secret_enc` columns)
Category:         Security (operational)
Severity:         Low — makes G16-1 remediation a manual export/re-import exercise
Location:         cli.py (absent); crypto_utils.py:23-60
Recommended fix:  `flask keys rotate-passphrase --new-file …` that re-wraps every ciphertext in one transaction.
```

---

### Area 14 — Container image

Files read in full: `Dockerfile`, `entrypoint.sh`, `entrypoint-app.sh`.

Verdicts: digest-pinned base in both stages (`Dockerfile:6,18`), `--require-hashes` (`:16`), only `softhsm su-exec` added (`:27`), non-root user (`:31`), pip removed (`:39`), selective `COPY app/ entrypoint*.sh` (`:41-42`) — no `.env`/`secrets`/`.git`; root phase = `chown` then `exec su-exec` (`entrypoint.sh:12-21`) → live PID 1 = gunicorn uid 1000; `umask 077` + `chmod 700/600` (`entrypoint-app.sh:10,46-47`); token init idempotent via the label grep (`:31`) → live: exactly one token; secrets bind-mounted read-only 0600; writable paths inside the container: `/app/data`, `/tmp` only.

```
[ID]  G14-1
Title:            On first boot the SoftHSM PINs are passed on the `softhsm2-util` command line
Category:         Security
Severity:         Info — visible in /proc/<pid>/cmdline inside the container for the seconds init takes; first boot only
Location:         entrypoint-app.sh:34-35 `softhsm2-util --init-token --free --label "$LABEL" --so-pin "$SO_PIN" --pin "$USER_PIN" …`
```

```
[ID]  G14-2
Title:            Root filesystem is writable (no `read_only: true`/tmpfs); no HTTP access log
Category:         Security
Severity:         Info — 08-08 INFRA-6 "read-only rootfs" half not done; forensic gap for unauthenticated traffic
Location:         docker-compose.yml (no `read_only`); live `ReadOnlyRootfs=false`; entrypoint-app.sh:52-56 (no `--access-logfile`)
```

---

### Area 15 — Compose & TLS

Files read in full: `docker-compose.yml`, `deploy/docker-compose.tls.yml`, `deploy/Caddyfile`.

Verdicts: secrets via files (`:86-89,116-127`); `cap_drop ALL` + 3 caps (`:109-114`); `no-new-privileges` (`:107-108`); mem/pids/cpu limits (`:93-95`); healthcheck (`:98-103`); `restart: unless-stopped`. TLS overlay drops the host port (`!reset []`), sets `SESSION_COOKIE_SECURE=true`, `OCSP_URL_SCHEME=https`, `TRUSTED_PROXY_COUNT=1`, pins `SERVER_NAME_FOR_OCSP` (`deploy/docker-compose.tls.yml:13-20`); Caddy proxies with `X-Forwarded-Proto` (`Caddyfile:14-18`) which ProxyFix trusts for exactly one hop. The reference compose is plain HTTP and says so.

- **G15-1 = G6-1** (the live box runs the plain-HTTP reference compose on the LAN).
- **G15-2 (Info):** `ports: "5000:5000"` publishes on every interface incl. IPv6 and bypasses host firewalls (Docker iptables); bind `10.0.0.82:5000:5000` if that is the intent.
- **G15-3 = G2-1** (env-literal secrets).

---

### Area 16 — Secret bootstrap

File read in full: `scripts/init-secrets.sh` (+ its git history).

Verdicts: `umask 077` (`:23`); never overwrites (`:45-52,:78-91`); `openssl rand` (CSPRNG); master passphrase `-base64 24` → 32 chars ≈ 192 bits (`:46`); `SECRET_KEY` 64 hex (`:64`); admin password 20 alnum (`:69`); PINs `rand_alnum 32` ≈ 190 bits (`:79,:87`) — the earlier 6-digit PIN bug is fixed for new deployments; `rand_pin` (`:35-38`) is dead code; the admin password is printed to stdout (`:71`, necessary but lands in scrollback).

```
[ID]  G16-1
Title:            The live master passphrase (14 bytes) and SECRET_KEY (24 chars) predate the generator — entropy source unknown
Category:         Security
Severity:         Medium if human-chosen (offline crack of the DB unlocks 10 software CA keys + 18 escrowed leaf keys; a guessable SECRET_KEY forges admin sessions remotely); Info if CSPRNG-generated
Confidence:       Needs-verification (owner knowledge; the secret was not read)
Status vs prior:  New
Location:         secrets/master_passphrase = 14 bytes (2026-08-05); .env SECRET_KEY = 24 chars; scripts/init-secrets.sh first appeared 2026-08-07
                  (`84f83df`) and would have produced 32 / 64 chars
Description:      Both values were created before any generator existed in the repo. PBKDF2-600k costs ~1 ms/guess on GPU-class hardware:
                  a dictionary/pattern passphrase of 14 characters is crackable from a stolen `data/` + nothing else.
Reproduction:     `wc -c secrets/master_passphrase` → 14; `awk -F= '/^SECRET_KEY=/{print length($2)}' .env` → 24
Recommended fix:  Confirm provenance. If not CSPRNG-derived: rotate SECRET_KEY (sessions drop) and rotate the master passphrase (needs G13-2 or
                  export→re-import of every software CA/leaf key). Either way, move both to `_FILE` secrets (G2-1).
Open questions:   How were these two values generated?
```

- **G16-2 = G5-1** (SO PIN 8 bytes).

---

### Area 17 — CI/CD pipeline

Files read in full: `.github/workflows/docker-publish.yml`, `.github/dependabot.yml`; `gh run list` checked.

Verdicts: triggers as documented (`:3-12`); `build-and-push` never runs for PRs/schedule (`:59`); registry login, push, provenance/SBOM, cosign and Trivy all gated on `refs/tags/v*` (`:75,:100,:106-107,:110-124,:127`) → a merge builds but cannot publish; all 8 actions SHA-pinned; job permissions minimal (`:23-24,:62-65`); no `pull_request_target`; only `GITHUB_TOKEN`; pip-audit blocks (`:49-52`) and re-runs weekly; the last four runs (2026-08-27) are green. Dependabot covers actions/docker/pip.

```
[ID]  G17-1
Title:            Test job installs unpinned tooling (`pip --upgrade`, `pytest`, `pip-audit`)
Category:         Security (supply chain)
Severity:         Low — the job holds a read-only token; a malicious release could still alter test/audit outcomes
Location:         docker-publish.yml:41-44, :51
Recommended fix:  Pin versions + hashes for CI tooling (a small `requirements-ci.txt`).
```

```
[ID]  G17-2
Title:            Trivy is report-only and runs only on release tags; the weekly cron audits pins but never re-scans the published image
Category:         Security
Severity:         Info — documented choice; the base-image openssl CVE (G18-1) is currently visible only by manual scan
Location:         docker-publish.yml:126-135 (`exit-code: "0"`), :9-12
```

Open question: are `v*` tags protected on GitHub (publishing is gated only by tag push rights)?

---

### Area 18 — Dependencies & build context

Verdicts: `requirements.in` pins 12 direct deps; `requirements.txt` has 30 packages / 533 `--hash` lines (every artifact hashed) and the Dockerfile uses `--require-hashes`; `.dockerignore` excludes `venv/ data/ secrets/ deploy/ scripts/ .claude/ .env .git/ .github/ tests/ *.md docker-compose.yml`. Currency: OSV batch query (2026-08-29) → **0 advisories** across all 30 pins; Trivy on the running image → **2 HIGH**: `libcrypto3`/`libssl3` 3.5.7-r0 CVE-2026-14456 (QUIC-server DoS; fixed 3.5.8-r0). `ldap3` dormant (accepted I3).

```
[ID]  G18-1
Title:            Base image one openssl patch behind (CVE-2026-14456, fix in Alpine 3.5.8-r0)
Category:         Security
Severity:         Low — QUIC server code path is not used by the app; pick up the Dependabot digest bump
Location:         Dockerfile:6,18 (digest pin); Trivy output
```

```
[ID]  G18-2
Title:            `requirements.in` regeneration comment still references `python:3.13-alpine`
Category:         Correctness (docs)
Severity:         Info
Location:         requirements.in:3
```

---

### Area 19 — Repo config

Verdicts: `.gitignore` covers `.env`, `secrets/`, `data/`, `instance/`, `venv/`, `.claude/`, `deploy/tls/`, override compose; `.claude/settings.local.json` is untracked/ignored (08-08 INFRA-3 fixed ✔), contains no secrets, grants broad local auto-approvals (`git push *`, `docker exec *`, `docker compose *`, `tar czf *`) — a local policy, not a repo risk.

```
[ID]  G19-1
Title:            Untracked, un-ignored dev scripts (`scripts/seed_demo.py`/`.sh`) with a `--remove` that deletes any CA named "Demo *" and destroys matching HSM objects
Category:         Correctness
Severity:         Info — decide: commit (they are useful) or ignore; document the naming hazard
Location:         git status; seed_demo.py:71-111
```

```
[ID]  G19-2
Title:            No `*.pem`/`*.key`/`*.p12` globs in `.gitignore`
Category:         Security
Severity:         Info — an exported key saved into the checkout would be committable
Location:         .gitignore
```

---

### Area 20 — Docs & meta-review

```
[ID]  G20-1
Title:            README `docker compose exec app flask …` examples cannot read the secrets under `cap_drop: ALL` (root lacks DAC_OVERRIDE) — must be `exec -u app`; stale/insecure API examples
Category:         Correctness (security-UX)
Severity:         Low — the documented CRL-refresh command fails when copy-pasted into cron (a plausible root cause of G4-1)
Confidence:       Confirmed (live: `docker compose exec app python -c "open('/run/secrets/master_passphrase')"` → PermissionError)
Status vs prior:  New
Location:         README.md:146, 153-154, 240-242, 428-430 (`docker compose exec app flask …`, 0 occurrences of `-u app`);
                  README.md:363-364 `GET /certificates/<id>/download?format=pem|der|pkcs12`, `GET …/download-key` and :374-377
                  `download?format=pkcs12&password=changeit` — both are POST-only (certificates.py:257-259, :310) and the example puts a
                  password in a URL; README.md:460 lists `RATE_LIMIT_ENABLED` default `false` (actual `true`, config.py:100)
Recommended fix:  Add `-u app` everywhere; replace the download examples with POST forms; fix the defaults table.
```

Meta-review of the three prior assessments: see Phase 2 §F. Docs otherwise steer to `init-secrets.sh`, the TLS overlay and `SERVER_NAME_FOR_OCSP` pinning correctly; CLAUDE.md's design notes matched the code in every point I checked (one nuance: "locally deactivating an LDAP user blocks them" is true at next request thanks to Flask-Login's `is_authenticated → is_active`).

---

### Area 21 — Licensing
GPLv3 (`LICENSE`). Runtime dependencies are MIT/BSD/Apache-2.0 plus `ldap3` (LGPLv3) — all GPLv3-compatible; Bootstrap is loaded from a CDN (not redistributed); SoftHSM (BSD) is installed in the image from Alpine. Clean.

---

### Area 22 — Test suite

Run: `python -m pytest tests/ -q -rs` → **615 passed, 18 skipped in 334.8 s** (Python 3.12 venv). All 18 skips are `tests/test_softhsm.py` ("softhsm2-util not installed" on this host); CI installs `softhsm2` (`docker-publish.yml:35-38`) so the HSM differential gate runs there (latest runs green; the Alpine-image scan doc also records the full suite passing inside the image).

Assertions verified as semantic (not status-only): byte-identical DER (`test_softhsm.py:95,:184`); TBS identity + chain verify (`:116-118`); OCSP field parity + signature verification (`:222-234`); PoP with a tampered CSR (`test_hardening_1_1_0.py:39-62`); revoked serial in CRL and REVOKED OCSP for a revoked intermediate (`:100-134`); cache never serves revoked as GOOD (`test_crl_ocsp_availability.py:95-117`); lockout trigger and release (`test_login_lockout.py`); sole-admin exemption (`test_lockout_availability.py:16-27`); JSON 401/403 (`test_fix_api_auth.py:20-29`, `test_json_api.py:177-191`); allow-list no-leak (`test_json_api.py:138-172` — adding a field fails the test); cross-site Basic CSRF (`test_fix_api_auth.py:65-81`); open-redirect matrix incl. backslash (`test_hardening_1_1_0.py:206-216`); export POST-only and password-not-from-query (`test_ca_export.py:124-152`); deactivated login refused (`test_rbac.py:200-213`); last-admin guards (`:216-252`). Fixtures: in-memory SQLite, throwaway SoftHSM token in tmp, `ldap3`/`urllib` mocked, update-check/webhooks/limiter/dual-control pinned off — offline and deterministic; test secrets are constants.

```
[ID]  G22-1
Title:            Coverage gaps matching this report's findings; one test pins non-RFC OCSP behaviour
Category:         Correctness
Severity:         Low
Location:         missing: sub-CA under a revoked parent (G4-2); key-size ceiling (G7-1); non-RSA/EC CSR keys (G4-3); dual-control user-management
                  bypass (G3-1); audit row on failed CRL refresh (G10-1); `path_length<0`/`reason` validation (G7-3); `next` round-trip (G6-3);
                  a live-session deactivation test (positive, currently untested). tests/test_routes.py:203-213 asserts the 500 for malformed OCSP (G8-2).
Recommended fix:  Add the negative tests above; change the OCSP test to expect `MALFORMED_REQUEST`.
```

---

### Area 23 — Git history

240 commits; tags to `v2.12.3`; 14 local and 69 remote-tracking branches (stale feature branches — hygiene only). Scans over **all** revisions: no `.env`, `secrets/`, `*.pem|key|p12|pfx` ever added; no blob > 300 KB (the 2026-08-05 `venv/` purge holds); credential-pattern grep hits only the template placeholder `-----BEGIN PRIVATE KEY-----` in `ca/create.html`.

```
[ID]  G23-1
Title:            A dev SQLite DB remains in history (`instance/cert-manager.db`, first commit → removed 2026-08-06, never purged)
Category:         Security
Severity:         Info — 32 KB blob `3d3251d` holds one `users` row (`admin`, scrypt hash) and zero CAs/certs; no key material
Confidence:       Confirmed (blob extracted and inspected)
Status vs prior:  Prior-claim-unverified — 08-08 "history independently re-verified clean" grepped `.env/.key/.pem/.p12` but not `.db`;
                  05-08 A2 correctly says "it remains only in git history"
Recommended fix:  Purge if the repo is public and that early password was ever reused; otherwise accept.
```

---

### Area 24 — Live/runtime state

Facts are consolidated in Phase 0. Findings tied to runtime: **G4-1** (all CRLs expired, no scheduler), **G8-3** (`localhost` URLs in issued certs), **G16-1/G5-1** (legacy secret lengths), **G2-1** (`SECRET_KEY`/`ADMIN_PASSWORD` in env), **G6-1** (HTTP). Verified positives: PID 1 non-root; caps/no-new-privileges; data/secrets modes; one SoftHSM token; debug off; healthcheck passing; `docker compose exec app` (root) **cannot** read the secrets (good for least privilege, bad for the README — G20-1). Additional Info: `.env` (0600) still contains `ADMIN_PASSWORD`; the `docker` group (uid 1000 is a member) can read `SECRET_KEY` via `docker inspect`.

---

### Area 25 — Threat model & data-at-rest

Adversary set completeness — the documented set (unauthenticated network, `csr_requester`, malicious admin, host reader, LAN MITM, supply chain) should add: **operator omission** (the missing CRL cron is the single most impactful issue found), **backup thief** (`data/` carries the DB, the SoftHSM token and four `.bak` copies; `.env` with `SECRET_KEY` sits next to it), **docker-group member** (root-equivalent: `docker exec`, reads `/run/secrets`), and **stolen admin session over HTTP**.

Blast radius today:

| Asset | Protection at rest | Falls with |
|---|---|---|
| 10 software CA keys, 18 escrowed leaf keys, webhook/LDAP secrets | Fernet under one 14-byte passphrase (G16-1) | `data/` + passphrase (or a weak passphrase) |
| 3 HSM CA keys | SoftHSM token, user PIN 32 chars / SO PIN 8 (G5-1) | `data/softhsm/tokens` + SO PIN brute force |
| Admin session | `SECRET_KEY` (env, 24 chars) | `docker inspect`, `/proc/environ`, LAN sniffing (G6-1) |
| Password hashes | scrypt | offline cracking only |
| Audit log | plain, mutable SQLite (accepted G1) | any DB writer |

The intended boundary (CA keys protected, leaf escrow accepted, audit best-effort) matches the docs — except that the SO PIN makes "HSM" no stronger than software against volume theft, and a single legacy passphrase guards everything else.

---

## Phase 2 — Consolidation

### A. Findings at a glance

| ID | Title | Cat | Sev | Conf | Location |
|---|---|---|---|---|---|
| G4-1 | Live CRLs expired; no in-app refresh, no scheduler | Both | **High** | Confirmed (live) | crl_service.py:129-130, config.py:73, public.py:29-37 |
| G6-1 | Plain HTTP on the LAN — creds/session/keys in cleartext | Sec | **High** | Confirmed (live) | docker-compose.yml:6-7,28; ca.py:333-362 |
| G4-2 | Sub-CA creatable under a revoked parent; issues leaves | Both | Medium | Confirmed (PoC) | ca.py:186-199; ca_service.py:147-150 |
| G7-1 | CSR keygen unbounded → authenticated DoS; 1024-bit accepted | Sec | Medium | Confirmed (PoC) | csr.py:75-78; csr_service.py:13-19 |
| G8-1 | Non-latin-1 names break public CRL/CA downloads (gunicorn latin-1) | Corr | Medium | Confirmed/Plausible | public.py:12-15; gunicorn wsgi.py:418 |
| G8-3 | Host-derived AIA/CDP — live certs embed `localhost:5000` | Corr | Medium | Confirmed (live) | certificates.py:64-66; csr.py:171-173 |
| G3-1 | Dual control bypass via user create / password reset | Sec | Medium (cond.) | Confirmed (PoC) | users.py:24-52,120-147 |
| G5-1 | SoftHSM SO PIN 8 bytes bounds HSM at-rest strength | Sec | Medium (cond.) | Confirmed length | secrets/pkcs11_so_pin |
| G16-1 | Legacy 14-byte master passphrase / 24-char SECRET_KEY, entropy unknown | Sec | Medium (cond.) | Needs-verification | secrets/master_passphrase; .env |
| G4-3 | Key floor ignores DSA/Ed25519 CSR keys | Both | Low | Confirmed (PoC) | policy.py:35-45 |
| G4-4 | EC curve by size; EC keyEncipherment; SAN prefixes | Corr | Low | Confirmed | policy.py:44-45; cert_service.py:28-44,129-142 |
| G6-2 | Admin-set passwords bypass min length / no forced rotation | Sec | Low | Confirmed | users.py:27-46,132-145 |
| G6-3 | `next` redirect never honoured | Corr | Low | Confirmed (live) | __init__.py:234; auth.py:23-29 |
| G6-4 | No session invalidation on password change | Sec | Low | Confirmed | auth.py:108-115 |
| G7-2 | csr routes turn ValueError into 500 | Corr | Low | Confirmed (PoC) | csr.py:62-64,246-248 |
| G7-3 | Negative path_length → 500; free-text reason | Corr | Low | Confirmed (PoC) | ca.py:172; certificates.py:220 |
| G8-2 | OCSP malformed → 500; no GET form | Corr | Low | Confirmed (live) | public.py:74-89 |
| G2-1 | SECRET_KEY/ADMIN_PASSWORD as env literals | Sec | Low | Confirmed (live) | docker-compose.yml:11,23 |
| G10-1 | Revocation persists, audit row lost on CRL-refresh failure | Both | Low | Confirmed (PoC) | crl_service.py:44-52; certificates.py:222-226 |
| G10-2 | CLI mutations unaudited | Sec | Low | Confirmed | cli.py |
| G13-1 | migrate-to-hsm `--yes`, unaudited, orphan on verify failure | Both | Low | Confirmed | cli.py:26,57-72 |
| G13-2 | No master-passphrase rotation tooling | Sec | Low | Confirmed | cli.py (absent) |
| G17-1 | Unpinned CI tooling | Sec | Low | Confirmed | docker-publish.yml:41-44,51 |
| G18-1 | Base image one openssl patch behind (CVE-2026-14456) | Sec | Low | Confirmed (Trivy) | Dockerfile:6,18 |
| G20-1 | README exec examples fail under cap_drop; stale insecure API examples | Corr | Low | Confirmed (live) | README.md:146,153,240,363-377,428,460 |
| G22-1 | Test gaps mirroring the above; OCSP 500 pinned | Corr | Low | Confirmed | tests/ |
| G4-6/7/8, G5-2/3, G6-5/6, G7-4/5/6, G8-4, G1-1/2/3, G2-2, G9-1/2, G10-3, G11-1, G12-1, G14-1/2, G15-2, G17-2, G18-2, G19-1/2, G23-1 | Info items (see areas) | — | Info | Confirmed | — |

Counts: **2 High, 7 Medium (3 conditional), 17 Low, ~24 Info.** No Critical. No unauthenticated authentication bypass, privilege escalation, serializer leak, IDOR, injection, or CA-key exfiltration path was found.

### B. Positive controls observed (verified, cited above)

PBKDF2-600k + per-record salt + authenticated Fernet; 159-bit random serials; SHA-256 only; leaf `ca=False` with `keyCertSign/cRLSign` hard-off and CSR extensions ignored; CSR proof-of-possession at the signing call site; validity caps + issuer clamp + stored real `notAfter`; expired-issuer refusal (leaf paths); revocation regenerates the issuing CRL, cascades to sub-CAs, lists revoked intermediates in the parent CRL and answers them REVOKED via OCSP; atomic monotonic `crlNumber`; OCSP parses/looks up before any key use, unsigned UNAUTHORIZED for unknown/keyless/pending, status-keyed response cache, request-hash mirroring, byKey responder; public CRL/CA endpoints strictly read-only. **HSM:** RSA cert/CRL DER byte-identical (asserted, and live chains/CRLs/OCSP verify), EC `r‖s`→DER correct, OCSP semantic parity incl. NULL RSA params, `CKA_SENSITIVE/EXTRACTABLE=false`, export genuinely refused, cross-backend intermediates correct, verify-before-scrub migration, serialised sessions reset on error, PINs via secret files and never logged, post-fork `C_Initialize`. **Auth:** scrypt hashes never serialised; local-first break-glass; LDAP injection/anon-bind/TLS handled correctly (disabled here); HMAC credential cache that re-reads the user row; per-account lockout across session+Basic with the sole-admin exemption; generic failure messages; robust `next` validation; POST+CSRF logout; forced first-login rotation incl. Basic-Auth refusal; **deactivation and demotion apply to live sessions immediately** (Flask-Login `is_authenticated → is_active`); last-admin/self-deactivation guards. **API:** allow-list serializers (tests fail on any new field); ownership before content negotiation; JSON 401/403/404/405/500; CSRF skipped only for valid, non-cross-site Basic Auth; key/PKCS#12 exports POST-only with the password from the form; header-injection-safe filenames; nosniff/DENY/nonce-CSP/Referrer-Policy/HSTS on every response. **Templates:** autoescape intact, no `|safe`, every form CSRF-tokened, SRI+crossorigin, `noopener`. **Infra:** digest-pinned Alpine base, hash-locked deps with `--require-hashes` (30/30 hashed; OSV clean today), pip removed, non-root PID 1 with `cap_drop ALL`/`no-new-privileges`/limits/healthcheck, secrets bind-mounted read-only, root inside the container cannot read them, idempotent single SoftHSM token, SHA-pinned actions with minimal permissions, publish gated to `v*` tags with keyless cosign + SLSA + SBOM, weekly pip-audit, Dependabot; TLS overlay provided; `init-secrets.sh` now generates strong values with `umask 077` and never overwrites. **Tests:** 615 passing, semantic assertions, offline fixtures, HSM parity gate in CI. **History:** no secrets/keys/large blobs ever committed.

### C. Consolidated open questions / needed context

1. **CRL consumers:** does any relying party on the LAN perform CRL or OCSP checks? (Sets the real-world impact of G4-1, G8-2, G8-3.) Was a `crl refresh` cron ever intended on this host?
2. **Legacy secrets:** how were the 14-byte master passphrase (2026-08-05) and the 24-char `SECRET_KEY` generated — CSPRNG or typed? (G16-1: Medium vs Info.)
3. **SO PIN:** is re-keying/re-issuing the three HSM CAs acceptable to move to a 32-char SO PIN? Are `data/` backups encrypted? (G5-1.)
4. **Transport:** is the LAN considered trusted, and is the Caddy overlay planned? (G6-1.)
5. **`dns.home`:** is that certificate in real use? Its CDP/AIA point at `localhost:5000` (G8-3).
6. **Dual control:** will a second admin exist here? (G3-1 severity; also changes lockout behaviour.)
7. **GitHub:** are `v*` tags protected (release publishing gate)? (Area 17.)
8. **Seed scripts:** commit or ignore `scripts/seed_demo.*`? (G19-1.)

### D. Prioritised remediation roadmap

1. **Today (minutes, no code):** `docker compose exec -u app app flask crl refresh --all`; install a cron/systemd timer with `-u app` (G4-1/G20-1). Set `SERVER_NAME_FOR_OCSP=10.0.0.82:5000` (or the future TLS name) and restart; re-issue `dns.home` if in use (G8-3). Delete `ADMIN_PASSWORD` from `.env` (G2-1). Alert on `chancery_ca_crl_next_update_timestamp_seconds` in Prometheus.
2. **This week (small code changes):** key-size allow-list in all three keygen paths (G7-1); `is_revoked`/expiry guard for parents in `create_intermediate_ca` + route (G4-2); `except ValueError` in `csr.sign`/`csr.create` (G7-2); `else: raise` in `enforce_public_key_strength` (G4-3); ASCII/RFC 5987 filenames (G8-1); audit-before-refresh in revocation (G10-1); `MIN_PASSWORD_LENGTH` + `must_change_password` on admin-set passwords (G6-2); `path_length`/`reason` validation (G7-3); README `-u app` + POST examples + defaults (G20-1); `request.full_path` in the unauthorized handler (G6-3). Add the corresponding tests (G22-1).
3. **Next sprint:** deploy the TLS overlay (G6-1) and `SECRET_KEY_FILE` (G2-1); in-app CRL refresh (single-flight) and a saner default window (G4-1 code half); OCSP `malformedRequest` + GET form (G8-2); dual-control gate on user management (G3-1); passphrase-rotation CLI (G13-2) then verify/rotate the legacy master passphrase and `SECRET_KEY` (G16-1); re-key the HSM token with a strong SO PIN and keep the token dir out of routine backups (G5-1); audit CLI mutations (G10-2); session versioning (G6-4); pin CI tooling (G17-1); take the Dependabot base-image bump (G18-1); `read_only: true` + tmpfs (G14-2).

### E. Executive risk summary

Chancery's cryptographic core and authorization model held up under an adversarial re-read: the CA cannot be tricked into minting a CA certificate from a CSR, proof-of-possession is enforced at the point of signing, serials and digests are correct, the SoftHSM re-implementation reproduces pyca's DER byte-for-byte (confirmed on the live CAs, CRLs and OCSP responses), no serializer leaks key material or hashes, every route enforces role and ownership before content negotiation, and the container/CI/supply-chain posture is genuinely hardened. Nothing found allows an unauthenticated party, or a `csr_requester`, to escalate, mint, or exfiltrate a key.

The risk that exists today is operational and correctness-shaped rather than cryptographic. First, **revocation via CRL is currently broken on the live instance**: every published CRL expired on 24 August because the fix for the previously reported "CRL silently expires" finding was a CLI that depends on a cron job that was never installed — and the README's copy-paste command would fail under the container's capability drop anyway. Second, most live certificates embed `http://localhost:5000` as their OCSP/CRL location because `SERVER_NAME_FOR_OCSP` was left at its default, so relying parties could not check revocation even with fresh CRLs. Third, the instance serves plain HTTP on the LAN, so an on-path attacker can take the admin session or read an exported CA key in transit; the project ships a TLS overlay that closes this in one command. Fourth, a low-privilege account can deny service to the whole CA (including OCSP) by requesting 16384-bit CSR keys, and an admin can keep issuing under a revoked hierarchy by creating a sub-CA beneath the revoked parent.

The at-rest story is good but rests on two legacy secrets: a 14-byte master passphrase and an 8-character SoftHSM SO PIN that both predate the repository's secret generator. If those were typed rather than generated, a stolen `data/` directory is crackable; confirming their provenance (or rotating them once rotation tooling exists) is the one item in this report whose severity depends on an answer only the owner has. Everything else is Low/Info hardening and test coverage.

### F. Reconciliation against the prior assessments (10-07, 05-08, 08-08)

- **Verified fixed in code as claimed (08-08 remediation table):** DoS-1 (rate limiting on, before the Basic hook), DoS-2/AUTH-4 (sole-admin exemption, unlock CLI, reset/reactivate clear lockout), TMPL-1 (nonce CSP, no `unsafe-inline`), META-1/META-2 (JSON negative tests, allow-list assertions), PKI-3 (clamped `not_after` stored), HSM-1/HSM-3/CORE-3 (curve check, session reset, verify-before-scrub), PKI-4 (leaf paths), PKI-6, PKI-7, AUTH-2, AUTH-3, CORE-2/4/5, API-3/4/5, TMPL-3, INFRA-2/3/5/6 (limits+healthcheck), and the 05-08 batch (B1–B5, C1–C5, D2, D5, D6, E2, E3, F2, F3, G2, H1, H2, I1, I2, J1, J2). Each was re-read at its current location.
- **Regressed / overstated:**
  - **PKI-1 → G4-1.** Fixed in code, but the deployment never got the scheduler; the outcome on the live box is exactly the original finding.
  - **INFRA-4** ("compose cookie/admin-password defaults hardened"): the reference compose still ships `ADMIN_PASSWORD` as an env literal and `SESSION_COOKIE_SECURE=false`; only a comment changed (G2-1). Documented, but not "fixed".
  - **INFRA-6:** read-only rootfs still not done (G14-2).
  - **INFRA-1 (SO-PIN half):** still 8 bytes (G5-1).
  - **API-2/TMPL-2 (C4):** the accepted residual now has measurable harm — `localhost` URLs inside issued certificates (G8-3).
  - **E1:** "Mitigated" by an overlay that this deployment does not use (G6-1).
  - **08-08 "git history independently re-verified clean":** accurate for its pattern set but missed the `.db` blob that 05-08 itself acknowledged (G23-1).
  - **05-08 D4 "no dual control — accepted"** was superseded by the 2.10.0 feature, which is bypassable by one admin (G3-1).
- **Refuted prior claims:** none material; the Flask-Login deactivation behaviour claimed in README/CLAUDE.md is correct (checked, positive).
- **Coverage gaps in prior reports (new surface since 08-08):** LDAP admin UI and webhooks (assessed: correct, SSRF/exfil by a malicious admin noted as Info), dual control (G3-1), metrics tokens (clean), CSRF error handling (clean), the JSON API's key-size ceiling (G7-1), the gunicorn header-encoding path (G8-1), the audit-loss failure path (G10-1), and the deployment-level checks (expired CRLs, `localhost` URLs, legacy secrets) that a code-only review cannot see.
- **Profile drift:** Python 3.14.7 / SQLAlchemy 2.0.52 (the mandate's profile said 3.13 / 2.0.51); `requirements.in` still says `python:3.13-alpine`; README defaults table stale (G20-1).
