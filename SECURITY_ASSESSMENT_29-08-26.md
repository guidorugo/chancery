# Chancery v2.12.3 — Independent Security & Correctness Assessment

> **Assessment date:** 2026-08-29 · **Target:** `guidorugo/chancery` at `db182cd` (v2.12.3, `master`). A throwaway test instance built from the same commit with the reference `docker-compose.yml` was used only to corroborate code findings; its state is not audited.
> **Method:** full read of every file in all 25 areas (7,791 app lines, 26 templates, 42 test modules, infra/CI/docs/prior reports), read-only corroboration on the test instance (`docker inspect/top/exec -u app`, `openssl` verification of served CRL/OCSP/chains), executable PoCs against an **in-memory** app instance, full test-suite run, OSV + Trivy scans. Every "Confirmed" finding below was either reproduced or read verbatim in the cited lines.
> **Independence caveat:** produced by Claude (Fable 5) on the owner's request; the code was also AI-assisted. Not a third-party audit.

---

## Phase 0 — Scope confirmation & blocking questions

**Repo access:** confirmed. Working tree clean except two untracked dev files (`scripts/seed_demo.py`, `scripts/seed_demo.sh`). 240 commits, tags through `v2.12.3`.

**Test instance:** a throwaway container built from `db182cd` with the reference `docker-compose.yml`, used only to corroborate code findings (`GET /health` → 200). Its data and secrets are not audited.

**Runtime profile (from the shipped artefacts; corroborated on the test instance):**

| Item | Value |
|---|---|
| Gunicorn | `--workers 2 --timeout 120`, sync workers, no `--preload` (`entrypoint-app.sh:52-56`) |
| Process identity | PID 1 = gunicorn, uid 1000; `cap_drop ALL` + `CHOWN,SETUID,SETGID`; `no-new-privileges`; rootfs **rw** (`entrypoint.sh`, `docker-compose.yml:107-114`) |
| Network | `0.0.0.0:5000` and `[::]:5000` published; plain HTTP; no proxy (`TRUSTED_PROXY_COUNT` empty → 0) — the reference compose |
| Security defaults | `SESSION_COOKIE_SECURE=false`, `SERVER_NAME_FOR_OCSP=localhost:5000` (**default → Host auto-detect active**), `OCSP_URL_SCHEME=http`, `RATE_LIMIT_ENABLED=true`, Basic Auth on, dual control / LDAP / webhooks / metrics off, `UPDATE_CHECK_ENABLED=true`, `KEY_BACKEND=software` (compose defaults) |
| Secrets | `MASTER_PASSPHRASE_FILE`, `PKCS11_USER_PIN_FILE`, `PKCS11_SO_PIN_FILE` via Docker secrets (0600, app uid); `SECRET_KEY` and `ADMIN_PASSWORD` as **env literals** (compose) |
| Data | `data/` 0700, DB 0600 (app uid); SoftHSM token dir 0700, one token — enforced by `entrypoint-app.sh` |
| Runtime versions | Python **3.14.7** (profile said 3.13), SQLAlchemy **2.0.52**, cryptography 50.0.0, Flask 3.1.3, gunicorn 26.2.0 |
| Prior assessments | **three** on disk (10-07, 05-08, 08-08), not two; reconciled against all three in Phase 2 §F |

**Blocking questions:** none — every §12 item was pre-answered and could be verified against the code and the shipped artefacts. Owner-knowledge questions that change a severity are consolidated in Phase 2 §C.

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
- Revocation propagation: cert revoke → commit → `refresh_crl` (`crl_service.py:44-52`); CA revoke cascades, then refreshes the **parent** CRL and each revoked CA's CRL (`:63-98`); parent CRL lists revoked sub-CAs (`:151-154`); OCSP resolves sub-CA rows (`ocsp_service.py:114-118`). Corroborated on the test instance: a revoked sub-CA is listed in its parent's CRL and revoked leaves in their issuer's.
- CRL number: atomic SQL increment then re-read inside the same transaction (`crl_service.py:117-124`); SQLite's single-writer lock serialises the two workers, so numbers are monotonic (test `test_hardening_quickwins.py:86-98`).
- OCSP: request parsed and subject looked up **before** any key use (`ocsp_service.py:105-122`); keyless/pending/unknown → unsigned `UNAUTHORIZED` (`:91-95,:102-103,:121-122`); CertID hash mirrored from the request with an allow-list (`:57-76`); responder byKey; response cache keyed on `(ca, serial, is_revoked, alg)` (`:127`). Corroborated: a software CA and an HSM CA both answer `Response verify OK` (see Area 5).
- Encoding/injection: subject built through pyca `NameAttribute` with field-named validation (`policy.py:88-113`); `DNSName` is ASCII-only in pyca; IPs via `ipaddress` (`cert_service.py:34-36`); nothing user-controlled reaches DER unescaped.

```
[ID]  G4-1
Title:            Published CRLs expire 7 days after generation with no in-app refresh — nothing shipped installs the timer the CLI depends on
Category:         Both
Severity:         High — once the window elapses, revocation via CRL is non-functional for any deployment that follows the shipped compose/README; strict validators hard-fail, lenient ones ignore revocation
Confidence:       Confirmed (code; corroborated on the test instance)
Status vs prior:  Regressed — 08-08 PKI-1 was closed by adding `flask crl refresh` "cron-friendly"; the cron half exists in none of the shipped artefacts (compose, entrypoint, README install steps)
Location:         crl_service.py:129-130  `.last_update(now)` / `.next_update(now + timedelta(days=validity_days))`
                  config.py:73            `CRL_VALIDITY_DAYS = int(os.environ.get("CRL_VALIDITY_DAYS") or "7")`
                  public.py:29-37         serves `ca.crl_pem` verbatim, never regenerates
                  cli.py:237-268          `crl refresh` is the only refresh path (a CLI)
Preconditions:    none (the default window elapses on its own)
Description:      The app stamps nextUpdate = now+7d and has no scheduler; the only refresh is an operator cron running the CLI. Neither
                  `docker-compose.yml`, the entrypoint nor the README install steps set one up, and the README's example command fails under
                  the shipped capability drop (G20-1). Corroborated: on a test instance left running past the window, every served CRL
                  reported a past nextUpdate.
Impact / attack:  Every issued cert carries a CDP pointing at these CRLs. OpenSSL-style validators return X509_V_ERR_CRL_HAS_EXPIRED
                  (outage); soft-fail validators skip revocation entirely (a revoked leaf keeps working). OCSP is unaffected (24 h fresh).
Reproduction:     after CRL_VALIDITY_DAYS have elapsed: curl -s http://<host>:5000/public/crl/<ca-id>.crl | openssl crl -inform DER -noout -nextupdate → a past date
Recommended fix:  Ship the timer: document `docker compose exec -u app app flask crl refresh --all` plus a cron/systemd unit (note `-u app`,
                  see G20-1) as an install step. Code: regenerate lazily on the public serve path when now ≥ nextUpdate − margin (single-flight
                  via a DB flag so one worker signs), or a background refresher; raise the default window; alert on the existing
                  `chancery_ca_crl_next_update_timestamp_seconds` metric wherever `/metrics` is scraped.
Open questions:   Which relying parties consume the CRLs?
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
Preconditions:    admin credentials (or a stolen admin session)
Description:      Neither the route nor the service checks `parent_ca.is_revoked` (nor expiry, see G4-6). The UI dropdown hides revoked
                  parents (`_create_page_context`, ca.py:46-50) but the server accepts any `parent_id`.
Impact / attack:  PoC: revoke root R1 → POST /ca/create parent_id=R1 → 201; child.is_revoked=False, in signing_capable(); POST
                  /certificates/create from child → 201. New leaves' AIA/CDP point at the new intermediate, whose OCSP says GOOD.
                  A CA-compromise response ("revoke the CA") therefore does not stop issuance by whoever holds admin.
Reproduction:     PoC-1 (in-memory app instance; script not committed) — output: `POST /ca/create parent=revoked -> 201 … leaf issued … -> 201`
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
Reproduction:     PoC-4 (in-memory app instance; script not committed)
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

Open questions (Area 4): CRL consumers; Ed25519 policy; CRL window vs refresh cadence.

---

### Area 5 — Key backends / HSM

Files read in full: `app/services/keybackend/{base,__init__,software,softhsm,pkcs11_session}.py`, `tests/test_softhsm.py`, `tests/test_keybackend.py`.

**Checklist verdicts:**
- **Byte parity (certs/CRLs):** `_reassemble` keeps `tbs_*` and `signature_algorithm` from the throwaway-signed object and swaps only the signature (`softhsm.py:101-111`); RSA uses `CKM_SHA256_RSA_PKCS` (`:94`), deterministic PKCS#1 v1.5 → identical DER. Asserted literally: `assert hsm_der == soft_der` (`test_softhsm.py:95`) and `assert soft == hsm` for CRLs (`:184`). The tests are not skipped in CI (`docker-publish.yml:35-38` installs `softhsm2`; latest runs green) — they **do** skip in the dev venv (no `softhsm2-util`), see Area 22.
- **EC path:** SHA-256 digest then raw `CKM_ECDSA` (`softhsm.py:97-98`); `encode_ecdsa_signature` (python-pkcs11) splits `r‖s` at `len//2` and DER-encodes two INTEGERs — correct for P-256/384/521 (66+66 for P-521), leading-zero padding handled by asn1crypto's minimal INTEGER encoding. Test asserts TBS identity and `verify_directly_issued_by` (`:113-118`).
- **OCSP over HSM:** CertID lifted from a throwaway pyca request (`:258-262`), responder `by_key` = SKI (`:264-269`), whole-second GeneralizedTime (`:117-124`), revoked reason names map 1:1 to asn1crypto `CRLReason` (`:126-137`). AlgorithmIdentifier: asn1crypto `sha256_rsa` encodes **with** NULL params (`300d06092a864886f70d01010b0500` — verified in the venv), `sha256_ecdsa` without — identical to pyca. Semantic-parity test (`:202-234`) plus signature verification against the CA key.
- **Corroborated on the test instance:** an HSM-backed intermediate chains to a software root — `openssl verify: OK`; an HSM-backed root's CRL — `verify OK`; OCSP via an HSM intermediate — `Response verify OK`, GOOD, byKey; an HSM-issued leaf chains root → HSM intermediate → leaf — `OK`.
- **Session management:** one logged-in session per process guarded by an `RLock` for the whole operation, closed and dropped on any exception (`pkcs11_session.py:16-21,48-72`); gunicorn runs without `--preload`, so `C_Initialize` happens post-fork in each worker; sync workers are single-threaded. No race found.
- **PINs:** `_read_secret("PKCS11_USER_PIN")` / `SO_PIN` (`config.py:87-88`) from `/run/secrets/*` (compose `:48-49`); never logged (grep). `hsm_available()` requires the user PIN (`keybackend/__init__.py:53-68`).
- **Key attributes:** generate: `TOKEN=True, PRIVATE=True, SENSITIVE=True, EXTRACTABLE=False, SIGN=True` (`softhsm.py:149-153,164-168`); import: same (`:205-211`). Export refused: `is_exportable` false for softhsm (`models/ca.py:66-70`), `_refuse_if_not_exportable` (`ca_service.py:539-546`), buttons hidden (`ca/detail.html:27-35,122`); tested (`test_softhsm.py:322-332`).
- **Cross-backend intermediates:** child key in the child's backend, parent's backend signs (`ca_service.py:153-159,239-240`); tests `:281-312`.
- **Migration:** `verify_signing_key` signs a nonce and verifies against the CA cert **before** `private_key_enc = b""` (`cli.py:66-72`, `softhsm.py:219-236`).

```
[ID]  G5-1
Title:            SoftHSM PIN strength is never checked — the token's at-rest strength is bounded by the weaker of the two PINs, and an existing token's SO PIN has no rotation path
Category:         Security
Severity:         Info — the generator writes 32-char PINs for new deployments; a token initialised with short PINs (pre-generator, or hand-typed) keeps them silently
Confidence:       Confirmed (read code)
Status vs prior:  Carried — 08-08 INFRA-1 "SO-PIN half deferred"
Location:         entrypoint-app.sh:22-35 (PIN files read and passed to `softhsm2-util --init-token` with no length check);
                  scripts/init-secrets.sh:85-91 (`rand_alnum 32`, new deployments only); keybackend/__init__.py:53-68 (`hsm_available` checks presence only)
Description:      SoftHSM2 wraps the token's object-encryption key under both PINs (C_InitPIN by the SO re-wraps it), so an offline attacker
                  with the token files needs only the weaker PIN; SoftHSM's PIN KDF is fast. HSM keys are non-extractable, so moving to a
                  stronger SO PIN means a new token and re-keying every HSM CA.
Recommended fix:  Warn (or refuse) at startup when a PIN file is below a minimum length; document the re-key procedure; advise keeping
                  `data/softhsm` out of unencrypted backups.
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

Open questions (Area 5): intended hash for P-521.

---

### Area 6 — Authentication

Files read in full: `auth_service.py`, `ldap_service.py`, `ldap_settings_service.py`, `routes/auth.py`, `models/user.py`, `extensions.py`, relevant parts of `__init__.py`, `routes/users.py`.

**Checklist verdicts:**
- Hashing: Werkzeug `generate_password_hash` default → `scrypt:32768:8:1$…` (`models/user.py:48-49`; corroborated). Never serialised (`to_dict` allow-list `:63-73`; test asserts `set(u) <= allowed`). `UNUSABLE_PASSWORD="!"` short-circuits `check_password` (`:55-61`).
- Local-first: local rows never fall through to LDAP (`auth_service.py:55-66`); LDAP only when the *effective* config enables it (`:68-71`); local deactivation wins for LDAP users (`:90-92`).
- Empty/anonymous bind: rejected before any bind (`ldap_service.py:55`); DN/filter escaping (`:62,:141-143`); `auto_referrals=False`, TLS verify default (`:88,:118`). LDAP is off by default.
- Basic Auth cache: HMAC(random per-process key, `user\0pass`) (`:242,:250-252`), `compare_digest` (`:267`), hit re-reads the `User` row and re-checks username + active (`:311-313`); TTL 60 s, 256 entries.
- Lockout: per-account, DB-backed, applies to Basic and session (`:57-66,:116-139`); the **sole active admin is never hard-locked** (`:128-133`, DoS-2 design) — a single-admin instance therefore has no lockout on its only account (G6-5).
- `next`: `_is_safe_url` rejects scheme/netloc/`//`/backslash/control chars (`auth.py:11-29`) — correct (but see G6-3).
- Sessions: `HttpOnly`, `SameSite=Lax`, secure flag from config (`config.py:40-45`), 30-min sliding lifetime (`:91-95`, `__init__.py:452-454`); logout is POST+CSRF (`auth.py:120-127`). Over the reference compose (plain HTTP, `SESSION_COOKIE_SECURE=false`) the cookie is `HttpOnly; Path=/; SameSite=Lax` without `Secure`, as designed; transport is a deployment choice (G15-1).
- **Deactivation/demotion of a live session (checked, positive):** Flask-Login 0.6's `UserMixin.is_authenticated` returns `self.is_active`, which the model overrides with `is_active_user` (`models/user.py:32-34`) → a deactivated user's existing session is refused on the next request; role is re-read per request. PoC: after `toggle-active`, the victim's session got 302 and a write attempt created nothing; demotion applied immediately.

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
Confidence:       Confirmed (PoC-7; corroborated on the test instance)
Status vs prior:  New
Location:         __init__.py:234 `return redirect(url_for(login_manager.login_view, next=request.url))`;
                  auth.py:23-29 `not parts.scheme and not parts.netloc and target.startswith("/")`
Reproduction:     `GET /` → `Location: /auth/login?next=http://<host>:5000/`; PoC: after login `Location = /` (expected `/ca/`)
Recommended fix:  Pass `request.full_path` (or `request.script_root + request.full_path`) instead of `request.url`.
```

```
[ID]  G6-4
Title:            No server-side session invalidation on password change/reset — a stolen cookie survives credential rotation
Category:         Security
Severity:         Low (design limit of client-side sessions)
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
Location:         auth_service.py:128-133 (no hard lock for the last admin), :224-291 (cache TTL),
                  :58-59 (`_is_locked` returns before `_burn_hash`, :97-99 → timing distinguishes locked accounts)
Description:      Brute force against the sole admin account is bounded only by the memory-backed limiter (60/min per worker → ~120/min) and password strength.
Recommended fix:  Optional: per-account throttle (progressive delay) for the exempt admin; invalidate cache entries on password change.
```

```
[ID]  G6-6
Title:            Basic-Auth CSRF exemption depends on `Sec-Fetch-Site` (absent in legacy browsers) — accepted residual of API-3
Category:         Security
Severity:         Info
Location:         extensions.py:24-31
```

LDAP (off by default) — code-correctness note (Info): the admin "Test connection" sends the **stored** bind password to whatever URI/TLS settings are in the form (`users.py:200-215`, `ldap_service.py:202-266`); a malicious admin can exfiltrate it. See G7-6.

Open questions (Area 6): whether deployments typically run a second admin (changes lockout/dual-control behaviour).

---

### Area 7 — HTTP routes / JSON API

Files read in full: `routes/{ca,certificates,csr,dashboard,users,auth,health,metrics}.py`, `responses.py`, `serialization.py`, all `to_dict()`.

**Checklist verdicts:**
- Serializers: CA (`models/ca.py:103-136`) omits `private_key_enc`, `key_label`, `crl_pem`; Certificate (`certificate.py:52-79`) omits `private_key_enc`; CSR (`csr.py:26-43`) exposes only public `csr_pem`; User (`user.py:63-73`) omits `password_hash`; MetricsToken omits hash; AuditLog `details` never contain secrets (Area 10). Tests assert allow-lists (`test_json_api.py:138-172`). CSR one-time key: returned once (`csr.py:97-101` JSON / `:107-110` HTML), `enc_key` discarded (`_`), CSR model has no key column (`models/csr.py:10-20`).
- Authz parity: ownership/role checks precede every `wants_json()` branch (`certificates.py:177-184,248-250`; `csr.py:132-139`; `decorators.py`). JSON 401/403 for API clients (`__init__.py:212-229`, `decorators.py:18-19,33-34`); corroborated: unauthenticated `Accept: application/json` → `401 {"error":"Authentication required."}`, bad Basic → `401` + `WWW-Authenticate: Basic realm="chancery"`.
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
Description:      Measured in the PoC: RSA-8192 ≈ 1.8–3.9 s, RSA-16384 ≈ 16.5 s per request (PoC-3: `key_size=8192 -> 201 in 3.9s`;
                  `key_size=1024 -> 201`). Two concurrent requests occupy both sync workers; 7 req/min sustains it under the 60/min limit.
Impact / attack:  UI, issuance, OCSP and CRL endpoints unavailable while the loop runs; worker kill/restart churn every 120 s.
                  Weak 1024-bit CSRs are stored (rejected only later at signing, cert_service.py:75).
Reproduction:     `curl -u req:pw -d 'mode=generate&cn=x&key_type=RSA&key_size=16384' http://<host>:5000/csr/create` ×2 in parallel, loop.
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
Severity:         Info — malicious/compromised admin only; LDAP off by default
Location:         webhook_service.py:251-253,312-315 (`urllib.request.urlopen(req…)` to any http(s) URL, `validate` :158-175 checks scheme only);
                  ldap_service.py:202-266 with `users.py:200-215` (stored bind password reused for a test against an admin-typed URI, TLS verify togglable)
Recommended fix:  Optionally deny loopback/link-local/private targets for webhooks; require re-entering the bind password for tests against a changed URI.
```

Open questions (Area 7): none blocking.

---

### Area 8 — Public unauthenticated surface

File read in full: `routes/public.py` (+ `ocsp_service.py`, `crl_service.py`, config).

**Checklist verdicts:**
- CRL/CA-cert download: strictly read-only — serve `ca.crl_pem`/`certificate_pem`; `404` when no CRL (`public.py:20-71`). `get_crl_pem/der` (which *could* regenerate) are dead code (no callers). No signing/decrypting on the public path ✔. Served headers (corroborated): `Content-Type: application/pkix-crl`, `Content-Disposition: attachment; filename="<ca-name>.crl"`.
- OCSP: parse → lookup → cache → sign (`ocsp_service.py:105-170`); body capped by `MAX_CONTENT_LENGTH` 1 MiB; rate-limited 60/min/IP (limiter exempts only health/metrics, `__init__.py:63-65`). Corroborated: GOOD for a test leaf, `WARNING: no nonce in response` (accepted PKI-5), 24 h window.
- IDs: integer `ca_id` enumeration by design (public material); serials are 159-bit random.
- Host header: see G8-3.

```
[ID]  G8-1
Title:            Non-latin-1 CA/certificate names break every download for that object — including the public CRL and CA-cert endpoints
Category:         Correctness (revocation availability)
Severity:         Medium — a CA named "Łódź Root", "Zürich-Ost" is fine but "Łódź", Cyrillic, Greek, CJK names get an unreachable CRL/CA URL
Confidence:       Confirmed (code path) / Plausible (the gunicorn write path was not exercised end-to-end)
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
Severity:         Low — clients that use GET (Windows CryptoAPI default, some appliances) get 404 → OCSP unavailable → fall back to the CRL (itself possibly expired, G4-1)
Confidence:       Confirmed (corroborated on the test instance)
Status vs prior:  New
Location:         public.py:74-89 `methods=["POST"]` … `except Exception: current_app.logger.exception("OCSP responder error"); return "Internal server error", 500`;
                  ocsp_service.py:108 `load_der_ocsp_request` raises ValueError; tests/test_routes.py:203-213 pins the 500 behaviour
Reproduction:     `curl -X POST --data-binary garbage /public/ocsp/<ca-id>` → `HTTP/1.1 500` (text/html); container log:
                  `ERROR in public: OCSP responder error … ValueError: error parsing asn1 value: ParseError { kind: ShortData … }`;
                  `GET /public/ocsp/<ca-id>/<b64>` → 404
Recommended fix:  Catch ValueError → `OCSPResponseBuilder().build_unsuccessful(MALFORMED_REQUEST)` at 200; add
                  `GET /public/ocsp/<int:ca_id>/<path:b64>`; keep 500 for real failures; lower the log level for parse errors.
```

```
[ID]  G8-3
Title:            AIA/CDP URLs come from the request Host when `SERVER_NAME_FOR_OCSP` is left at its default — certificates issued via `localhost` embed http://localhost:5000/… for life
Category:         Correctness (Security only with a spoofable Host)
Severity:         Medium — for such certificates revocation checking is impossible for their whole lifetime (URLs are immutable)
Confidence:       Confirmed (code; corroborated on the test instance)
Status vs prior:  Carried — 10-07 C4 → 05-08 "Mitigated (documented)" → 08-08 API-2 "residual"; the residual produces concrete harm whenever the default is left in place
Location:         certificates.py:64-66 / csr.py:171-173 `if ocsp_server == "localhost:5000": ocsp_server = request.host`; :103-106 / :199-202 URL build;
                  config.py:34 default; docker-compose.yml:24 passes the same default through (`${SERVER_NAME_FOR_OCSP:-localhost:5000}`)
Preconditions:    `SERVER_NAME_FOR_OCSP` unset (the compose default)
Description:      With the default in place, whatever `Host` the issuing request carried is baked into the certificate as both CDP and AIA.
                  Anything issued through `localhost` — a port-forward, a script, the JSON API from the host — gets `http://localhost:5000/public/...`;
                  a browser on another machine gets that machine's idea of the hostname. Corroborated on the test instance.
Impact / attack:  Relying parties resolve `localhost` to themselves → CRL/OCSP fetch fails silently or hard. The Host-spoofing angle remains
                  Low (only the issuer's own Host is used; the value is HTML-escaped inside the template JS string, certificates/create.html:262).
Reproduction:     issue a certificate at the default config via `http://localhost:5000`; `openssl x509 -in <leaf.pem> -noout -text | grep -A1 'Authority Information\|CRL Distribution'`
Recommended fix:  Refuse to embed a loopback URL outside debug/testing; make the compose require `SERVER_NAME_FOR_OCSP` (`:?` like `SECRET_KEY`)
                  or document it as a mandatory install step; affected certificates must be re-issued (the URLs are immutable).
Open questions:   none
```
```
[ID]  G8-4
Title:            CRL responses have no caching headers; default rate limit applies to public endpoints
Category:         Correctness
Severity:         Info
Location:         public.py:31-37,50-55 (no Cache-Control/Expires/ETag); `__init__.py:63-65` exempts only health/metrics from the 60/min/IP limit
Recommended fix:  `Expires`/`Last-Modified` from the CRL's nextUpdate/thisUpdate; consider exempting or raising the limit for `/public/*`.
```

Open questions (Area 8): CRL/OCSP consumers.

---

### Area 1 — Bootstrap & factory

Files read in full: `app/__init__.py`, `extensions.py`, `_version.py`.

Verdicts: `_check_security` exits for unset/blank/default `SECRET_KEY` and `MASTER_PASSPHRASE` (`:257-267`) unless `TESTING` or `app.debug` (`:239-249`; debug prints a loud warning; gunicorn never enables debug and the image sets no `FLASK_DEBUG`). `ADMIN_PASSWORD` is guarded only at seed time (`:610-614`) — consistent with docs. Forced-password-change guard (`:112-133`) exempts Basic Auth (which is separately refused with 403 while flagged, `:204-210`), `public`/`health`/`metrics` blueprints, change-password, logout, static — every state-changing route lives in a gated blueprint, no bypass found. Error handlers (`:394-446`): JSON for API clients, plain `"Internal Server Error"`, Werkzeug default 404/405 pages — no traces (404 checked on the test instance); `CSRFError` handler honours same-host referrers only (`:441-445`). ProxyFix is applied only when `TRUSTED_PROXY_COUNT > 0` (`:17-22`); with 0, `X-Forwarded-*` is ignored — audit IP and limiter key are the TCP peer (correct for the reference compose, which has no proxy). Context processors inject version/update flag/dual-control callable (`:94-109`) — no secrets. Admin seed race handled by the unique constraint (`:621-627`).

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
Title:            SECRET_KEY and ADMIN_PASSWORD are delivered as env literals by the reference compose (visible in `docker inspect` / `/proc/<pid>/environ`); ADMIN_PASSWORD stays in the environment after it has served its purpose
Category:         Security
Severity:         Low — host-level reader precondition; SECRET_KEY compromise = forge an admin session remotely
Confidence:       Confirmed (compose; corroborated on the test instance)
Status vs prior:  Carried — 08-08 INFRA-4 was marked "Fixed" but only a comment/`_FILE` option shipped; the reference compose is unchanged
Location:         docker-compose.yml:11 `SECRET_KEY=${SECRET_KEY:?…}`, :23 `ADMIN_PASSWORD=${ADMIN_PASSWORD:-admin}`;
                  config.py:21,28 already support `SECRET_KEY_FILE`/`ADMIN_PASSWORD_FILE`
Recommended fix:  Deliver both as Docker secrets in the reference compose (`secrets/secret_key`, written by `init-secrets.sh`); document
                  removing `ADMIN_PASSWORD` once the first admin exists.
```
```
[ID]  G2-2
Title:            Update check is on by default (outbound HTTPS to api.github.com from a CA host)
Category:         Security
Severity:         Info — documented; set `UPDATE_CHECK_ENABLED=false` for an air-gapped CA
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
Severity:         Medium when DUAL_CONTROL_ENABLED (Low for a single-admin instance, where the mode never activates) — defeats the stated four-eyes guarantee
Confidence:       Confirmed (PoC-9)
Status vs prior:  New (dual control is a 2.10.0 feature; 05-08 D4 was "Accepted: no dual control")
Location:         users.py:24-52 `create_user` (no dual-control gate; any admin, any role), :120-147 `reset_password` (any user incl. ADMIN_USERNAME);
                  dual_control_service.py:25-31 `is_exempt` = username equality; ca.py:278-285 / csr.py:161-168 compare only creator vs current user
Preconditions:    DUAL_CONTROL_ENABLED=true and a multi-user instance
Description:      PoC: alice creates pending CA → self-approve 403 ✔ → alice creates admin "mallory" (302) → mallory approves alice's CA (200).
                  Alternative: reset the bootstrap admin's (ADMIN_USERNAME) password → log in as the exempt account → sign/approve anything.
Impact / attack:  One malicious admin performs both halves of "four-eyes". The audit log shows `create_user`/`reset_user_password` +
                  `login_success` from the same IP — detectable after the fact, not prevented.
Reproduction:     PoC-9 (in-memory app instance with DUAL_CONTROL_ENABLED=True; script not committed)
Recommended fix:  While dual control is active: require a second admin's approval for user creation, admin promotion and password resets; refuse
                  resets of ADMIN_USERNAME; refuse approval by an account created/reset by the CA's creator within N hours; document the limit
                  in README "Dual control" until then.
Open questions:   none
```

---

### Area 9 — Data models & migration

Files read in full: all `app/models/*.py`, `_migrate_schema()`.

Verdicts: every `ALTER TABLE ADD COLUMN` is guarded by a column-presence check (idempotent; `__init__.py:485-589`); upgrade defaults are safe (`role` → `csr_requester` then promote the configured admin with a bound parameter `:492-497`; `must_change_password DEFAULT 0`; `key_backend DEFAULT 'software'`; `approval_status DEFAULT 'approved'`); single commit (`:596`). Three-state key model is consistent across `signing_capable()` (`models/ca.py:77-85`), `has_signing_key` (`:57-64`), `is_exportable` (`:66-70`), `refresh_crl` (`crl_service.py:32`), OCSP (`ocsp_service.py:102`), CLI (`cli.py:255`), metrics (`metrics_service.py:165`), `backend_for_ca` (`keybackend/__init__.py:46-49`). SQL: ORM everywhere; raw SQL is static DDL plus one bound UPDATE. On disk: DB 0600 in 0700, enforced by the entrypoint (corroborated); `instance/` neither shipped nor tracked.

```
[ID]  G9-1
Title:            `certificate_authorities.serial_number` has no DB-level uniqueness (import checks in code; generated serials are random)
Category:         Correctness
Severity:         Info
Location:         models/ca.py:13; ca_service.py:366-369
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
Location:         __init__.py:189-199 (success row per request)
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
Severity:         Low — rotating a passphrase is a manual export/re-import exercise
Location:         cli.py (absent); crypto_utils.py:23-60
Recommended fix:  `flask keys rotate-passphrase --new-file …` that re-wraps every ciphertext in one transaction.
```

---

### Area 14 — Container image

Files read in full: `Dockerfile`, `entrypoint.sh`, `entrypoint-app.sh`.

Verdicts: digest-pinned base in both stages (`Dockerfile:6,18`), `--require-hashes` (`:16`), only `softhsm su-exec` added (`:27`), non-root user (`:31`), pip removed (`:39`), selective `COPY app/ entrypoint*.sh` (`:41-42`) — no `.env`/`secrets`/`.git`; root phase = `chown` then `exec su-exec` (`entrypoint.sh:12-21`) → PID 1 = gunicorn uid 1000 (corroborated); `umask 077` + `chmod 700/600` (`entrypoint-app.sh:10,46-47`); token init idempotent via the label grep (`:31`) → exactly one token (corroborated); secrets bind-mounted read-only 0600; writable paths inside the container: `/app/data`, `/tmp` only.

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
Location:         docker-compose.yml (no `read_only`); entrypoint-app.sh:52-56 (no `--access-logfile`)
```

---

### Area 15 — Compose & TLS

Files read in full: `docker-compose.yml`, `deploy/docker-compose.tls.yml`, `deploy/Caddyfile`.

Verdicts: secrets via files (`:86-89,116-127`); `cap_drop ALL` + 3 caps (`:109-114`); `no-new-privileges` (`:107-108`); mem/pids/cpu limits (`:93-95`); healthcheck (`:98-103`); `restart: unless-stopped`. TLS overlay drops the host port (`!reset []`), sets `SESSION_COOKIE_SECURE=true`, `OCSP_URL_SCHEME=https`, `TRUSTED_PROXY_COUNT=1`, pins `SERVER_NAME_FOR_OCSP` (`deploy/docker-compose.tls.yml:13-20`); Caddy proxies with `X-Forwarded-Proto` (`Caddyfile:14-18`) which ProxyFix trusts for exactly one hop. The reference compose is plain HTTP and says so.

- **G15-1 (Info):** the reference compose is plain HTTP by design (`SESSION_COOKIE_SECURE=false`, host port published) and the app does not distinguish transports for secret-bearing responses (key/PKCS#12 export, one-time CSR key); the TLS overlay in `deploy/` is the documented alternative and is correctly wired. Transport is a deployment choice, not a finding.
- **G15-2 (Info):** `ports: "5000:5000"` publishes on every interface incl. IPv6 and bypasses host firewalls (Docker iptables); bind a specific address (`<address>:5000:5000`) if that is the intent.
- **G15-3 = G2-1** (env-literal secrets).

---

### Area 16 — Secret bootstrap

File read in full: `scripts/init-secrets.sh` (+ its git history).

Verdicts: `umask 077` (`:23`); never overwrites (`:45-52,:78-91`); `openssl rand` (CSPRNG); master passphrase `-base64 24` → 32 chars ≈ 192 bits (`:46`); `SECRET_KEY` 64 hex (`:64`); admin password 20 alnum (`:69`); PINs `rand_alnum 32` ≈ 190 bits (`:79,:87`) — the earlier 6-digit PIN bug is fixed for new deployments; `rand_pin` (`:35-38`) is dead code; the admin password is printed to stdout (`:71`, necessary but lands in scrollback).

```
[ID]  G16-1
Title:            No strength check on `MASTER_PASSPHRASE` / `SECRET_KEY` beyond the literal-default rejection — a pre-generator or hand-typed value runs unnoticed
Category:         Security
Severity:         Info — `init-secrets.sh` (first appeared 2026-08-07, `84f83df`) produces 32 / 64 chars, but nothing verifies what a deployment actually runs
Confidence:       Confirmed (read code)
Status vs prior:  New
Location:         __init__.py:257-267 (`_check_security` compares against the two insecure literals only); config.py:21-22 (`_read_secret`)
Description:      PBKDF2-600k costs ~1 ms/guess on GPU-class hardware, so a short dictionary/pattern passphrase is crackable from a stolen `data/`
                  and nothing else; a guessable `SECRET_KEY` forges admin sessions remotely. A deployment that predates the generator has no
                  in-app way to learn this, and no rotation path exists (G13-2).
Recommended fix:  Warn at startup when either value is shorter than the generator's output (or fails a simple entropy estimate); ship the
                  rotation CLI (G13-2); deliver both as `_FILE` secrets (G2-1).
```

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
Confidence:       Confirmed (reproduced on the test instance: `docker compose exec app python -c "open('/run/secrets/master_passphrase')"` → PermissionError)
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

Run: `python -m pytest tests/ -q -rs` → **615 passed, 18 skipped in 334.8 s** (Python 3.12 venv). All 18 skips are `tests/test_softhsm.py` ("softhsm2-util not installed" in the dev venv); CI installs `softhsm2` (`docker-publish.yml:35-38`) so the HSM differential gate runs there (latest runs green; the Alpine-image scan doc also records the full suite passing inside the image).

Assertions verified as semantic (not status-only): byte-identical DER (`test_softhsm.py:95,:184`); TBS identity + chain verify (`:116-118`); OCSP field parity + signature verification (`:222-234`); PoP with a tampered CSR (`test_hardening_1_1_0.py:39-62`); revoked serial in CRL and REVOKED OCSP for a revoked intermediate (`:100-134`); cache never serves revoked as GOOD (`test_crl_ocsp_availability.py:95-117`); lockout trigger and release (`test_login_lockout.py`); sole-admin exemption (`test_lockout_availability.py:16-27`); JSON 401/403 (`test_fix_api_auth.py:20-29`, `test_json_api.py:177-191`); allow-list no-leak (`test_json_api.py:138-172` — adding a field fails the test); cross-site Basic CSRF (`test_fix_api_auth.py:65-81`); open-redirect matrix incl. backslash (`test_hardening_1_1_0.py:206-216`); export POST-only and password-not-from-query (`test_ca_export.py:124-152`); deactivated login refused (`test_rbac.py:200-213`); last-admin guards (`:216-252`). Fixtures: in-memory SQLite, throwaway SoftHSM token in tmp, `ldap3`/`urllib` mocked, update-check/webhooks/limiter/dual-control pinned off — offline and deterministic; test secrets are constants.

```
[ID]  G22-1
Title:            Coverage gaps matching this report's findings; one test pins non-RFC OCSP behaviour
Category:         Correctness
Severity:         Low
Location:         missing: sub-CA under a revoked parent (G4-2); key-size ceiling (G7-1); non-RSA/EC CSR keys (G4-3); dual-control user-management
                  bypass (G3-1); audit row on failed CRL refresh (G10-1); `path_length<0`/`reason` validation (G7-3); `next` round-trip (G6-3);
                  an active-session deactivation test (positive, currently untested). tests/test_routes.py:203-213 asserts the 500 for malformed OCSP (G8-2).
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

### Area 24 — Runtime state

Out of scope by owner decision (2026-09-14): a deployment's runtime state is used only to corroborate code findings, never audited. Corroborations were performed on a throwaway test instance built from `db182cd` with the reference compose and are marked "corroborated" where they appear above (non-root PID 1, capability set, file modes, a single SoftHSM token, debug off, healthcheck, root inside the container unable to read the secrets — G20-1).

---

### Area 25 — Threat model & data-at-rest

Adversary set completeness — the documented set (unauthenticated network, `csr_requester`, malicious admin, host reader, LAN MITM, supply chain) should add: **operator omission** (the missing CRL refresh timer is the single most impactful issue found), **backup thief** (`data/` carries the DB and the SoftHSM token; in the reference layout `.env` with `SECRET_KEY` sits next to it), **docker-group member** (root-equivalent: `docker exec`, reads `/run/secrets`), and **stolen admin session over plain HTTP** (the reference compose).

Blast radius (reference deployment):

| Asset | Protection at rest | Falls with |
|---|---|---|
| Software CA keys, escrowed leaf keys, webhook/LDAP secrets | Fernet under the single master passphrase | `data/` + the passphrase (a weak passphrase alone if it was never generated — G16-1) |
| HSM CA keys | SoftHSM token under the user and SO PINs | `data/softhsm/tokens` + the weaker PIN (G5-1) |
| Admin session | `SECRET_KEY` (env literal in the reference compose, G2-1) | `docker inspect`, `/proc/environ`, sniffing over plain HTTP |
| Password hashes | scrypt | offline cracking only |
| Audit log | plain, mutable SQLite (accepted G1) | any DB writer |

The intended boundary (CA keys protected, leaf escrow accepted, audit best-effort) matches the docs — with the caveat that SoftHSM's at-rest strength is only as good as the weaker PIN and a single passphrase guards everything else, and neither is checked for strength at startup (G5-1, G16-1).

---

## Phase 2 — Consolidation

### A. Findings at a glance

| ID | Title | Cat | Sev | Conf | Location |
|---|---|---|---|---|---|
| G4-1 | CRLs expire after 7 days; no in-app refresh, no timer shipped | Both | **High** | Confirmed | crl_service.py:129-130, config.py:73, public.py:29-37 |
| G4-2 | Sub-CA creatable under a revoked parent; issues leaves | Both | Medium | Confirmed (PoC) | ca.py:186-199; ca_service.py:147-150 |
| G7-1 | CSR keygen unbounded → authenticated DoS; 1024-bit accepted | Sec | Medium | Confirmed (PoC) | csr.py:75-78; csr_service.py:13-19 |
| G8-1 | Non-latin-1 names break public CRL/CA downloads (gunicorn latin-1) | Corr | Medium | Confirmed/Plausible | public.py:12-15; gunicorn wsgi.py:418 |
| G8-3 | Host-derived AIA/CDP at the default config — `localhost:5000` baked into certs | Corr | Medium | Confirmed | certificates.py:64-66; csr.py:171-173 |
| G3-1 | Dual control bypass via user create / password reset | Sec | Medium (cond.) | Confirmed (PoC) | users.py:24-52,120-147 |
| G4-3 | Key floor ignores DSA/Ed25519 CSR keys | Both | Low | Confirmed (PoC) | policy.py:35-45 |
| G4-4 | EC curve by size; EC keyEncipherment; SAN prefixes | Corr | Low | Confirmed | policy.py:44-45; cert_service.py:28-44,129-142 |
| G6-2 | Admin-set passwords bypass min length / no forced rotation | Sec | Low | Confirmed | users.py:27-46,132-145 |
| G6-3 | `next` redirect never honoured | Corr | Low | Confirmed | __init__.py:234; auth.py:23-29 |
| G6-4 | No session invalidation on password change | Sec | Low | Confirmed | auth.py:108-115 |
| G7-2 | csr routes turn ValueError into 500 | Corr | Low | Confirmed (PoC) | csr.py:62-64,246-248 |
| G7-3 | Negative path_length → 500; free-text reason | Corr | Low | Confirmed (PoC) | ca.py:172; certificates.py:220 |
| G8-2 | OCSP malformed → 500; no GET form | Corr | Low | Confirmed | public.py:74-89 |
| G2-1 | SECRET_KEY/ADMIN_PASSWORD as env literals in the reference compose | Sec | Low | Confirmed | docker-compose.yml:11,23 |
| G10-1 | Revocation persists, audit row lost on CRL-refresh failure | Both | Low | Confirmed (PoC) | crl_service.py:44-52; certificates.py:222-226 |
| G10-2 | CLI mutations unaudited | Sec | Low | Confirmed | cli.py |
| G13-1 | migrate-to-hsm `--yes`, unaudited, orphan on verify failure | Both | Low | Confirmed | cli.py:26,57-72 |
| G13-2 | No master-passphrase rotation tooling | Sec | Low | Confirmed | cli.py (absent) |
| G17-1 | Unpinned CI tooling | Sec | Low | Confirmed | docker-publish.yml:41-44,51 |
| G18-1 | Base image one openssl patch behind (CVE-2026-14456) | Sec | Low | Confirmed (Trivy) | Dockerfile:6,18 |
| G20-1 | README exec examples fail under cap_drop; stale insecure API examples | Corr | Low | Confirmed | README.md:146,153,240,363-377,428,460 |
| G22-1 | Test gaps mirroring the above; OCSP 500 pinned | Corr | Low | Confirmed | tests/ |
| G4-6/7/8, G5-1/2/3, G6-5/6, G7-4/5/6, G8-4, G1-1/2/3, G2-2, G9-1, G10-3, G11-1, G12-1, G14-1/2, G15-1/2, G16-1, G17-2, G18-2, G19-1/2, G23-1 | Info items (see areas) | — | Info | Confirmed | — |

Counts: **1 High, 5 Medium (1 conditional), 17 Low, ~30 Info.** No Critical. No unauthenticated authentication bypass, privilege escalation, serializer leak, IDOR, injection, or CA-key exfiltration path was found.

### B. Positive controls observed (verified, cited above)

PBKDF2-600k + per-record salt + authenticated Fernet; 159-bit random serials; SHA-256 only; leaf `ca=False` with `keyCertSign/cRLSign` hard-off and CSR extensions ignored; CSR proof-of-possession at the signing call site; validity caps + issuer clamp + stored real `notAfter`; expired-issuer refusal (leaf paths); revocation regenerates the issuing CRL, cascades to sub-CAs, lists revoked intermediates in the parent CRL and answers them REVOKED via OCSP; atomic monotonic `crlNumber`; OCSP parses/looks up before any key use, unsigned UNAUTHORIZED for unknown/keyless/pending, status-keyed response cache, request-hash mirroring, byKey responder; public CRL/CA endpoints strictly read-only. **HSM:** RSA cert/CRL DER byte-identical (asserted, and corroborated chains/CRLs/OCSP verify), EC `r‖s`→DER correct, OCSP semantic parity incl. NULL RSA params, `CKA_SENSITIVE/EXTRACTABLE=false`, export genuinely refused, cross-backend intermediates correct, verify-before-scrub migration, serialised sessions reset on error, PINs via secret files and never logged, post-fork `C_Initialize`. **Auth:** scrypt hashes never serialised; local-first break-glass; LDAP injection/anon-bind/TLS handled correctly (off by default); HMAC credential cache that re-reads the user row; per-account lockout across session+Basic with the sole-admin exemption; generic failure messages; robust `next` validation; POST+CSRF logout; forced first-login rotation incl. Basic-Auth refusal; **deactivation and demotion apply to live sessions immediately** (Flask-Login `is_authenticated → is_active`); last-admin/self-deactivation guards. **API:** allow-list serializers (tests fail on any new field); ownership before content negotiation; JSON 401/403/404/405/500; CSRF skipped only for valid, non-cross-site Basic Auth; key/PKCS#12 exports POST-only with the password from the form; header-injection-safe filenames; nosniff/DENY/nonce-CSP/Referrer-Policy/HSTS on every response. **Templates:** autoescape intact, no `|safe`, every form CSRF-tokened, SRI+crossorigin, `noopener`. **Infra:** digest-pinned Alpine base, hash-locked deps with `--require-hashes` (30/30 hashed; OSV clean today), pip removed, non-root PID 1 with `cap_drop ALL`/`no-new-privileges`/limits/healthcheck, secrets bind-mounted read-only, root inside the container cannot read them, idempotent single SoftHSM token, SHA-pinned actions with minimal permissions, publish gated to `v*` tags with keyless cosign + SLSA + SBOM, weekly pip-audit, Dependabot; TLS overlay provided; `init-secrets.sh` now generates strong values with `umask 077` and never overwrites. **Tests:** 615 passing, semantic assertions, offline fixtures, HSM parity gate in CI. **History:** no secrets/keys/large blobs ever committed.

### C. Consolidated open questions / needed context

1. **CRL consumers:** do relying parties of a typical deployment perform CRL or OCSP checks? (Sets the real-world impact of G4-1, G8-2, G8-3.)
2. **Dual control:** is a second admin expected in typical deployments? (G3-1 severity; also changes lockout behaviour.)
3. **GitHub:** are `v*` tags protected (release publishing gate)? (Area 17.)
4. **Seed scripts:** commit or ignore `scripts/seed_demo.*`? (G19-1.)

### D. Prioritised remediation roadmap

1. **Deployment guidance (docs and compose, no app code):** ship a CRL refresh timer (with `-u app`) and require `SERVER_NAME_FOR_OCSP` as install steps (G4-1/G20-1/G8-3); tell operators to drop `ADMIN_PASSWORD` after first login (G2-1); recommend alerting on `chancery_ca_crl_next_update_timestamp_seconds` wherever `/metrics` is scraped.
2. **This week (small code changes):** key-size allow-list in all three keygen paths (G7-1); `is_revoked`/expiry guard for parents in `create_intermediate_ca` + route (G4-2); `except ValueError` in `csr.sign`/`csr.create` (G7-2); `else: raise` in `enforce_public_key_strength` (G4-3); ASCII/RFC 5987 filenames (G8-1); audit-before-refresh in revocation (G10-1); `MIN_PASSWORD_LENGTH` + `must_change_password` on admin-set passwords (G6-2); `path_length`/`reason` validation (G7-3); README `-u app` + POST examples + defaults (G20-1); `request.full_path` in the unauthorized handler (G6-3). Add the corresponding tests (G22-1).
3. **Next sprint:** `SECRET_KEY_FILE` (G2-1); in-app CRL refresh (single-flight) and a saner default window (G4-1 code half); OCSP `malformedRequest` + GET form (G8-2); dual-control gate on user management (G3-1); passphrase-rotation CLI (G13-2) and a startup strength warning for the two secrets and the PIN files (G16-1, G5-1); audit CLI mutations (G10-2); session versioning (G6-4); pin CI tooling (G17-1); take the Dependabot base-image bump (G18-1); `read_only: true` + tmpfs (G14-2).

### E. Executive risk summary

Chancery's cryptographic core and authorization model held up under an adversarial re-read: the CA cannot be tricked into minting a CA certificate from a CSR, proof-of-possession is enforced at the point of signing, serials and digests are correct, the SoftHSM re-implementation reproduces pyca's DER byte-for-byte (corroborated against real chains, CRLs and OCSP responses on a test instance), no serializer leaks key material or hashes, every route enforces role and ownership before content negotiation, and the container/CI/supply-chain posture is genuinely hardened. Nothing found allows an unauthenticated party, or a `csr_requester`, to escalate, mint, or exfiltrate a key.

The risk that exists is operational and correctness-shaped rather than cryptographic. First, **CRL revocation silently stops working seven days after the last regeneration** in any deployment that follows the shipped artefacts: the fix for the previously reported "CRL silently expires" finding was a CLI that depends on a timer nothing installs — and the README's copy-paste command fails under the container's capability drop anyway. Second, with `SERVER_NAME_FOR_OCSP` left at its compose default, certificates issued through `localhost` embed `http://localhost:5000` as their OCSP/CRL location for their whole lifetime, so relying parties cannot check revocation even with fresh CRLs. Third, a low-privilege account can deny service to the whole CA (including OCSP) by requesting 16384-bit CSR keys, and an admin can keep issuing under a revoked hierarchy by creating a sub-CA beneath the revoked parent.

The at-rest story is good: everything software-backed sits under one PBKDF2-600k passphrase and HSM keys under SoftHSM's PINs. Its weak point is that neither value is checked for strength at startup — a deployment that predates the secret generator, or typed its own values, runs unnoticed — and there is no in-app rotation path for either (G13-2, G16-1, G5-1). Everything else is Low/Info hardening and test coverage.

### F. Reconciliation against the prior assessments (10-07, 05-08, 08-08)

- **Verified fixed in code as claimed (08-08 remediation table):** DoS-1 (rate limiting on, before the Basic hook), DoS-2/AUTH-4 (sole-admin exemption, unlock CLI, reset/reactivate clear lockout), TMPL-1 (nonce CSP, no `unsafe-inline`), META-1/META-2 (JSON negative tests, allow-list assertions), PKI-3 (clamped `not_after` stored), HSM-1/HSM-3/CORE-3 (curve check, session reset, verify-before-scrub), PKI-4 (leaf paths), PKI-6, PKI-7, AUTH-2, AUTH-3, CORE-2/4/5, API-3/4/5, TMPL-3, INFRA-2/3/5/6 (limits+healthcheck), and the 05-08 batch (B1–B5, C1–C5, D2, D5, D6, E2, E3, F2, F3, G2, H1, H2, I1, I2, J1, J2). Each was re-read at its current location.
- **Regressed / overstated:**
  - **PKI-1 → G4-1.** Fixed in code only: the CLI it added depends on a timer that nothing shipped installs, so a deployment that follows the docs regresses to the original finding after seven days.
  - **INFRA-4** ("compose cookie/admin-password defaults hardened"): the reference compose still ships `ADMIN_PASSWORD` as an env literal and `SESSION_COOKIE_SECURE=false`; only a comment changed (G2-1). Documented, but not "fixed".
  - **INFRA-6:** read-only rootfs still not done (G14-2).
  - **INFRA-1 (SO-PIN half):** the generator now emits 32-char PINs for new deployments; an existing token's SO PIN has no rotation path and its strength is never checked (G5-1, Info).
  - **API-2/TMPL-2 (C4):** the accepted residual produces measurable harm at the default config — `localhost` URLs inside issued certificates (G8-3).
  - **E1:** the TLS overlay exists and is correctly wired; transport is a deployment choice and is no longer carried as a finding (G15-1, Info).
  - **08-08 "git history independently re-verified clean":** accurate for its pattern set but missed the `.db` blob that 05-08 itself acknowledged (G23-1).
  - **05-08 D4 "no dual control — accepted"** was superseded by the 2.10.0 feature, which is bypassable by one admin (G3-1).
- **Refuted prior claims:** none material; the Flask-Login deactivation behaviour claimed in README/CLAUDE.md is correct (checked, positive).
- **Coverage gaps in prior reports (new surface since 08-08):** LDAP admin UI and webhooks (assessed: correct, SSRF/exfil by a malicious admin noted as Info), dual control (G3-1), metrics tokens (clean), CSRF error handling (clean), the JSON API's key-size ceiling (G7-1), the gunicorn header-encoding path (G8-1), the audit-loss failure path (G10-1), and the default-config outcomes (CRL expiry with no shipped timer, `localhost` URLs, unchecked secret strength) that only surface when the shipped artefacts are actually run.
- **Profile drift:** Python 3.14.7 / SQLAlchemy 2.0.52 (the mandate's profile said 3.13 / 2.0.51); `requirements.in` still says `python:3.13-alpine`; README defaults table stale (G20-1).
