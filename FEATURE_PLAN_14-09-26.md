# Chancery feature plan — 14-09-26

Baseline: v2.12.3 (`db182cd`; v2.12.4 and v2.12.5 since then are dependency-only patch releases and change nothing below), 7.8k lines of app code, 616 tests. Each plan below is
grounded in the current code (file:line references are against that commit).
Nothing here is implemented yet; this document is the tracking artifact, the same
way `SECURITY_ASSESSMENT_29-08-26.md` tracks findings.

## 1. Release policy: minor, not major

Every feature in this plan is **additive and backward compatible**: new tables and
columns via `_migrate_schema` (`app/__init__.py:479`), new env vars with safe defaults,
new routes, no change to existing URLs, JSON shapes, on-disk identifiers
(`cert-manager.db`, SoftHSM label), or the Basic Auth contract. Under the repo's
semver convention (features → minor, fixes → patch) they all ship as **2.x minors**.

A **3.0.0** is only justified when defaults flip in a way that changes what an
existing deployment emits or accepts without any config change. Three candidates are
marked below and deliberately held back so they can ship together with one UPGRADE
note:

| Default flip | Why it is breaking |
|---|---|
| Profiles mandatory (`PROFILES_REQUIRE_SELECTION=true`) | API scripts that post raw `ku_*`/`eku_*` fields start getting 400 |
| Delegated OCSP responder on by default | Responder ID / signer in OCSP responses changes for every CA |
| Hash matched to curve on by default | New signatures from P-384/P-521 CAs change algorithm |

Recommendation: ship the assessment fixes as a **2.12.6 patch** first (§4.2), then the
sequence of minors in §2, then decide at 2.18 whether the flips are worth a 3.0. ACME
and PostgreSQL are large but not breaking; they do not force a major on their own.

## 2. Proposed release train

| Release | Theme | Features | Size |
|---|---|---|---|
| 2.12.6 | Assessment fixes | **Shipped 2026-09-14 (PR #127).** Patch batch from §4.2 (G4-2, G8-1, G8-2, G8-3 code half, G7-2/3/4/5, G6-2/3, G10-1, …); no features | M |
| 2.13.0 | Policy | **Shipped 2026-09-14 (PR #129).** F1 server-side profiles (+ G7-1 max key size). F4 URI/UPN SANs, F15 list search/filter and F18 passphrase rotation follow as their own minors (see the numbering note) | L |
| 2.14.0 | Lifecycle | F8 in-app scheduler (closes G4-1), F10 time-based webhook events, F9 renew/re-key | L |
| 2.15.0 | Algorithms | F5 Ed25519/Ed448, F6 hash-by-curve (flag) + RSA-3072, F2 Name Constraints, F3 Certificate Policies | L |
| 2.16.0 | Trust ops | F7 delegated OCSP responder (flag), F11 CA re-issue & cross-sign | L |
| 2.17.0 | Access | F12 scoped API tokens, F13 TOTP (+ G6-4 session versioning), F16 audit export + hash chain, F19 dual control for user management | L |
| 2.18.0 | Enrollment | F14 ACME (http-01, then dns-01) | XL |
| 3.0.0 | Defaults | F17 PostgreSQL, the three default flips, compose hardening (G14-2), UPGRADE guide | L |

Sizes: S ≤ 200 lines + tests, M 200–600, L 600–1500, XL > 1500 (app code only).

Numbering (decided 2026-09-14): **one minor release per feature**, in the order the rows list them; the theme rows group related work, but the version numbers advance per feature (2.13.0 = F1, next minor = F4, then F15, F18, F8, ...). The 3.0 rationale in §1 is unchanged.

Dependencies: F10 needs F8. F13 should land after F12 (a TOTP user must have a
non-password API path). F14 needs F1 (issuance profile per CA), F8 (order/nonce
cleanup) and realistically the TLS overlay. F7 renewal of responder certs needs F8.
F16 anchoring needs F8 + webhooks. F18 needs the encrypted-column registry, and F7 and
F13 register their new ciphertext columns with it. The 2.12.6 batch goes first because
several features build on its guards: F9 on the revoked/expired-parent checks (G4-2,
G4-6), F7 on the OCSP malformed/GET handling (G8-2), F9 and F14 on the CSR single-flight
guard (G7-4).

Shared conventions for every feature (not repeated below):

- Schema: add columns in `_migrate_schema`, new tables come from `db.create_all()`.
- Settings pages: copy the LDAP/webhook pattern (`app/routes/users.py:192-336`,
  `app/templates/users/_tabs.html`, single-row model, `effective_config()` g-cached).
- Every mutating route: `wants_json()` branch, `audit_service.log_action`, entry in
  `webhook_service.EVENT_CATALOG`, CSRF via the existing `ConditionalCSRFProtect`.
- Dual control: decide per feature whether the action is "issuance" (creator ≠ signer
  rule, bootstrap admin exempt) and write that decision into `CLAUDE.md`.
- Tests: one new `tests/test_<feature>.py`, plus the SoftHSM differential tests in
  `tests/test_softhsm.py` for anything that touches signing.
- Docs: README feature bullet + env var list, `CLAUDE.md` design bullet, `.env.example`.
- Release: bump `app/_version.py`, `release/vX.Y.Z` branch, PR, `v*` tag.

---

## F1. Server-side certificate profiles (2.13.0, L)

**Goal.** Turn the four client-side presets into stored, enforced issuance policies.

**Current state.** Presets are a JS dict duplicated in
`app/templates/certificates/create.html:225-230` and `app/templates/csr/sign.html:125-130`;
they only tick `ku_*`/`eku_*` checkboxes. The server parses those checkboxes in
`app/routes/certificates.py:107-135` and `app/routes/csr.py:196-224` and never learns
which preset was used. Validity is only bounded globally
(`policy.bounded_not_after`, `app/services/policy.py:48`); key size has a floor but no
ceiling (`policy.py:22-33`, assessment G7-1).

**Design.**

- New model `CertificateProfile` (`app/models/certificate_profile.py`, table
  `certificate_profiles`): `name` (unique), `description`, `is_builtin`, `enabled`,
  `key_usage_json`, `extended_key_usage_json`, `default_validity_days`,
  `max_validity_days`, `allowed_key_types_json` (`["RSA","EC"]`), `min_rsa_bits`,
  `max_rsa_bits`, `allowed_ec_sizes_json`, `allowed_san_types_json`
  (`dns|ip|email|uri|upn`), `require_san`, `cn_in_san`, `include_ocsp_aia`,
  `updated_at`, `updated_by`.
- Seed the five built-ins (Web Server, Client Auth, Email, Code Signing, Custom) on
  first boot from `profile_service.ensure_builtins()`; built-ins are editable, not
  deletable. `Custom` carries no restrictions beyond the global bounds, which keeps
  today's behaviour for requests that name no profile.
- FK columns: `certificates.profile_id`, `certificate_signing_requests.profile_id` (nullable),
  `certificate_authorities.allowed_profiles_json` (null = all).
- `profile_service.resolve(request_form, ca)` returns the profile (by `profile` form
  field, name or id; absent → Custom) and refuses when the CA's allow-list excludes it.
- `profile_service.enforce(profile, key_type, key_size, validity_days, san_list,
  key_usage, eku)` raises `ValueError` with a specific message; called from both
  `cert_service.create_certificate` and `cert_service.sign_csr` (so the API path is
  covered, not just the forms). For a named profile the KU/EKU come from the profile
  and posted checkboxes are ignored; for Custom they are honoured as today.
- CSR flow: the requester picks a profile on `/csr/create`; it is stored on the CSR
  and preselected on the sign page. The signer may change it (audited as
  `profile_changed` in the `sign_csr` details).
- G7-1: independent of profiles, add `MAX_RSA_KEY_SIZE` (default 8192) to
  `enforce_key_strength` and `enforce_public_key_strength`.
- Config: `PROFILES_REQUIRE_SELECTION` (default false; 3.0 flips to true).

**UI.** Preferences → Profiles tab: list, create/edit form, enable/disable, "used by
N certificates". CA create/edit gains an "Allowed profiles" multi-select. The
create/sign forms render the profile list from the DB (`profiles_json` context) and
lock the KU/EKU checkboxes unless Custom is selected.

**API/CLI.** `profile=<name>` form field on `/certificates/create` and
`/csr/<id>/sign`; `GET /users/profiles` JSON list; `flask profiles export|import`
(JSON) for backup.

**Tests.** `tests/test_profiles.py`: built-in seeding is idempotent; admin-only CRUD;
validity clamp to `max_validity_days`; key type/size refusal; SAN type refusal;
CA allow-list; CSR profile carried to sign page; legacy request without `profile`
unchanged; JSON API; RSA above `MAX_RSA_KEY_SIZE` refused on generate and on CSR
import (G7-1 regression test).

**Risks.** None to existing data (all new columns nullable). Existing scripts keep
working until the 3.0 flip.

**Assessment links.** G7-1 (the ceiling and allow-list; the missing
`enforce_key_strength` call in `csr_service` is patched in 2.12.6). G4-4: the default
Key Usage comes from the profile and is keyed by key type, so EC and Ed leaves no
longer get `keyEncipherment`.

## F2. Name Constraints on CAs (2.15.0, M)

**Current state.** No `NameConstraints` anywhere in `app/services/`. Intermediates are
built in `ca_service.create_intermediate_ca` (`app/services/ca_service.py:144-248`).

**Design.**

- Column `certificate_authorities.name_constraints_json`:
  `{"permitted": [...], "excluded": [...]}` with typed entries using the SAN prefixes
  (`DNS:`, `IP:<cidr>`, `email:`, `URI:`).
- Create form (root and intermediate): two textareas under Advanced. Service adds
  `x509.NameConstraints(permitted_subtrees, excluded_subtrees)` critical=True.
- Import: parse an existing constraint extension from imported CA certs into the
  column so the UI shows it and enforcement applies.
- App-level enforcement `policy.enforce_name_constraints(chain, subject_attrs,
  san_list)` called from `create_certificate`, `sign_csr` and
  `create_intermediate_ca`: walk `ca_service.get_ca_chain(ca)`, apply RFC 5280
  §4.2.1.10 matching (DNS suffix, IP within network, email domain, URI host); treat a
  CN that looks like a hostname as a DNS name. pyca does not validate constraints at
  issuance, so without this the CA would happily issue a cert that every client
  rejects.
- CA detail page shows the constraints; the F1 profile's `allowed_san_types` and the
  constraints compose (both must pass).

**Tests.** `tests/test_name_constraints.py`: extension present and critical; permitted
subtree accepts/refuses; excluded wins over permitted; sub-CA outside parent scope
refused; imported CA constraints enforced; `openssl verify` of an issued cert against
the constrained chain passes.

## F3. Certificate Policies extension (2.15.0, S)

Column `certificate_authorities.certificate_policies_json` (`[{oid, cps_uri}]`), form
fields under Advanced, `x509.CertificatePolicies` stamped on the CA cert at creation
and inherited by every leaf it issues (optionally overridden per F1 profile). Shown on
CA and certificate detail pages and in `to_dict()`. Tests: OID and CPS URI round-trip,
inheritance, invalid OID refused.

## F4. URI and UPN SAN types (shipped as v2.14.0, PR #131)

**Current state.** `_build_san` (`app/services/cert_service.py:28-44`) and the CSR
parser (`app/services/csr_service.py:30-36, 89-95`) handle DNS, IP and email only.

**Design.** Move SAN build/parse into a shared `app/services/san.py` (removes the
duplication), add `URI:` → `UniformResourceIdentifier` and `UPN:` → `OtherName(OID
1.3.6.1.4.1.311.20.2.3, UTF8String)` encoded with `asn1crypto` (already a dependency).
Parse both on CSR import, display them on detail pages and in `san_json`. Profiles
(F1) can allow or forbid each type. Tests: encode/decode round-trip, CSR import,
`openssl x509 -text` shows `othername:UPN`.

**Assessment links.** G4-4: an unknown prefix (anything with a colon that is not
`DNS:`, `IP:`, `EMAIL:`, `URI:`, `UPN:`) is rejected with a 400 instead of being
silently treated as a DNS name.

## F5. Ed25519 / Ed448 keys (2.15.0, M)

**Verified.** cryptography 50 signs with `algorithm=None` for Ed keys; python-pkcs11 in
the venv exposes `KeyType.EC_EDWARDS` and `Mechanism.EDDSA`; the image runs SoftHSM
2.7.0, which supports EdDSA.

**Design.**

- Collapse the three `_generate_key` copies (`cert_service.py:18`, `csr_service.py:13`,
  `ca_service.py:45`, `keybackend/software.py:40`) into `crypto_utils.generate_key`.
  Accept `key_type` `ED25519` / `ED448` (store `key_size` 256 / 456 to satisfy the
  NOT NULL column).
- Hash selection returns `None` for Ed keys (`software.py:22`, `ca_service.py:55`,
  `cert_service.py:47`); CSR builder likewise.
- SoftHSM backend: `generate_keypair(KeyType.EC_EDWARDS, ...)` with `EC_PARAMS` = DER
  PrintableString `edwards25519`; sign raw TBS with `Mechanism.EDDSA`; `_sig_alg_name`
  → `ed25519`; throwaway key of the same type.
- Forms: key type dropdown gains the two entries and hides the size selector.
  `enforce_key_strength` / `enforce_public_key_strength` accept them.
- Metrics `chancery_ca_info` key_type label already free-form.

**Compatibility note for the README.** Browsers and Windows Schannel do not accept
Ed25519 in TLS server certs; it is for mTLS between modern stacks (Go, OpenSSL 3,
rustls), SSH-style use and code signing. The UI should say so next to the option.

**Tests.** Root/intermediate/leaf issuance, CSR generate/sign, OCSP and CRL from an
Ed25519 CA, SoftHSM parity test, `openssl verify` chain.

**Assessment links.** G4-3: this answers the open question — Ed25519/Ed448 are
supported deliberately. `enforce_public_key_strength` becomes an explicit allow-list
(RSA, the three NIST curves by class, Ed25519, Ed448) with an `else: raise`, applied
at `import_csr` too, so DSA and unknown keys can no longer be signed as
`key_type="Unknown"`. G5-2: fix the CKA_ID mismatch between the key-pair objects and
cache one throwaway key per process while in the backend.

## F6. Hash matched to curve, RSA-3072 (2.15.0, S)

**Current state.** `_get_hash_algorithm` at `app/services/ca_service.py:55-58` returns
SHA-256 in both branches; `keybackend/software.py:22` and `cert_service.py:47` the
same. P-384/P-521 CAs therefore sign with SHA-256, which verifiers accept but the
CA/Browser Forum and RFC 5759 profiles do not expect. Dropdowns offer RSA 2048/4096
only (`ca/create.html:297`, `certificates/create.html:217`).

**Design.**

- One `crypto_utils.hash_for_key(public_key)`: P-256→SHA-256, P-384→SHA-384,
  P-521→SHA-512, RSA→`RSA_SIGNATURE_HASH` (default sha256), Ed→None.
- Config `SIGNATURE_HASH_POLICY=legacy|match-curve` (default `legacy` in 2.15, flip in
  3.0). Applies to certs, CRLs and OCSP responses (the OCSP *request* hash still only
  selects the CertID digest).
- SoftHSM backend: RSA mechanism chosen per hash (`SHA384_RSA_PKCS` exists); EC path
  already pre-hashes, so only the digest and `_sig_alg_name` mapping change.
- Add 3072 to both RSA dropdowns.

**Tests.** Parametrised parity tests per curve; `signature_hash_algorithm` asserted on
cert, CRL and OCSP response; legacy flag keeps SHA-256.

**Assessment links.** G5-3 is this feature. G4-4 (curve accepted by size, not
identity) lands with `hash_for_key`, which keys on the curve class.

## F7. Delegated OCSP responder certificate (2.16.0, M)

**Current state.** Responses are signed by the CA key itself with a byKey responder ID
(`keybackend/software.py:86-100`, `softhsm.py:251-292`); the software backend caches
the decrypted CA key for `OCSP_KEY_CACHE_TTL_SECONDS` (`software.py:59-76`).

**Design.**

- Columns `certificate_authorities.ocsp_responder_cert_pem`,
  `ocsp_responder_key_enc` (Fernet under `MASTER_PASSPHRASE`, always software).
- `ocsp_service.ensure_responder(ca)`: CA signs a short-lived responder cert
  (CN "<CA name> OCSP Responder", KU digitalSignature, EKU OCSPSigning,
  `OCSPNoCheck`, validity `OCSP_RESPONDER_VALIDITY_DAYS` default 30). Works for HSM
  CAs through the existing `sign_certificate`.
- `build_ocsp_response` (`ocsp_service.py:98`): when a valid responder exists and
  `OCSP_DELEGATED_RESPONDER=true`, build with pyca directly:
  `.responder_id(HASH, responder_cert).certificates([responder_cert]).sign(responder_key,
  hash)`. No backend call, no asn1crypto assembly; the HSM special case disappears on
  this path. Fallback to the current byKey path otherwise.
- The key cache now holds the responder key, not the CA key. That is the security win:
  the CA key leaves the token or the Fernet blob only once a month.
- Scheduler job (F8) renews responders with < 7 days left; CA detail shows responder
  status with a "Rotate now" button; `flask ocsp rotate-responders`.
- Default off in 2.16; flip in 3.0 (responder ID changes for every CA).

**Tests.** `openssl ocsp -VAfile`-style verification of the response using the
responder cert; parametrise existing OCSP tests on delegated/direct; revoked-status
cache key still honoured; expired responder falls back and is renewed by the tick.

**Assessment links.** Builds on the G8-2 patch (malformedRequest at 200, GET form)
from 2.12.6; the delegated path must serve both request forms.

## F8. In-app scheduler (shipped as v2.17.0, PR #137) — closes G4-1

**Current state.** CRLs are refreshed only by `flask crl refresh` (`app/cli.py:237`)
and by revocation; no scheduler. gunicorn runs 2 sync workers without `--preload`
(`entrypoint-app.sh`), so a naive thread would run twice. `update_service` already
shows the background-thread pattern (`app/services/update_service.py:83-110`).

**Design.**

- `app/services/scheduler_service.py`: one daemon thread per worker, ticking every
  `SCHEDULER_TICK_SECONDS` (60). Table `scheduler_leases(name PK, holder, expires_at)`;
  each tick tries
  `UPDATE ... SET holder=:me, expires_at=:t WHERE name='main' AND (expires_at < :now OR holder = :me)`;
  only the worker with rowcount 1 runs jobs. Lease TTL = 3 ticks; holder =
  `hostname:pid:uuid`. Zero deployment changes, safe with N workers.
- Start only when `CHANCERY_RUN_SCHEDULER=1`, which `entrypoint-app.sh` sets on the
  `exec gunicorn` line only. CLI invocations via `docker compose exec`, the boot-time
  `create_app()` call and tests never start it. `SCHEDULER_ENABLED=false` disables it.
- Jobs (each wrapped, logged, never raises out of the tick):
  - `crl_refresh`: for each signing-capable CA whose CRL `nextUpdate` is missing or
    within `CRL_REFRESH_BEFORE_DAYS` (default 2) → `crl_service.refresh_crl`.
  - `expiry_events` (daily): see F10.
  - `ocsp_responders` (F7), `acme_cleanup` (F14), `audit_anchor` (F16), expired
    API/metrics token cleanup.
- Audit: `audit_service.log_action` reads `current_user` and `request`; add a
  `system_actor` path (username `scheduler`, user_id NULL, ip set to the loopback
  address) so jobs
  produce audit rows and therefore webhook events through the existing choke point.
- Belt and braces: lazy refresh on the public CRL routes (`app/routes/public.py:20-60`)
  when the served CRL is past `nextUpdate`, as suggested in the assessment.
- Metrics: `chancery_scheduler_last_tick_timestamp_seconds`,
  `chancery_scheduler_lease_held` (per worker).
- `flask crl refresh` stays for manual/cron use.

**Tests.** `tests/test_scheduler.py`: `tick()` called directly with frozen time; lease
contention between two holders; stale CRL refreshed, fresh CRL untouched; pending and
cert-only CAs skipped; job exception does not kill the tick; lazy refresh on download.

**Upgrade note.** The release notes should tell operators to run
`flask crl refresh --all` once after upgrading, so any stale CRL is regenerated
immediately rather than on the first tick.

**Assessment links.** G4-1 is this feature. G10-2 and G13-1: the `system_actor` audit
path is also what every CLI mutation uses, so CLI auditing ships here. G8-4: while
adding the lazy refresh to the public CRL routes, emit `Last-Modified`, `Expires` and
`Cache-Control: max-age` from the CRL's thisUpdate/nextUpdate and give `/public/*`
its own, higher rate-limit bucket.

## F9. Renew and re-key (2.14.0, M)

**Current state.** No renewal path; `grep -i renew app/` is empty. Direct-created certs
keep an escrowed key (`certificates.private_key_enc`); CSR-signed certs do not, but the
CSR row is linked (`csrs.certificate_id`).

**Design.**

- `POST /certificates/<id>/renew` (admin), form: `validity_days`, `revoke_old`
  (reason `superseded`), `rekey` (direct-created only).
  - CSR-based cert: re-sign the stored CSR (same public key) through
    `cert_service.sign_csr` with the old cert's KU/EKU/profile/SANs.
  - Direct-created cert: `create_certificate` with copied subject/SANs/KU/EKU/profile;
    `rekey=false` reuses the escrowed key (new `private_key` kwarg), `rekey=true`
    generates a new one.
- Column `certificates.renewed_from_id` (FK self); detail page shows "Renewed from" /
  "Superseded by"; old cert gets a badge.
- Refuse when the CA is revoked, expired or pending; when the cert is already
  superseded (unless forced).
- Dual control: CSR-based renewal is "signing" (creator ≠ signer rule applies);
  direct-created renewal is "direct creation" (refused while active, bootstrap admin
  exempt). Document in `CLAUDE.md`.
- Audit `renew_certificate` with `{old_id, new_id, revoked_old}`; webhook catalog
  entry. JSON API returns the new cert with 201.
- Dashboard "expiring soon" rows get a Renew button (pairs with F15 filters).

**Tests.** `tests/test_renewal.py`: both paths, key reuse vs rekey, SAN/KU/EKU
equality, chain of renewals, revoke-old reason on CRL, dual-control refusals, JSON.

## F10. Time-based webhook events (shipped as v2.18.0, PR #139)

New "Scheduled" group in `EVENT_CATALOG`: `certificate_expiring`,
`certificate_expired`, `ca_expiring`, `crl_refreshed`, `crl_refresh_failed`,
`scheduler_error`. Daily job selects certs and CAs crossing `CERT_EXPIRY_WARNING_DAYS`
and not yet notified (columns `certificates.expiry_notified_at`,
`certificate_authorities.expiry_notified_at`), logs an audit row per item via the
system actor, which fires the webhook. Tests: fired once, not re-fired next day,
re-armed after renewal (F9 clears the column on the new cert).

## F11. CA certificate re-issue and cross-signing (2.16.0, L)

**Design.**

- New table `ca_certificates(id, ca_id, certificate_pem, issuer_ca_id nullable,
  serial, not_before, not_after, is_primary, created_at)`. `certificate_authorities.
  certificate_pem` stays the primary (no change to any existing reader); the table
  holds alternates.
- **Re-issue** (`POST /ca/<id>/reissue`): new certificate for the *same* key (same SKI,
  new serial and validity), signed by the parent (or self for a root). Existing leaves
  keep validating because AKI matches. Old cert moves to the table as non-primary.
- **Cross-sign** (`POST /ca/<id>/cross-sign`, choose issuer CA): certificate for this
  CA's public key issued by another CA; stored as an alternate with `issuer_ca_id`.
  `get_ca_chain` gains `via=` so downloads (`/ca/<id>/download?format=chain&via=<id>`)
  and `export_fullchain_pem` can build either path.
- Public endpoint `/public/ca/<id>.crt` keeps serving the primary; add
  `/public/ca/<id>/alt/<alt_id>.crt`.
- Dual control: both are CA creation events (pending until approved by another admin).

**Tests.** `openssl verify` of a leaf via both chains; SKI/AKI equality on re-issue;
revoked alternate excluded; import of a cross-cert bundle.

## F12. Scoped API tokens (2.17.0, M)

**Current state.** API access is Basic Auth with the user's real password
(`app/__init__.py:136-235`, `auth_service.authenticate_basic`). The
`MetricsToken` model/service (`app/models/metrics_token.py`,
`app/services/metrics_token_service.py`) is the pattern to copy.

**Design.**

- Model `ApiToken`: `user_id`, `name`, `token_id`, `token_hash` (SHA-256),
  `scopes_json` (`read`, `issue`, `revoke`, `admin`), `expires_at` (required, capped
  by `API_TOKEN_MAX_DAYS`=365), `last_used_at`, `revoked`, `created_by`. Presented
  form `chy_api_<token_id>_<secret>`; the prefix keeps it distinguishable from metrics
  tokens, and each endpoint refuses the other kind.
- Extend `check_basic_auth` into `check_api_auth`: `Authorization: Bearer chy_api_…`
  → verify → same `g.basic_auth_used` semantics (CSRF bypass, JSON errors, forced
  password-change gate, deactivated user wins). `load_user_from_request` returns the
  token's user.
- Scope check in `app/decorators.py`: when the request is token-authenticated, the
  route's declared scope must be in the token; session and Basic keep full role
  rights. A token can never exceed its owner's role.
- UI: Preferences → API tokens (admin sees all, can revoke any) and a self-service
  page for requesters listing their own. Secret shown once. CLI `flask api-token
  create|list|revoke`. Audit `create_api_token`, `revoke_api_token`,
  `api_token_auth_failed`.
- README API section recommends tokens; Basic Auth stays enabled (3.0 may reconsider).

**Tests.** `tests/test_api_tokens.py`: bearer accepted, expired/revoked refused,
scope enforcement per route, metrics token refused here and API token refused at
`/metrics`, deactivated owner, audit entries, CSRF bypass only with a valid token.

## F13. TOTP second factor (2.17.0, M, after F12)

**Design.**

- Columns on `users`: `totp_secret_enc` (Fernet via `crypto_utils.encrypt_secret`),
  `totp_enabled`, `totp_confirmed_at`, `recovery_codes_json` (werkzeug-hashed).
- `app/services/totp_service.py`: RFC 6238 with stdlib `hmac`/`struct`/`base64`, ±1
  step window, last-used-step stored to block replay. QR as inline SVG from `segno`
  (pure Python, no transitive deps) or plain otpauth URL as fallback.
- Login flow: password ok and `totp_enabled` → `session["pre_2fa"]` (user id, 5-minute
  expiry) → `/auth/2fa` → `login_user`. TOTP failures count toward the existing
  lockout (`failed_login_count`).
- Enrol at `/auth/2fa/setup` (show QR, confirm one code, show recovery codes once);
  disable needs password + code. Admin reset from the user edit page and
  `flask users reset-2fa <username>` (audited). LDAP users may enrol too.
- `REQUIRE_2FA_FOR_ADMINS` (default false) forces enrolment on next login through
  the same guard mechanism as `must_change_password`.
- A TOTP-enabled user is refused Basic Auth with a JSON hint to use an API token
  (that is why F12 comes first).
- Webhook events `totp_enabled`, `totp_disabled`, `totp_reset`, `login_2fa_failed`.

**Tests.** RFC 6238 appendix vectors, window and replay, lockout, forced enrolment,
Basic Auth refusal, recovery code single use.

**Assessment links.** G6-4 and G6-5 ship here because they touch the same files: add
`users.session_version`, store it in the session at login, bump it on password
change, admin reset and any 2FA change, reject older sessions in the Flask-Login
`user_loader`, and drop the user's Basic Auth cache entry at the same points.

## F14. ACME server (2.18.0, XL)

**Scope.** RFC 8555 with `http-01` first, `dns-01` second, per-CA directory at
`/acme/<ca_id>/directory`. Lets certbot, acme.sh, lego and Caddy enrol from the LAN
CA without a human.

**Design.**

- Models: `acme_accounts` (jwk, thumbprint unique, status, contact, EAB kid),
  `acme_orders` (account, ca, status, identifiers, expires, csr, certificate_id),
  `acme_authorizations`, `acme_challenges` (type, token, status, error), `acme_nonces`,
  `acme_eab_keys` (admin-issued MAC keys for external account binding).
- `app/services/acme/`: `jws.py` (RS256/ES256/ES384 verification with pyca,
  jwk↔kid, nonce issue/consume), `problem.py` (`application/problem+json`),
  `validation.py` (http-01 outbound GET with 10 s timeout, key-authorization compare;
  dns-01 needs `dnspython`, phase 2), `service.py` (state machine).
- Blueprint `app/routes/acme.py`, exempt from session auth, CSRF and the
  password-change guard like `/public`; its own rate-limit bucket.
- Issuance goes through `cert_service.sign_csr` with the CA's `acme_profile_id` (F1),
  `issuance_source='acme'` and the account id recorded on the certificate. Revocation
  via `revoke-cert` signed by the account key or the certificate key.
- Per-CA settings: `acme_enabled`, `acme_profile_id`, `acme_require_eab` (default
  true; without it any LAN host can obtain a cert for any name it controls, which is
  standard ACME semantics but worth an explicit switch). Global `ACME_ENABLED` default
  false, `ACME_BASE_URL` (falls back to the OCSP hostname logic).
- Dual control: ACME is automated issuance. Enabling ACME on a CA is the approved act
  (needs a second admin while dual control is active); orders afterwards are exempt.
  Write this into `CLAUDE.md`.
- Scheduler (F8) expires stale orders/authorizations and prunes nonces.
- Transport: RFC 8555 §6.1 requires HTTPS for the directory and clients differ in how
  strictly they enforce it. Test the chosen clients against plain HTTP early; plan on
  running the TLS overlay (`deploy/docker-compose.tls.yml`) for ACME even where the
  UI itself is served over plain HTTP.

**Tests.** `tests/test_acme.py` with a hand-rolled JWS client in pyca and a local
http-01 responder thread on a random port (`ACME_HTTP01_PORT` override); full
happy path, bad nonce, bad signature, EAB required, unauthorized identifier, order
expiry, revoke. Optional CI job running certbot against the dev server.

**Estimate.** 1500–2500 lines plus ~60 tests.

**Assessment links.** G7-6: http-01 validation fetches hostnames chosen by the
requester, so add `app/services/net_policy.py` (`check_outbound_target(host)`:
resolve, always deny loopback and link-local, deny the CA's own addresses, allow RFC
1918 because a LAN CA validates LAN hosts) and reuse it for webhook URLs and the LDAP
test URI; require re-entering the LDAP bind password when the test URI differs from
the saved one.

## F15. List search, filter and pagination (shipped as v2.15.0, PR #133)

**Current state.** `list_certs` (`app/routes/certificates.py:29-41`), CSR and CA lists
accept no query parameters and return everything; only the audit log paginates.

**Design.** Query params `q` (CN, serial, SAN substring), `status`
(certs: `active|revoked|expiring|expired`; CSRs: `pending|approved|rejected`),
`ca_id`, `profile` (F1), `page`/`per_page` (default 50). Filter bar in the three list
templates; dashboard counts become links to the filtered view. JSON keeps the bare
array when no `page` is given (compat) and returns
`{items, page, per_page, total}` when it is. Tests: each filter, requester scoping
preserved, pagination envelope, legacy array unchanged.

## F16. Audit log export and hash chain (2.17.0, M)

**Current state.** `audit_logs` has no integrity fields (`app/models/audit_log.py`);
the page paginates but cannot filter or export.

**Design.**

- Columns `prev_hash`, `entry_hash` (SHA-256 over `prev_hash || canonical JSON of the
  row`). Two gunicorn workers inserting concurrently would fork an inline chain, so
  sealing is done by the F8 lease holder: each tick hashes unsealed rows in id order.
- Daily `audit_anchor` job emits the head hash and row count as a webhook event so a
  receiver (n8n) holds an out-of-band record.
- `flask audit verify [--from-id]` recomputes the chain and reports the first bad row.
- Export `GET /users/audit-log/export?format=csv|json&from=&to=&action=&user=`
  (streamed) and matching filters on the page; `flask audit export --since`.

**Tests.** Chain verifies after N inserts; edited row detected; deleted row detected;
export filters; anchor event payload.

**Assessment links.** G10-3: `AUDIT_RETENTION_DAYS` (default 0 = keep everything).
Pruning runs in the scheduler, exports the pruned range to a file under `data/` first,
and writes a checkpoint row carrying the last pruned hash so `flask audit verify` can
still verify from the checkpoint forward.

## F17. PostgreSQL support (3.0.0, L)

**Design.**

- Dependency `psycopg[binary]` (musllinux wheels exist; hash-locked like the rest).
- Make `_migrate_schema` dialect-aware: boolean defaults `1` → `true`, `DATETIME` →
  `TIMESTAMP`, wrap in a small `_col(type, default)` helper. Everything else in the
  models is portable, including the atomic CRL-number increment in `crl_service.generate_crl`.
- `flask db copy --to <url>`: reflect and copy all tables in FK order for a one-time
  SQLite → Postgres move.
- `deploy/docker-compose.postgres.yml` overlay with a `db` service and a Docker secret
  for the password.
- CI: second test job with a `postgres:16` service and
  `DATABASE_URL=postgresql+psycopg://…` running the whole suite.

**Why 3.0.** Not because it breaks anything, but because it is the release where the
UPGRADE guide changes shape (choose an engine, migrate) and the default flips from §1
ride along. Compose hardening rides along too (G14-2): `read_only: true` with tmpfs
for `/tmp` and the SoftHSM lock directory, and gunicorn's access log to stdout.

## F18. Master-passphrase rotation CLI (shipped as v2.16.0, PR #135) — G13-2, G16-1

**Current state.** No rotation tooling. Four ciphertext columns are wrapped under
`MASTER_PASSPHRASE` today (`crypto_utils.encrypt_private_key` / `encrypt_secret`,
PBKDF2 600k + Fernet, salt stored with the ciphertext):
`certificate_authorities.private_key_enc`, `certificates.private_key_enc`,
`ldap_settings.bind_password_enc`, `webhook_settings.secret_enc`. Rotating the
passphrase is therefore a manual export-and-reimport of every software key.

**Design.**

- `crypto_utils.ENCRYPTED_COLUMNS`: a registry of `(model, column, kind)`. F7
  (`ocsp_responder_key_enc`) and F13 (`totp_secret_enc`) register theirs; a test
  asserts every `LargeBinary` column whose name ends in `_enc` is registered, so a
  future feature cannot silently add an unrotatable secret.
- `flask keys rotate-passphrase --new-file <path> [--dry-run]`: reads the new value
  from a file (never argv), verifies the current passphrase decrypts one blob per
  registered column, re-wraps every ciphertext in one transaction, verifies each
  re-wrapped blob decrypts with the new value, audits the rotation (system actor once
  F8 lands, the CLI audit helper before), and prints the operator's next steps: swap
  the Docker secret file, restart. HSM-backed CAs hold the empty sentinel and are
  skipped. Running while gunicorn is up leaves a window where decrypts fail until the
  restart; the README documents the stop → rotate → swap → start order.
- `flask keys check-passphrase`: decrypts one blob per registered column to confirm
  the running secret matches the database. Useful before a rotation and after a
  restore from backup.

**Tests.** Round-trip on every registered column; dry-run writes nothing; wrong
current passphrase aborts before any write; a failure mid-way rolls back; registry
completeness test.

**Pairs with G2-1.** The README rotation procedure ends with both secrets delivered as
`_FILE` secrets; a rotation drops sessions once.

## F19. Dual control for user management (2.17.0, M) — G3-1

**Current state.** With dual control active, one admin can create a second admin or
reset another admin's password (`app/routes/users.py:24-52, 120-147`) and then act as
both requester and approver. `CLAUDE.md` describes dual control as a four-eyes
guarantee; the assessment rates the bypass Medium once the flag is on.

**Design.** Only while `dual_control_service.is_active()`:

- New local users start `is_active_user=False` with `approval_status='pending'` (new
  column on `users`, migration default `approved`); a *different* admin activates them
  (`POST /users/<id>/approve`, audit `approve_user`). LDAP-provisioned users are
  unaffected, the directory is the second party there.
- Promotion to admin goes through the same pending/approve step. Demotion and
  deactivation stay single-admin: they remove power rather than grant it.
- An admin resetting another admin's password sets `must_change_password` and
  deactivates the account until a different admin re-activates it. Resets of the
  literal `ADMIN_USERNAME` account are refused (it is break-glass; it rotates its own
  password, or `flask users reset-password` does it, audited).
- Cool-down: an account created or reset by admin X cannot approve anything X created
  for `DUAL_CONTROL_COOLDOWN_HOURS` (default 24). Implemented once as
  `dual_control_service.can_approve(approver, creator)` and used by the CA approve
  route as well.
- The bootstrap `ADMIN_USERNAME` account stays exempt, consistent with the existing
  break-glass rule.

**Tests.** `tests/test_dual_control_users.py`: a pending user cannot log in; the
creator cannot approve their own creation; cool-down blocks a freshly created
approver; break-glass exempt; nothing changes while the mode is inactive. README
"Dual control" paragraph updated.

---

## 4. Assessment findings folded into the plan

Every code-level finding in `SECURITY_ASSESSMENT_29-08-26.md` now has a home in one
of two buckets: the **2.12.6 patch batch** of small fixes that ships before any
feature, and **feature-bound** items that are cheaper to do inside the feature
touching the same code. Findings that describe the state of a particular
installation rather than the code are out of scope for this plan: an installation is
corroboration material for a finding, not a plan item.

### 4.1 Disposition

| Finding | Sev | Disposition |
|---|---|---|
| G4-1 CRLs expire with no in-app refresh | High | **F8** (lazy refresh + scheduler) |
| G4-2 sub-CA under a revoked parent | Med | **2.12.6** |
| G7-1 unbounded CSR keygen | Med | **2.12.6** (missing `enforce_key_strength` call) + **F1** (ceiling, allow-list) |
| G8-1 non-latin-1 filenames | Med | **2.12.6** |
| G8-3 Host-derived AIA/CDP | Med | Refuse-loopback guard and shared hostname helper in **2.12.6**; helper reused by F14 |
| G3-1 dual-control bypass via user management | Med (cond.) | **F19** |
| G4-3 non-RSA/EC CSR keys accepted | Low | **F5** (explicit allow-list + `else: raise`) |
| G4-4 curve by size, EC keyEncipherment, SAN prefixes | Low | **F6** (curve identity), **F1** (KU by key type), **F4** (prefix rejection) |
| G6-2 admin-set passwords bypass policy | Low | **2.12.6** |
| G6-3 `next` never honoured | Low | **2.12.6** |
| G6-4 no session invalidation | Low | **F13** (session versioning) |
| G7-2 ValueError → 500 in csr routes | Low | **2.12.6** |
| G7-3 negative path_length, free-text reason | Low | **2.12.6** |
| G8-2 OCSP malformed → 500, no GET form | Low | **2.12.6** (F7 builds on it) |
| G2-1 `SECRET_KEY`/`ADMIN_PASSWORD` as env literals in the reference compose | Low | **2.12.6** (compose, `.env.example`, README move both to `_FILE` secrets) |
| G10-1 audit row lost on CRL-refresh failure | Low | **2.12.6** |
| G10-2 CLI mutations unaudited | Low | **F8** (system actor) |
| G13-1 migrate-to-hsm `--yes`, orphan object | Low | **2.12.6** (orphan cleanup, `--yes` needs `--ca-id`); audit via F8 |
| G13-2 no passphrase rotation | Low | **F18** |
| G17-1 unpinned CI tooling | Low | **2.12.6** |
| G18-1 base image one openssl patch behind | Low | Dependabot digest bump |
| G20-1 README exec examples | Low | **2.12.6** |
| G22-1 test gaps | Low | Each 2.12.6 item lands with its negative test; OCSP test flipped to `MALFORMED_REQUEST` |
| G4-6 intermediate under an expired parent | Info | **2.12.6** (same guard as G4-2) |
| G5-1 PIN strength unchecked, no SO PIN rotation path | Info | **2.12.6** (startup warning); re-key procedure documented with **F11** |
| G16-1 secret strength unchecked beyond the literal defaults | Info | **2.12.6** (startup warning) + **F18** (rotation) |
| G15-1 reference compose is plain HTTP by design | Info | Deployment choice; TLS overlay already shipped; not in the plan |
| G4-7 import parent not signature-verified | Info | **2.12.6** |
| G4-8 revoked CA's own CRL expires | Info | **2.12.6** (final CRL with `nextUpdate` = CA `notAfter`) |
| G5-2 HSM backend nits | Info | **F5 / F6** |
| G5-3 SHA-256 on P-384/P-521 | Info | **F6** |
| G6-5 Basic cache after password change | Info | **F13** with G6-4 |
| G7-4 CSR double-issue race | Info | **2.12.6** (single-flight guard; F9 and F14 rely on it) |
| G7-5 empty `parent_id` silently creates a root | Info | **2.12.6** |
| G7-6 SSRF via admin-configured URLs | Info | **F14** (`net_policy`, shared with webhooks and LDAP test) |
| G8-4 CRL cache headers, public rate limit | Info | **F8** |
| G9-1 CA serial has no DB uniqueness | Info | **2.12.6** (unique index) |
| G10-3 audit growth / retention | Info | **F16** (`AUDIT_RETENTION_DAYS` with checkpoint) |
| G12-1 `ocsp_server` without `tojson` | Info | **2.12.6** |
| G14-2 writable rootfs, no access log | Info | **3.0.0** compose hardening |
| G17-2 Trivy only on release tags | Info | **2.12.6** (weekly report-only rescan of the published image) |
| G18-2 stale regeneration comment | Info | **2.12.6** |
| G19-2 no key globs in `.gitignore` | Info | **2.12.6** (no tracked `.pem`/`.key`/`.p12` files exist, so the globs are safe) |
| G1-1 per-worker limiter, G1-2 CDN in CSP, G1-3 bare-metal boot race, G2-2 update check, G6-6 `Sec-Fetch-Site`, G11-1, G14-1 PIN on cmdline, G19-1 untracked scripts, G23-1 history blob | Info | Accepted or owner decision; not in the plan (F13 renders its QR inline, so no new CDN origin is added) |

### 4.2 The 2.12.6 patch batch (fixes only, one PR)

1. **G4-2, G4-6.** `create_intermediate_ca` refuses a revoked or expired parent
   (`ca_service.py:147-150` gains both checks); `ca.create` (`ca.py:186-199`) and
   `import_ca(parent_id=…)` (`ca_service.py:378-382`) resolve the parent through
   `CertificateAuthority.signing_capable()`.
2. **G4-7.** `_import_ca_object` calls `verify_directly_issued_by(parent_cert)`
   whenever a parent is chosen, explicit or by issuer match.
3. **G4-8.** `crl_service.revoke_ca` already refreshes the revoked CA's CRL
   (`crl_service.py:98`); pass `validity_days` so that final CRL's `nextUpdate` equals
   the CA's `notAfter`.
4. **G7-1, first half.** `csr_service._generate_key` (`csr_service.py:13`) calls
   `enforce_key_strength`. Ceiling and allow-list follow in F1/F5.
5. **G7-2.** `except ValueError as e: return _err(str(e))` before the generic handler
   in `csr.create` upload mode (`csr.py:62-64`) and `csr.sign` (`csr.py:246-248`).
6. **G7-3.** `path_length >= 0` in `ca.create`; `reason in REVOCATION_REASONS` on both
   revoke routes.
7. **G7-4.** Single-flight guard before signing:
   `UPDATE certificate_signing_requests SET status='signing' WHERE id=:id AND status='pending'`;
   rowcount 0 → 409; reset to `pending` on failure.
8. **G7-5.** `ca_type=intermediate` with an empty `parent_id` → 400.
9. **G8-1.** One `app/services/filenames.py` replaces the three copies of
   `_safe_filename` (`public.py:12`, `ca.py:33`, `certificates.py:21`): ASCII-only
   `filename=` plus RFC 5987 `filename*=UTF-8''…`; public CRL/CA names fall back to
   `ca-<id>` when nothing printable survives.
10. **G8-2.** Malformed OCSP request → `build_unsuccessful(MALFORMED_REQUEST)` at
    HTTP 200; new `GET /public/ocsp/<int:ca_id>/<path:b64>`; parse errors logged at
    INFO; the pinned test expectation flipped (G22-1).
11. **G8-3.** Refuse to embed a loopback hostname in an AIA or CDP URL outside
    debug/testing; move the hostname resolution now duplicated in `certificates.py`,
    `csr.py` and `ca.py` into `app/services/public_url.py` (F14 reuses it).
12. **G6-2.** `MIN_PASSWORD_LENGTH` enforced in `users.create_user` and
    `users.reset_password`; both set `must_change_password=True`.
13. **G6-3.** The unauthorized handler passes `request.full_path` as `next`
    (`__init__.py:234`).
14. **G10-1.** In both revoke paths the audit row is written before `refresh_crl`, in
    the same transaction as the revocation; a refresh failure returns "revoked; CRL
    refresh failed" as a warning, not a 500.
15. **G13-1.** `migrate-to-hsm` destroys the token object when verification fails;
    `--yes` is accepted only together with `--ca-id`.
16. **G9-1.** Unique index on `certificate_authorities.serial_number` (migration
    step; serials are random, so existing data cannot collide).
17. **G12-1.** `{{ ocsp_server|tojson }}` in the two templates that inline it.
18. **G2-1.** Compose comments and `.env.example` point at `SECRET_KEY_FILE`; README
    says to delete `ADMIN_PASSWORD` after first login.
19. **G17-1, G17-2, G18-2.** `requirements-ci.txt` with hashes for pytest and
    pip-audit; a weekly report-only Trivy rescan of the published image; the
    `python:3.13-alpine` comment fixed.
20. **G19-2.** `*.pem`, `*.key`, `*.p12`, `*.pfx` added to `.gitignore`.
21. **G20-1.** README: `-u app` on every `docker compose exec`, POST examples for the
    key/PKCS#12 downloads, defaults table corrected.
22. **G5-1, G16-1.** `_check_security` warns at startup when `MASTER_PASSPHRASE` or
    `SECRET_KEY` is shorter than the generator's output, and the entrypoint warns when a
    PIN file is; warnings only, so no existing deployment fails to boot.

Every item ships with its negative test (G22-1). Version bump to 2.12.6, patch
release.

## Not planned now

- **RSA-PSS signatures.** pyca and SoftHSM support it (`rsa_padding=` on `sign`,
  `SHA256_RSA_PKCS_PSS`), but the AlgorithmIdentifier parameters complicate the HSM
  reassembly and older clients gain nothing. Revisit if a consumer demands it.
- **SCEP / EST.** ACME covers the self-hosted enrolment case; SCEP is mostly for network
  gear and MDM and would need its own PKCS#7/CMS layer.
- **Rewrite in another language.** Assessed 13-09-26: no advantage.
