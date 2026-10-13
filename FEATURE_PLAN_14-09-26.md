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

**3.0.0 shipped 2026-09-17 as the new UI (sidebar shell, redesigned dashboard/lists/detail pages, PR #165) at the user's request; the items in that row — F17 PostgreSQL, the three default flips, compose hardening (G14-2), UPGRADE guide — move to 3.1+. Compose hardening (G14-2: read-only rootfs + tmpfs, access log) shipped as v3.5.0, PR #180. ACME dns-01 + wildcards shipped as v3.6.0, PR #182. **The three default flips are NOT being made — the defaults stay as they are (`legacy`, delegated OCSP off, profiles optional); they are documented as recommended opt-ins in `UPGRADE.md` (plain docs, no version) instead. PostgreSQL (F17) is on hold at the user's request.** All lettered features F1–F19 are shipped.**

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

## F1. Server-side certificate profiles (shipped as v2.13.0, PR #129)

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

## F2. Name Constraints on CAs (shipped as v2.22.0, PR #149)

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

## F3. Certificate Policies extension (shipped as v2.23.0, PR #151)

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

## F5. Ed25519 / Ed448 keys (shipped as v2.20.0, PR #143) — G4-3, G5-2

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

## F6. Hash matched to curve, RSA-3072 (shipped as v2.21.0, PR #145) — G5-3, G4-4

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

## F7. Delegated OCSP responder certificate (shipped as v2.24.0, PR #153)

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

## F9. Renew and re-key (shipped as v2.19.0, PR #141)

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

## F11. CA certificate re-issue and cross-signing (shipped as v2.25.0, PR #157)

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

## F12. Scoped API tokens (shipped as v2.26.0, PR #159)

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

## F13. TOTP second factor (shipped as v2.27.0, PR #161)

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

## F14. ACME server (shipped as v3.2.0, PR #174 — http-01; dns-01 + wildcards shipped as v3.6.0, PR #182)

**dns-01 and wildcard identifiers shipped as v3.6.0 (user request 2026-09-17: a wildcard use case; operator example `examples/acme-dns01/` with BIND 9 + TSIG, verified with lego 5 and certbot).**

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

## F16. Audit log export and hash chain (shipped as v3.3.0, PR #176)

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

## F19. Dual control for user management (shipped as v3.4.0, PR #178) — G3-1

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

## F20. Longer validity tiers: 5-year leaves, tiered CA caps (shipped as v3.7.0)

**Requested.** Allow leaf certificates beyond the current 825-day ceiling — up to
**1825 days (5 years)** — and give intermediates and roots distinct caps:
**3650 days (10 years) for intermediates**, **7300 days (20 years) for roots**.

**Current state.** `policy.bounded_not_after(now, validity_days, ca_not_after=None,
is_ca=False)` knows only two tiers: leaf (`MAX_CERT_VALIDITY_DAYS`, default **825**)
and any CA (`MAX_CA_VALIDITY_DAYS`, default **7305** — used for both roots and
intermediates). `create_root_ca`/`create_intermediate_ca`/`reissue_ca_certificate`
all call it with `is_ca=True`, so an intermediate may currently run to the same
7305 as a root. Leaves are additionally clamped to the issuing CA's `not_after`,
and a profile's `max_validity_days` caps tighter still; those two clamps stay.

**Design.**
- Raise the leaf default: `MAX_CERT_VALIDITY_DAYS` **825 → 1825**.
- Split the CA tier in two: keep `MAX_CA_VALIDITY_DAYS` for **roots** (**7305 →
  7300**) and add **`MAX_INTERMEDIATE_VALIDITY_DAYS`** (default **3650**).
- Give `bounded_not_after` a three-way kind instead of the `is_ca` bool — e.g.
  `kind="leaf"|"intermediate"|"root"` (or an `is_intermediate=` flag) — and pick
  the matching cap. `create_intermediate_ca` (`ca_service.py:194`) passes
  intermediate; `create_root_ca` (`:67`) passes root; `reissue_ca_certificate`
  (`:307`) uses the CA's own kind (root vs intermediate), and the reissue/
  cross-sign paths keep clamping to the issuer's expiry so a child never
  outlives its parent. `ocsp_service` responder validity is unaffected (its own
  `OCSP_RESPONDER_VALIDITY_DAYS`, 30).
- Forms/UI: raise the validity input `max` and helper text on the certificate
  create/sign and the CA create pages to the new per-kind ceilings; the profile
  editor's `max_validity_days` is unchanged (it already caps tighter per profile).
- Forward the new/changed knobs in `docker-compose.yml` and document all three
  in the README env table.

**Config.**
- `MAX_CERT_VALIDITY_DAYS` — leaf cap, default **1825** (was 825).
- `MAX_INTERMEDIATE_VALIDITY_DAYS` — intermediate cap, default **3650** (new).
- `MAX_CA_VALIDITY_DAYS` — root cap, default **7300** (was 7305).

**Tests.** Extend the policy tests: a leaf > 1825, an intermediate > 3650 and a
root > 7300 are each refused with the right message; a leaf is still clamped to
the CA's expiry and a profile's `max_validity_days` still wins when tighter; an
intermediate is capped at 3650 even though its root allows 7300.

**Notes / judgment calls** (per the 2026-09-18 release-notes rule):
- **Public trust:** 825 days is the CA/Browser Forum maximum for publicly
  *trusted* TLS server certificates. 5-year leaves are fine for a private,
  internally-trusted CA (which Chancery is) but are rejected by browser/public
  trust programs. This is a deliberate operator choice, called out in the docs.
- **Default leaf cap rises:** a request for, say, 1500 days that used to be
  refused will now succeed on a default deployment. Release notes must say so;
  an operator who wants the old ceiling sets `MAX_CERT_VALIDITY_DAYS=825`.
- **Intermediates are capped *tighter* than before** (3650 vs the old shared
  7305) — a deliberate hygiene default, but a behaviour change: a deployment
  that issued intermediates longer than 10 years must set
  `MAX_INTERMEDIATE_VALIDITY_DAYS` higher. This one tightening is the item to
  flag most prominently in the release notes. Existing certificates and CAs are
  never touched — caps apply only at issuance.

**Release.** A minor (new config + raised defaults); no schema change. Ships
with the release-notes callouts above and an `UPGRADE.md` note that the leaf and
intermediate caps moved.

## F21. Optional CRL Distribution Point — opt out of unreachable revocation pointers

**Status.** Requested 2026-09-23; **not scheduled — spec only, no implementation
yet.**

**Requested.** Allow issuing a certificate with **no CRL Distribution Point**
(and, by symmetry with the existing OCSP-AIA toggle, no revocation pointers at
all), for a CA whose CRL/OCSP endpoints relying parties can never reach.
Motivating scenario: a certificate generated by Chancery — hosted behind a VPN —
is deployed to a production environment outside the VPN. The CDP (and OCSP AIA)
baked into the leaf point at the VPN-only Chancery host, so relying parties
attempt a revocation fetch that can only time out: latency on every validation,
occasional hard-fail rejection (Windows CryptoAPI / .NET, Java with
`enableCRLDP`, OpenSSL `-crl_check`), and no revocation benefit in return. A
present-but-unreachable pointer is worse than none.

**Current state.**
- `public_url.issuance_urls(ca_id, crl_dp_override)` (`app/services/public_url.py:73-83`)
  back-fills a blank / `None` / whitespace CDP with the default `crl_url(ca_id)`;
  only a non-empty override survives. Every HTTP issuance path routes the field
  through it — `certificates.create` (`certificates.py:161`), `certificates.renew`
  (`:393`), `csr.sign` (`csr.py:283`) — so **no UI or API path can omit the CDP**;
  the create form's JS also auto-fills the field on load (`create.html:284-291`).
- `cert_service._leaf_builder` (`cert_service.py:228`) *already* omits the
  extension when `crl_dp_url` is falsy — the capability exists at the service
  layer, the route just never reaches it. Verified: a blank UI POST still issues a
  cert carrying `…/public/crl/<id>.crl`, while a direct
  `create_certificate(crl_dp_url=None)` produces no CDP extension.
- The OCSP AIA is *already* suppressible per-profile: `certificate_profiles.include_ocsp_aia`
  (default true, `certificate_profile.py:39`) → `include_aia` in `cert_service`
  (`:99`, `:216`). The CDP has no equivalent, so the two revocation pointers are
  asymmetric today.
- Encoding note: a literally empty `CRLDistributionPoints` extension is illegal
  (`SEQUENCE SIZE (1..MAX) OF DistributionPoint`). "Empty" therefore has to mean
  **omit the whole extension** — which the existing `if crl_dp_url:` guard does.

**Design.**
- Add a profile flag `certificate_profiles.include_crl_dp` (default **true**),
  the mirror of `include_ocsp_aia`: model column + `to_dict` + profile form/editor
  + `profile_service.enforce()` returning it alongside `include_aia`. When false,
  the leaf gets no CDP.
- Thread an `include_crl_dp` kwarg through `create_certificate` / `sign_csr` /
  `renew_certificate` → `_leaf_builder`, exactly mirroring `include_aia`; when
  false, pass `crl_dp_url=None` to the builder regardless of the resolved URL.
- Per-cert opt-out on the create/sign forms: a **"No CRL Distribution Point"**
  checkbox in Advanced Settings beside the CDP field (ticking it disables the
  field). The route must carry the intent *past* `issuance_urls` rather than rely
  on a blank field (which is back-filled today) — e.g. `issuance_urls` gains an
  `omit=` parameter, or the route skips the fill when the box is set. Default
  behaviour (auto-populate) is unchanged when the box is unticked.
- Policy precedence: the profile flag is the floor; the per-cert checkbox may only
  *remove* the CDP, never add one a profile forbids — consistent with how KU/EKU
  lock under a named profile.
- `renew_certificate` carries the predecessor's choice forward (as it already does
  KU/EKU/profile), so a renewed cert does not silently regain a CDP.
- No change to CA CRL generation, the scheduler, or the public CRL/OCSP endpoints
  — this governs only what is stamped into a leaf.

**Config.** None required — policy lives in the profile flag (deployment-wide)
plus the per-cert checkbox. A global `DEFAULT_INCLUDE_CRL_DP` is deliberately
*not* added unless asked; the profile flag already expresses deployment policy.

**Tests.**
- A profile with `include_crl_dp=false` → issued cert has no CDP extension; the
  default profile still stamps one.
- The per-cert checkbox on create / sign / renew → no CDP even though
  `issuance_urls` would have produced one.
- The checkbox cannot add a CDP a profile forbids.
- Renewal carries the predecessor's choice.
- Regression guard: with neither flag set, a blank CDP field still back-fills the
  default (today's behaviour is preserved).

**Notes / judgment calls** (per the 2026-09-18 release-notes rule):
- **Default is unchanged.** The CDP is still auto-populated; this is purely an
  opt-out, so upgrading changes nothing for anyone who does not use it.
- **Standards.** Omitting the CDP is conformant with **RFC 5280** — the extension
  is optional (§4.2.1.13 only *recommends* it) and revocation checking is
  relying-party local policy. It is **not** acceptable for publicly-*trusted* TLS
  certificates under the CA/Browser Forum Baseline Requirements, but those bind
  only public trust programs, not a private CA like Chancery. Documented so an
  operator does not ship a no-CDP cert expecting public trust.
- **Operational tradeoff.** A cert with no CDP (and no OCSP AIA) cannot be
  revocation-checked by relying parties. The recommended pattern for a
  VPN-isolated CA is **short validity + reissue** (F9 renewal), or **publishing
  the CRL where production can reach it** and pointing the already-editable CDP
  field there. Suppression is the right choice only when the CA's endpoints are
  genuinely unreachable — the docs should say so next to the checkbox.

**Release.** A minor: additive `include_crl_dp` column via `_migrate_schema`
(default true), plus profile UI and the per-cert form field. No breaking change;
default behaviour preserved.

## F22. OpenAPI document and Swagger UI — interactive, role-filtered API documentation (shipped as v3.8.0, PR #199)

**Status.** Requested and implemented 2026-10-13, shipped as **v3.8.0** (PR #199). The
spec below is as written before implementation; what shipped follows it, with one addition found in the
browser smoke test: the *Try it out* interceptor also forces `Accept: application/json` (Swagger UI
sends `*/*`, which made an unauthenticated call fetch the login page instead of the 401 body), and the
form-only user-management writes (create/edit/toggle/reset password, LDAP and webhook settings) are
**excluded** from the document with a reason rather than documented with HTML redirects. Security is the
design driver: this feature loads a third-party JavaScript bundle into the signed-in
origin of a CA, so every choice below is made to add **no new attack surface** beyond
what Bootstrap-from-CDN already represents, and to keep the published document a
**pure function of the code** (never of the database, the request, or a secret).
Numbers and `file:line` references are against `bccab2e` (v3.7.1).

**Requested.** Swagger-style documentation of the JSON API: a machine-readable
OpenAPI document that code generators and tooling can consume, and an interactive
page that lists every operation with its parameters, form fields and response
shapes, and lets an operator exercise an endpoint with their own API credentials.

**Current state.**
- The API *is* the web app: every route negotiates HTML vs JSON through
  `responses.wants_json()` (`app/responses.py:7` — Basic Auth / a bearer token, or
  `Accept: application/json` outranking `text/html`). Request bodies are
  **form-encoded** (`request.form`), the CA import additionally **multipart**
  (`_get_pem_input`, `app/routes/ca.py:25-33`, `p12_file` at `:170`; 64 KB cap).
  There are 101 route × method pairs across 10 blueprints; 11 serializers
  (`to_dict`: `ca.py:173`, `certificate.py:82`, `csr.py:28`, `user.py:104`,
  `audit_log.py:29`, `certificate_profile.py:88`, `api_token.py:108`,
  `ca_certificate.py:54`, `metrics_token.py:102`, `acme.py:42/:72`) define the
  response shapes. Errors are `{"error": "..."}` with a 4xx/5xx (`api_error`).
- The only API documentation is the hand-kept README tables (README "API
  Reference", ~200 lines), with no mechanical link to the routes — they have drifted
  before (PR #185 filled gaps). No test enumerates `app.url_map`.
- Authentication for programmatic clients already maps 1:1 onto OpenAPI security
  schemes: HTTP Basic (`_setup_basic_auth`, `app/__init__.py:175-265`) and bearer
  API tokens (`_check_api_token`, `:267-305`; scopes `read|issue|revoke|admin`,
  `api_token_service.required_scope`, `api_token_service.py:137-151` — any GET on a
  non-public blueprint needs `read`). Both set `g.basic_auth_used`, which is what
  bypasses CSRF. A session cookie alone can only *read* through the API: a POST
  without the CSRF token is a 400 (`_handle_csrf_error`, `app/__init__.py:579`).
- The CSP (`_setup_security_headers`, `app/__init__.py:522-536`) already allows
  `https://cdn.jsdelivr.net` for `script-src`/`style-src`/`font-src`, keeps
  `style-src 'unsafe-inline'`, `img-src 'self' data:`, `connect-src 'self'`, and
  authorises inline scripts only through the per-request nonce; it is applied with
  `setdefault`, so a view *could* set its own policy — this feature must **not**.
  `base.html` pins Bootstrap/Icons with SRI (`:19-20`, `:187`) and
  `tests/test_security.py::TestSRIHashes` (`:285-308`) checks the pins exist; there
  is no `{% block head %}` for a page-level stylesheet (`base.html:6/:168/:213`).
- Guards treat an unknown blueprint as *authenticated surface*: the forced
  password-change / 2FA gate exempts only `public/health/metrics/acme` and a few
  endpoints (`app/__init__.py:145-152`), the limiter exempts only `health`/`metrics`
  (`:69-75`), and bearer tokens are scope-checked everywhere but `/metrics`. Those
  defaults are exactly right for the new blueprint and need no exemption.
- `swagger-ui-dist` **5.33.2** is current on jsdelivr (checked 2026-10-13). Static
  inspection of the bundle: no `eval(`; one `new Function("return this")` inside the
  webpack `globalThis` shim wrapped in `try/catch` (a CSP without `'unsafe-eval'`
  makes it throw and fall back to `window` — cosmetic console report only); lodash's
  `Function("return this")` is short-circuited by `self` in browsers;
  `localStorage` is touched only behind `persistAuthorization`; the default
  `validatorUrl` is `validator.swagger.io`; the CSS references only `data:` SVGs and
  system fonts (no `@import`, no web fonts). Nothing requires relaxing the current
  CSP; **confirmed in a real browser before release** (see Verification).
  SRI (sha384, computed from the jsdelivr files 2026-10-13, re-verify at build):
  `swagger-ui-bundle.js` → `gNnUp++d7WqR9OKX4OMoUmV2w0JxEs1uu6NPXgcynGClIX5DOu6ol4Lp+lINyZcJ`,
  `swagger-ui.css` → `Ov4/wv3j2bmct8cDc5X4ngJZohVPzEmc6uDPH8WeljUxO5vtoykvMEfbu9Vh6RaW`.

**Design.**
- **No existing route changes.** The feature is additive: a new blueprint, a new
  service package, one template, one 1-line `{% block head %}{% endblock %}` in
  `base.html`, a sidebar entry. No model, schema, CLI, audit-event or webhook-catalog
  change; no new runtime dependency (the OpenAPI document is plain Python dicts; a
  validator is added to the **CI-only** lockfile, see Tests).
- **Why not a library.** `flask-smorest`/`apispec` want marshmallow schemas on
  MethodViews — a rewrite of the dual HTML/JSON blueprints and of the form-field
  contract; `flasgger` pulls PyYAML/jsonschema/mistune into the hash-locked runtime
  lockfile and the pip-audit gate for a loosely maintained package. A
  code-owned document plus **mechanical drift gates** (below) gives the same result
  with zero runtime deps and zero touch of security-sensitive route code.
- **Blueprint `apidocs`** (`app/routes/apidocs.py`, `url_prefix="/api"`), GET only:
  - `GET /api/openapi.json` — `@login_required`; returns the OpenAPI **3.1.0**
    document for the caller's role (below); `application/json`,
    `Cache-Control: no-store`. Always JSON regardless of `Accept`.
  - `GET /api/docs` — `@login_required`; renders Swagger UI inside the app shell.
  - A blueprint-level `before_request` returns **404 when `API_DOCS_ENABLED` is
    false** — before the login decorator runs, so a disabled deployment is
    indistinguishable from one without the feature (the `metrics` pattern,
    `app/routes/metrics.py:31-36`).
  - Under a bearer token both are plain GETs → `required_scope` demands `read`
    (a token with only `issue` gets the existing scope-denied 403, audited). A
    metrics token is refused by `_check_api_token` as today. The password-change /
    2FA gate applies unchanged.
- **Builder** (`app/services/openapi/` package: `builder.py`, `operations.py`,
  `schemas.py`):
  - `build(role)` walks `current_app.url_map.iter_rules()`, skips `static`,
    `HEAD`/`OPTIONS`, converts `<int:x>` → `{x}` (`schema: integer`, `<path:>` →
    string) and looks each `endpoint:METHOD` up in `operations.OPERATIONS`
    (summary, description, tag, `role` = `admin|any|public`, scope, request body
    — media type + fields with type/enum/required/description —, query parameters,
    responses with `$ref`s, `x-chancery-key-material`). `operations.EXCLUDED`
    maps the deliberately undocumented pairs to a **reason string** (HTML form GETs,
    the browser-session `auth.*` flows, the ten RFC 8555 JWS endpoints — an ACME
    client speaks those; the directory and new-nonce are documented). A pair in
    neither is a **test failure** (coverage gate) and, defensively, is **omitted and
    logged** at run time rather than raising (fail closed, never a 500; in
    `TESTING` it raises).
  - **Role filtering.** `admin` operations are present only when
    `current_user.is_admin`; a `csr_requester` receives `any` + `public`
    operations (their own CSR/certificate/API-token surface and the public
    endpoints). Unreferenced tags/schemas are pruned. The document still names the
    role and token scope of every operation (`x-chancery-role`, `x-chancery-scope`,
    rendered with `showExtensions`), so the page doubles as an access-control map.
  - **Static-document rule (security invariant).** The document is a pure function
    of the code, the running version (`info.version` = the footer's `app_version`,
    `app/__init__.py:117`) and non-secret policy limits (`MAX_*_VALIDITY_DAYS`,
    `MIN/MAX_RSA_KEY_SIZE`, the `per_page` cap — the same numbers the forms show).
    **Never** anything from the database (no CA ids/names, no profile keys as
    enums — the `profile` field is documented as "a profile key, see
    `GET /users/profiles`"), never the request (**no `servers` entry** — relative
    paths only, so the Host header is never reflected into a document a code
    generator may trust; no `Host`-derived example URLs), never a secret, never a
    live example value. Descriptions are hand-written Markdown that Swagger UI
    renders through its sanitizer; the invariant is what makes that safe. Cached
    per `(role, version)` after the first build (`lru_cache`), so a flood costs a
    dict lookup.
  - **Schemas** (`schemas.py`): hand-written JSON Schema 2020-12 components for
    `Error`, `Page` (the `{items, page, per_page, total, pages}` envelope),
    `CertificateAuthority` / `…Detail`, `Certificate` / `…Detail`,
    `Csr` / `…Detail`, `User`, `AuditEntry`, `CertificateProfile`, `ApiToken`
    (+ `ApiTokenCreated` with the one-time `token`), `CaCertificate` (alternates),
    `DashboardStats`, `EabKeyCreated`, `DetectParentResult`; downloads documented
    with their real media types (`application/x-pem-file`, `application/pkix-crl`,
    `application/pkcs12`, `application/ocsp-response`, …). Every object schema is
    **`additionalProperties: false`**, so a field added to a `to_dict` later fails
    the schema↔reality test until it is documented — a reviewer sees every new
    exposure as a schema diff in the PR.
  - **Request bodies** stay `application/x-www-form-urlencoded`
    (`multipart/form-data` for `POST /ca/create` with `cert_file`/`key_file`/
    `p12_file` as `format: binary`; `application/ocsp-request` for the OCSP
    POST). Checkbox
    semantics are documented per field exactly as the route reads them
    (`"on"`, presence-only `ku_*`/`eku_*`, the `on|1|true|yes` set of `renew`);
    repeated fields (`allowed_profiles`, `scopes`) as arrays with `explode`.
  - **Security schemes**: `basicAuth` (http/basic) and `apiToken` (http/bearer,
    `chy_api_<id>_<secret>`); public endpoints carry `security: []`; `/metrics`
    its own `metricsToken` scheme. The session cookie is *described* in
    `info.description` (reads only; writes need the CSRF token the page never
    exposes) but is **not** offered as a scheme Swagger UI could "authorize" with.
- **Page** (`app/templates/apidocs/index.html`, extends `base.html`, light panel
  inside the shell; a few CSS variables for the dark theme are a nice-to-have):
  - Loads `swagger-ui.css` and `swagger-ui-bundle.js` **only** from
    `https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.33.2/…` with `integrity` +
    `crossorigin="anonymous"` — the same origin and trust decision as Bootstrap,
    so the CSP is **unchanged**; no `swagger-ui-standalone-preset.js` (its top bar
    is a URL input — exactly the surface of CVE-2018-25031).
  - Nonce'd inline init: `url: "/api/openapi.json"` fixed, `dom_id`,
    `presets: [SwaggerUIBundle.presets.apis]`, `layout: "BaseLayout"`,
    **`queryConfigEnabled: false`** (no `?url=` / `?configUrl=` takeover),
    **`persistAuthorization: false`** (credentials typed into *Authorize* live in
    page memory only — never `localStorage`), **`validatorUrl: null`** (no call to
    validator.swagger.io; `connect-src 'self'` would block it anyway),
    `deepLinking: false`, `tryItOutEnabled: false` (explicit click),
    `supportedSubmitMethods` from `API_DOCS_TRY_IT_OUT`, `showExtensions: true`.
  - **Explicit credentials only.** A `requestInterceptor` sets
    `req.credentials = "omit"` on every request **except the spec load**
    (`req.loadSpec`), so *Try it out* never rides on the browser session: without
    *Authorize* a call gets the existing JSON 401, with Basic/bearer it is an
    ordinary API request (audited `basic_auth_success` / token touch, CSRF bypass
    by design, scope- and role-checked). The docs page therefore cannot become a
    session-authenticated console even for reads; CSRF on session POSTs stays as
    defence in depth (verify in the browser that swagger-client honours
    `credentials`; if it does not, CSRF still blocks session writes and the plan
    falls back to documenting that reads use the session).
  - Intro card (static copy): prefer **API tokens** over Basic Auth (scoped,
    expiring, revocable, work for 2FA accounts, and a typo in *Authorize* cannot
    trip the `LOGIN_LOCKOUT_THRESHOLD`); writes need *Authorize*; operations marked
    *returns private-key material* (`POST /ca/{id}/download` key/pkcs12,
    `POST /certificates/{id}/download` pkcs12, `POST /certificates/{id}/download-key`)
    display the key **on screen** — use `curl` unless that is intended.
  - Sidebar: *API reference* under *Account* (`base.html:67-74`), hidden when the
    flag is off; link from the API-tokens page. Existing headers already forbid
    framing (`X-Frame-Options: DENY`, `frame-ancestors 'none'`) so the console
    cannot be clickjacked.

**Security model.**

| Asset | Threat | Control | Gate |
|---|---|---|---|
| Admin browser origin / session | Compromised or hijacked CDN script runs in the signed-in origin | Exact-version pin + SRI on both files; CSP unchanged (`script-src` nonce + jsdelivr, no `unsafe-eval`); no standalone preset | SRI/CSP tests; template scan for any un-pinned external resource |
| Same | XSS through document content rendered by Swagger UI | Static-document rule — nothing from DB/request/secrets | Marker test (CA/profile/user named with a marker never appear); Host-reflection test; byte-identical across requests |
| Same | Docs page becomes a CSRF-free console for the session | `credentials: "omit"` interceptor; session POSTs still CSRF-protected; GET-only routes added | Interceptor present in page; CSRF 400 on a session POST without token |
| Typed API credentials | Persisted to disk / replayed later | `persistAuthorization: false`; `no-store` | Config-string tests |
| API surface / version knowledge | Disclosure to the anonymous internet | `@login_required` on both routes; 404 when disabled; `/health` still version-free | Anonymous 302/401; disabled 404; version only to authenticated callers |
| Admin-only surface | Disclosure to requesters | Role-filtered document | Requester spec has no `admin` operation (`/users/create` absent, `/csr/` present) |
| Token least privilege | Any bearer token reads the spec | Existing `required_scope` → `read` | Token with `issue` only → 403; metrics token → 401 |
| Availability | Spec-generation CPU flood | Built once per role, cached; default per-IP limit applies (not exempt) | 429 after `RATE_LIMIT_DEFAULT` in the limiter test |
| Operator trust in the document | Drift: routes, fields or shapes change silently | Coverage gate over `url_map`; literal form-key gate; schema↔`to_dict` validation with `additionalProperties: false`; media-type check on downloads; OpenAPI validator | all in `tests/test_openapi.py` |
| Outbound traffic from an admin browser | Validator badge / telemetry | `validatorUrl: null`; CSP `connect-src 'self'` | Config-string test |
| Policy guards | New blueprint bypasses them | Nothing exempted: password-change/2FA gate, rate limit, scope check all apply | Guard tests (must-change user redirected; token scope) |

**Config.**
- `API_DOCS_ENABLED` — default **`true`**; `false` → both routes 404 and the nav
  entry disappears (`app/config.py` next to `METRICS_ENABLED`; forwarded as
  `- API_DOCS_ENABLED=${API_DOCS_ENABLED:-true}` in `docker-compose.yml` with a
  comment; README env row).
- `API_DOCS_TRY_IT_OUT` — `all` (default) | `read` | `off`: which methods *Try it
  out* may execute (`supportedSubmitMethods`); `off` makes the page documentation
  only. Unknown values refuse startup like `REQUIRE_2FA`. Forwarded and documented
  the same way.

**Tests** (`tests/test_openapi.py`; `openapi-spec-validator` added to
`requirements-ci.in` → hash-locked `requirements-ci.txt`, CI-only, never in the
image; the validator tests `importorskip` so a bare venv still runs the rest).
- *Access:* anonymous browser → 302 to login (both routes); anonymous JSON client →
  401 JSON; `API_DOCS_ENABLED=false` → 404 for anonymous **and** admin; admin via
  session, Basic and a `read` token → 200; token with `issue` only → 403; `cmt_`
  token → 401; a `must_change_password` session → redirected; requester spec
  contains no admin operation and no admin-only schema, admin spec contains all.
- *Static document:* create a CA, a profile, a user and an API token whose names
  carry `ZZMARKERZZ` → the marker is absent from both role variants; request with
  `Host: evil.example` → absent; no `servers` key; two consecutive fetches are
  byte-identical; the only URLs in the document are allow-listed documentation
  links (RFC/datatracker, the project repo).
- *Validity:* `openapi-spec-validator` passes for both variants; every `$ref`
  resolves; `operationId`s unique; every `{param}` declared; every operation has
  `summary`, `tags`, `responses`.
- *Coverage gates:* every `url_map` rule × method is in `OPERATIONS` or `EXCLUDED`,
  and neither holds a stale key; the metadata role matches the view's decorator
  (source inspection: `@admin_required` ⇒ `admin`, `@login_required`/`role_required`
  ⇒ `any`, neither ⇒ `public`); every documented form/query field name is a literal
  read in that route module (`request.form|values|files.get(...)`, `getlist`,
  `"x" in request.form`), and every such literal in `app/routes/*.py` is documented
  for some operation of that module or listed in `UNDOCUMENTED_FIELDS` with a
  reason.
- *Schema ↔ reality:* objects created through the services (CA incl. HSM-less
  software root with alternates, certificate incl. renewal lineage, CSR, user,
  profile, API token, audit row, alternate CA certificate) have `to_dict()` /
  `to_dict(detail=True)` validated with `jsonschema` (Draft 2020-12) against the
  component schemas; real JSON responses of list/detail/create/paginated
  endpoints validated against the documented response; download and public
  endpoints' `Content-Type` equals the documented media type.
- *Page hardening:* inline init script carries the CSP nonce and the CSP header
  equals the dashboard's (modulo nonce) — no relaxation; every external `<script>`/
  `<link>` in **every** template has `integrity` + `crossorigin` (generalises
  `TestSRIHashes`); the page's pinned version and hashes match one constant;
  config strings present (`persistAuthorization: false`, `queryConfigEnabled:
  false`, `validatorUrl: null`, `deepLinking: false`, `credentials = "omit"`), no
  `standalone-preset`, no `unsafe-eval`; `Cache-Control: no-store` on both; the
  limiter test gains `/api/openapi.json`; no `bg-light`/`text-muted`.
- *Deployment files:* `test_compose_hardening` asserts the two variables are
  forwarded.

**Docs.** README: a *Features* bullet and an *Interactive API documentation*
subsection at the top of *API Reference* (open `/api/docs`, *Authorize* with a
token, writes need credentials, key-material warning, codegen from
`/api/openapi.json`, the two variables); the hand-kept endpoint tables stay for
now and point at the page as the authoritative list. `CLAUDE.md`: a design bullet
(static-document rule, the gates, the `head` block, and the **bump procedure** for
the Swagger UI pin: new version → fetch the two files → `openssl dgst -sha384
-binary | base64` → update the single constant → tests). `UPGRADE.md`: nothing
beyond fetch-and-restart; release notes name the page and the two variables.
Optional: a minimal `package.json` listing `swagger-ui-dist`, `bootstrap` and
`bootstrap-icons` so **Dependabot** (npm ecosystem, weekly) opens bump PRs for the
CDN pins too, with a test tying the manifest versions to the template constants —
the PR goes red until the SRI hashes are refreshed; dockerignored, not installed.

**Notes / judgment calls** (per the 2026-09-18 release-notes rule):
- **Default on, behind login.** The page adds no unauthenticated surface (an
  anonymous request sees a redirect/401, a disabled one a 404), the README already
  publishes the same endpoint list, and the *value* is for operators who are
  logged in anyway. An operator who wants no third-party script on that page or
  no API console in the admin UI sets `API_DOCS_ENABLED=false` or
  `API_DOCS_TRY_IT_OUT=off|read`. Release notes say the page appears.
- **CDN + SRI rather than vendoring.** Vendoring ~1.8 MB of Swagger UI into
  `app/static` would remove jsdelivr from this page but not from the app
  (Bootstrap), would grow the image and the repo, and would need a manual bump
  script of its own. SRI makes a modified CDN file unexecutable, which is the
  threat that matters; availability and the CDN seeing the admin's IP are already
  accepted for Bootstrap. If the trust decision for jsdelivr is ever revisited, it
  should be revisited for all three bundles together.
- **Writes from the page are allowed by default** (with explicit API credentials).
  They are the same actions the UI offers behind its own confirm pages, audited the
  same way, and never reachable through the session cookie from this page. The
  `read`/`off` settings exist for deployments whose policy forbids an interactive
  console.
- **Requesters see a filtered document, not nothing.** They are legitimate API
  users (own CSRs/certificates, their tokens); hiding admin operations from them
  keeps need-to-know without denying them the docs.
- **The document is role-filtered, not scope-filtered.** A token's scopes are a
  property of the credential, not the viewer; each operation states the scope it
  needs instead.
- **Key-material operations are warned, not hidden.** Swagger UI has no supported
  per-operation *Try it out* switch; the warning in the summary and the intro card
  make the on-screen display a conscious act. Hiding them from the document would
  make it lie.

**Release.** A minor (**3.8.0**): two new config variables with safe defaults, a new
blueprint, no schema change, no runtime dependency. Size L–XL, almost all of it
declarative metadata (~1.5k lines of operations/schemas, ~150 builder, ~60 route,
~100 template; ~500 lines of tests). Order of work: `head` block + blueprint +
flags → builder + coverage gate (red) → operations module by module (csr,
certificates, ca, users, public, monitoring, acme) until green → schemas +
schema↔reality tests → page + hardening tests → docs → release checks.
**Verification before tagging** (the three-step rule plus one): venv suite;
SoftHSM-inclusive suite on the pinned `python:3.14-alpine` digest; hardened image
boot test; and a **browser smoke test** of `/api/docs` against the boot-test
container — console clean of CSP violations (the caught `new Function` report is
acceptable), *Authorize* with a `read` token → `GET /ca/` executes, a POST without
*Authorize* → 401, the spec loads with the session but *Try it out* does not.

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
