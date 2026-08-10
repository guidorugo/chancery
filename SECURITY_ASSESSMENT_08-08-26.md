# Security & Correctness Assessment — cert-manager

> **Assessment date: 2026-08-08.** Method: static source/config/filesystem review + local behavioral checks (no live exploitation). Lens: **security vulnerabilities and functional correctness** (pure style excluded).
> This assessment was produced by executing `SECURITY_ASSESSMENT_PROMPT.md` — a point-by-point pass over all **25 reviewable areas** — and **supersedes nothing**; it *extends* `SECURITY_ASSESSMENT_05-08-26.md` by (a) re-verifying its "Resolved" claims against current code and (b) covering surface added since (the JSON content-negotiation API, the update-check service, keybackend internals, the CLI, and the test/CI/infra layers).

> **🛠 Remediation status — updated 2026-08-10.** Every finding in this report has since been triaged and addressed **except three deliberate residuals** (API-2 / TMPL-2, PKI-5, and INFRA-1's SO-PIN half). The fixes shipped in **v2.5.0** (PRs [#66](https://github.com/guidorugo/cert-manager/pull/66)–[#77](https://github.com/guidorugo/cert-manager/pull/77)), with follow-ups in **v2.5.1** and **v2.6.0** ([#79](https://github.com/guidorugo/cert-manager/pull/79), [#82](https://github.com/guidorugo/cert-manager/pull/82)). See the **[Remediation status](#remediation-status-updated-2026-08-10)** section (just below the findings table) for the per-finding ✅/📌 status and the closing PR; each detailed finding is also tagged inline. The test suite grew **406 → 470** passing across the batch.

## Scope & Method

Full repository + runtime posture, decomposed into 25 areas (app bootstrap/config/decorators; crypto & PKI core; key backends/HSM; authn/authz; HTTP routes + JSON API; public surface; models/migration; audit; update-check; templates/static; CLI; container/entrypoints; compose/deploy; secret bootstrap; CI/CD; dependencies; repo hygiene; docs; tests; git history; threat model). Reviewed by **8 independent reviewers** (one per area cluster), each required to cite `file:line`, treat prior docs as claims to re-verify, refute-before-report, and mark confidence; results consolidated and de-duplicated here.

**Grounded deployment context** (assumed; correct any that are wrong): single-operator homelab, LAN, but shipped as a public repo/GHCR image for real deployment; gunicorn non-root uid 1000, 2 workers; default compose = plain HTTP (Caddy TLS example in `deploy/`); `TRUSTED_PROXY_COUNT=0`; secrets via Docker `*_FILE` from `scripts/init-secrets.sh`; SoftHSM wired and usable per-CA, software (Fernet) backend the default; both software- and HSM-backed CAs may exist; Basic Auth on; LDAP opt-in; update-check on.

## Provenance, AI assistance, token usage & cost

Produced with **Claude Opus 4.8**: eight parallel review sub-agents (one per area cluster) followed by a consolidation/orchestration pass. As with the prior assessments, **both the code and this review come from the same model family, so this is not an independent third-party audit.** For a trust-critical CA, an independent human review remains necessary before production trust is placed in this CA.

**Token usage (measured sub-agent totals).** Each sub-agent's total billable tokens and tool calls, as reported by the orchestration runtime:

| Reviewer (area cluster) | Model | Tokens | Tool calls |
|---|---|--:|--:|
| PKI core (crypto / CSR / CRL / OCSP / policy) | Opus 4.8 | 117,075 | 24 |
| Key backends / HSM (PKCS#11) | Opus 4.8 | 126,952 | 25 |
| AuthN / AuthZ | Opus 4.8 | 121,495 | 29 |
| Routes + JSON API + public surface | Opus 4.8 | 135,722 | 29 |
| App core / config / migration / audit / update / CLI | Opus 4.8 | 114,100 | 36 |
| Templates & frontend | Opus 4.8 | 111,781 | 32 |
| Infra / CI / supply-chain / secrets / repo | Opus 4.8 | 117,255 | 26 |
| Tests / docs / git-history / threat-model | Opus 4.8 | 144,297 | 46 |
| **Sub-agent subtotal** | | **988,677** | **247** |
| Orchestration + consolidation (main loop) | Opus 4.8 | not separately instrumented (est. ≈ 0.3–0.6 M) | — |

**Estimated cost.** At Opus 4.8 list price — input \$5 / output \$25 / cache-write \$6.25 / cache-read \$0.50 per 1M tokens — and assuming the **cache-read-dominated** mix seen in the prior sessions, the sub-agent phase is ≈ **\$2–3** and the full run including orchestration/consolidation is **on the order of \$4–7**. The per-message input/output/cache split was **not** separately captured for this run, so this is a **list-price estimate, not a bill**, and excludes any subscription, tooling, or human-review time.

---

## Executive Summary

**No Critical or High findings.** The crown-jewel paths are sound and were verified, not assumed: CA private keys are not exfiltrable (software = Fernet/PBKDF2-600k with a ~144-bit passphrase held outside the data volume; HSM = `CKA_EXTRACTABLE=false`), leaf CSRs cannot obtain a CA cert, CSR proof-of-possession is enforced, serials/digests are correct, the HSM byte-parity re-implementation is correct (RSA DER byte-identical, EC `r‖s`→DER correct), authorization decorators and `csr_requester` ownership/IDOR checks are complete on **both** the HTML and JSON paths, and no serializer leaks key material or password hashes.

The residual risk is concentrated in **five Medium themes**, none of which is an authentication bypass, privilege escalation, or unauthorized-issuance path:

1. **At-rest key protection inversion for HSM CAs** — the SoftHSM **user PIN is 6 digits (~20 bits)** and its token store is colocated in the `./data` volume, so choosing the "hardware-backed" backend is *weaker* against volume/backup theft than the software backend. Affects any HSM-backed CA. **[INFRA-1]**
2. **CRL silently expires** 7 days after the last revocation/regeneration with **no auto-refresh** — CRL-based revocation checking breaks cluster-wide over time (OCSP is unaffected). **[PKI-1]**
3. **Unauthenticated resource-exhaustion / lockout DoS** because rate limiting is **off by default**: Basic-Auth failures pay an expensive KDF and grow the audit table unbounded; the same path can hold the **sole admin locked out** indefinitely; OCSP re-signs per request. **[CORE-1/AUTH-1/PKI-2/HSM-2]**
4. **CSP is present but keeps `'unsafe-inline'` in `script-src`**, so it provides no XSS defense-in-depth (the app is XSS-safe today only because Jinja autoescape holds). **[TMPL-1]**
5. **The JSON API has no authz/negative-path tests and is absent from the 05-08 assessment's "no open residuals" closure** — the property holds (verified) but is untested and the prior doc overstates closure. **[META-1]**

Plus two Low-Medium data/URL-integrity issues and ~23 Low/Info hardening items. Full list below.

---

## Findings at a glance

| ID | Sev | Cat | Finding | Area | vs prior |
|---|---|---|---|---|---|
| INFRA-1 | **Medium** | Sec | SoftHSM user PIN 6 digits (~20-bit) + token store colocated with DB → HSM CA keys brute-forceable from a stolen volume | Secrets/HSM | Refines A1 |
| PKI-1 | **Medium** | Corr | Published CRL expires 7d after last change; no scheduled/lazy refresh → revocation breaks | PKI | New |
| DoS‑1 | **Medium** | Sec | Unauth Basic-Auth KDF + unbounded audit-log flood; OCSP re-signs per request; rate limiting off by default | Auth/API/DoS | Residual of C1 |
| DoS‑2 | **Medium** | Sec | Unauth last-admin **lockout DoS** (Basic-Auth path, no last-admin exemption, no unlock) | Auth | Residual of D1 |
| TMPL-1 | **Medium** | Sec | CSP keeps `'unsafe-inline'` in `script-src` → no XSS defense-in-depth | Templates | Residual of E2 |
| META-1 | **Medium** | Test | JSON API: zero authz/negative-path tests; omitted from 05-08 "no residuals" claim | Tests/Docs | New (gap) |
| PKI-3 / API-1 | Low-Med | Corr | Issued cert `not_after` **stored unclamped** while the real cert is clamped → UI/API/DB overstate expiry | PKI/API | New (2× confirmed) |
| API-2 / TMPL-2 | Low-Med | Sec | OCSP/CRL URLs in issued certs derived from unvalidated `Host` under default config | API/Templates | Reaffirms C4 |
| HSM-1 | Low | Corr | EC CA on unsupported curve → `migrate-to-hsm` irreversibly bricks signing (`KeyError`) | HSM/CLI | New |
| HSM-3 | Low | Avail | Cached PKCS#11 session never invalidated on error → signing wedged until worker restart | HSM | New |
| PKI-4 | Low | Corr | No guard issuing from an expired (non-revoked) CA → opaque 500 / silent ultra-short cert | PKI | New |
| PKI-6 | Low | Corr | Intermediate creation ignores parent `pathLenConstraint` → un-validatable chain | PKI | New |
| PKI-7 | Low | Sec | CA **import** path skips the `MIN_RSA_KEY_SIZE`/curve floor enforced everywhere else | PKI | New |
| PKI-5 | Low | Sec | OCSP omits request nonce (replay window) | PKI | Reaffirms B6 (accepted) |
| AUTH-2 | Low | Sec | Username enumeration via distinct "account locked" message | Auth | New |
| AUTH-3 / CORE‑q | Low | Sec | Forced first-login password change bypassable via Basic Auth | Auth | New |
| AUTH-4 | Low | Corr | `reset-password`/`toggle-active` don't clear a lockout; no unlock path/CLI | Auth | New (compounds DoS‑2) |
| CORE-2 | Low | Sec | Insecure-default startup guard is exact-match; empty/blank secret boots | Config | New |
| CORE-3 | Low | Corr | `migrate-to-hsm` scrubs the only software key with no post-import verify (contradicts docs) | CLI/HSM | New |
| CORE-4 | Low | Avail | `update_service` `refreshing` flag not reset in `finally` → permanent stall on non-dict JSON | Update | New |
| CORE-5 | Low | Corr | `SESSION_LIFETIME_MINUTES` uses `int(default=)` not `or`-fallback → empty value crashes boot | Config | New |
| API-3 | Low | Sec | CSRF exemption abusable **iff** a browser has cached Basic-Auth creds | API | New |
| API-4 / CORE-6 | Low/Info | Corr | 401/403 (and 404/405/500) don't honor `wants_json()` → HTML to JSON clients (no leak) | API | New |
| API-5 | Info | Corr | `csr.reject` has no status guard → approved-then-rejected inconsistency | API | New |
| TMPL-3 | Low | Sec | Logout is GET → logout CSRF (forced logout only) | Templates | New |
| INFRA-2 | Low | Doc/CI | Docs claim "Trivy fs + image"; only a non-blocking, tag-only image scan exists | CI | Doc drift |
| INFRA-3 | Low | Hygiene | `.claude/settings.local.json` committed with broad auto-approve Bash perms | Repo | New |
| INFRA-4 | Low | Sec | Reference compose ships `SESSION_COOKIE_SECURE=false` + `ADMIN_PASSWORD` env literal | Deploy | Reaffirms A4 |
| INFRA-5 | Low | Sec | `.dockerignore` omits `secrets/` (latent-Critical if a `COPY . .` is ever added) | CI | New |
| INFRA-6 | Low | Avail | Compose lacks resource/pids limits, healthcheck, read-only rootfs | Deploy | New |
| META-2 | Low | Test | JSON no-leak assertions are field-name-specific, not structural | Tests | New |

Counts: **0 Critical, 0 High, 6 Medium, 2 Low-Medium, ~23 Low/Info.** — **Remediation: 28 fixed, 3 deliberate residuals** (details below).

---

## Remediation status (updated 2026-08-10)

Every finding in this assessment was triaged and addressed after it was written: **28 fixed** (shipped in **v2.5.0**, with UI polish in **v2.5.1** and a PIN-entropy follow-up in **v2.6.0**) and **3 deliberate residuals** kept by decision. The original finding text below this section is preserved unchanged; the tags here — and the ✅/📌 notes inline in each detailed finding — record what shipped. PR links point to `github.com/guidorugo/cert-manager/pull/<n>`.

| ID | Sev | Status | PR | What shipped |
|---|---|---|---|---|
| INFRA-1 | Med | ✅ Fixed¹ | [#79](https://github.com/guidorugo/cert-manager/pull/79), [#82](https://github.com/guidorugo/cert-manager/pull/82) | `init-secrets.sh` generates high-entropy alphanumeric PINs (v2.5.0), raised to **32 chars** + a PIN-migration guide (v2.6.0); live user PIN re-keyed. |
| PKI-1 | Med | ✅ Fixed | [#74](https://github.com/guidorugo/cert-manager/pull/74) | `CRL_VALIDITY_DAYS` window + `flask crl refresh [--all]` regenerate stale CRLs. |
| DoS-1 | Med | ✅ Fixed | [#73](https://github.com/guidorugo/cert-manager/pull/73), [#74](https://github.com/guidorugo/cert-manager/pull/74) | Per-IP rate limiting **on by default** (before the Basic-Auth hook); OCSP response cache keyed by `(ca, serial, status, hash_alg)`. |
| DoS-2 | Med | ✅ Fixed | [#71](https://github.com/guidorugo/cert-manager/pull/71) | Last active admin never hard-locked; `flask users unlock`; reset/reactivate clear the lockout. |
| TMPL-1 | Med | ✅ Fixed | [#78](https://github.com/guidorugo/cert-manager/pull/78) | Per-request CSP nonce; `script-src` drops `'unsafe-inline'`; inline handlers → `addEventListener`. |
| META-1 | Med | ✅ Fixed | [#77](https://github.com/guidorugo/cert-manager/pull/77) | JSON API authz / negative-path tests added. |
| PKI-3 / API-1 | Low-Med | ✅ Fixed | [#68](https://github.com/guidorugo/cert-manager/pull/68) | Issuance stores the CA-clamped `not_after`; `flask certs recompute-expiry` backfills. |
| API-2 / TMPL-2 | Low-Med | 📌 Residual | — | **Documented mitigation** (pin `SERVER_NAME_FOR_OCSP`); host auto-detected + `localhost` warning banner added; not code-enforced to preserve the zero-config default. |
| HSM-1 | Low | ✅ Fixed | [#70](https://github.com/guidorugo/cert-manager/pull/70) | Curve validated before the migrate-to-HSM scrub; friendly error, no `KeyError`. |
| HSM-3 | Low | ✅ Fixed | [#75](https://github.com/guidorugo/cert-manager/pull/75) | PKCS#11 session invalidated/cleared on error. |
| PKI-4 | Low | ✅ Fixed | [#70](https://github.com/guidorugo/cert-manager/pull/70) | Expired-CA issuance guarded. |
| PKI-6 | Low | ✅ Fixed | [#72](https://github.com/guidorugo/cert-manager/pull/72) | Intermediate `pathLenConstraint` validated against the parent. |
| PKI-7 | Low | ✅ Fixed | [#70](https://github.com/guidorugo/cert-manager/pull/70) | Key/curve strength floor enforced on CA import. |
| PKI-5 | Low | 📌 Accepted | — | OCSP nonce omission accepted per RFC 5019 (bounded by `nextUpdate`). |
| AUTH-2 | Low | ✅ Fixed | [#72](https://github.com/guidorugo/cert-manager/pull/72) | Generic login-failure message; reason only in the audit log. |
| AUTH-3 | Low | ✅ Fixed | [#76](https://github.com/guidorugo/cert-manager/pull/76) | `must_change_password` enforced on the Basic-Auth path. |
| AUTH-4 | Low | ✅ Fixed | [#71](https://github.com/guidorugo/cert-manager/pull/71) | Lockout cleared on reset/reactivate; unlock CLI. |
| CORE-2 | Low | ✅ Fixed | [#70](https://github.com/guidorugo/cert-manager/pull/70) | Startup guard also rejects empty/too-short secrets. |
| CORE-3 | Low | ✅ Fixed | [#75](https://github.com/guidorugo/cert-manager/pull/75) | Verify the token key before scrubbing the software copy. |
| CORE-4 | Low | ✅ Fixed | [#70](https://github.com/guidorugo/cert-manager/pull/70) | `refreshing` reset in `finally`; non-dict JSON validated. |
| CORE-5 | Low | ✅ Fixed | [#70](https://github.com/guidorugo/cert-manager/pull/70) | Empty-safe numeric env parsing. |
| API-3 | Low | ✅ Fixed | [#76](https://github.com/guidorugo/cert-manager/pull/76) | CSRF exemption also requires a cross-site guard. |
| API-4 / CORE-6 | Low/Info | ✅ Fixed | [#76](https://github.com/guidorugo/cert-manager/pull/76) | Error responses honor `wants_json()`; JSON 404/405/500 handlers. |
| API-5 | Info | ✅ Fixed | [#70](https://github.com/guidorugo/cert-manager/pull/70) | `csr.reject` guarded on `pending`. |
| TMPL-3 | Low | ✅ Fixed | [#72](https://github.com/guidorugo/cert-manager/pull/72) | Logout is POST + CSRF. |
| INFRA-2 | Low | ✅ Fixed | [#77](https://github.com/guidorugo/cert-manager/pull/77) | Trivy scan scope reconciled with the docs. |
| INFRA-3 | Low | ✅ Fixed | [#77](https://github.com/guidorugo/cert-manager/pull/77) | `.claude/` untracked + gitignored. |
| INFRA-4 | Low | ✅ Fixed | [#77](https://github.com/guidorugo/cert-manager/pull/77) | Compose cookie/admin-password defaults hardened. |
| INFRA-5 | Low | ✅ Fixed | [#77](https://github.com/guidorugo/cert-manager/pull/77) | `.dockerignore` excludes `secrets/`, `deploy/`, `scripts/`, `.claude/`. |
| INFRA-6 | Low | ✅ Fixed | [#77](https://github.com/guidorugo/cert-manager/pull/77), [#67](https://github.com/guidorugo/cert-manager/pull/67) | Compose healthcheck + limits; `/health` endpoint. |
| META-2 | Low | ✅ Fixed | [#77](https://github.com/guidorugo/cert-manager/pull/77) | No-leak tests assert an allowlist subset. |

¹ **INFRA-1 residual:** the token **SO PIN** cannot be rotated in place while it holds non-extractable keys, so it is **deferred** — bounded by filesystem access control on `./data/softhsm`. The everyday **user PIN** is fixed (32-char). See the v2.6.0 release notes' PIN-migration guide.

### Deliberate residuals (kept by decision — do not "re-fix" without revisiting)
- **API-2 / TMPL-2** — host-header → cert OCSP/CRL URLs. Left as the **documented** mitigation: pin `SERVER_NAME_FOR_OCSP` in production. Enforcing it in code would break the zero-config `localhost` default, so instead the host is auto-detected and a **warning banner** shows in Advanced Settings when it contains `localhost`, and the CRL-DP field is operator-editable. The `{{ ocsp_server }}` interpolation stays autoescape-safe in its (now nonce-gated) `<script>` context.
- **PKI-5** — OCSP request nonce omitted. **Accepted** as RFC 5019 lightweight-OCSP behaviour; replay is bounded by the response `nextUpdate`.
- **INFRA-1 (SO-PIN half)** — see footnote 1 above.

---

## Detailed findings (most-severe first)

### [INFRA-1] SoftHSM user PIN is a 6-digit (~20-bit) at-rest KEK for HSM-backed CA keys — Medium — Confirmed (PIN length) / Plausible (exploitation)
`scripts/init-secrets.sh:79` writes a **6-digit** user PIN (`rand_pin 6`); the SoftHSM token store lives in the DB volume (`docker-compose.yml:36` `SOFTHSM2_CONF=/app/data/softhsm/...`, `:9` `./data:/app/data`). SoftHSM2's file backend encrypts private-key objects with a **PIN-derived** key. An attacker who obtains `./data` (backup, snapshot, stolen disk, uid-1000 read) can brute-force 10⁶ candidates offline in seconds and recover the CA signing keys — **without** the PIN secret file. This **inverts** the intended posture: software CAs in the same volume are sealed with the ~144-bit `MASTER_PASSPHRASE` (not in the volume), so the "hardware-backed" option is *weaker* at rest against volume theft. Affects any HSM-backed CA. **Fix:** generate high-entropy alphanumeric PINs (SoftHSM permits non-numeric — e.g. `rand_alnum 16`) for both user and SO PIN; re-init/re-migrate affected tokens; and/or store the token dir on a separately-encrypted volume excluded from ordinary DB backups. This refines A1: HSM-at-rest strength is only as good as the PIN entropy.

> **✅ Fixed — [#79](https://github.com/guidorugo/cert-manager/pull/79) (v2.5.0) + [#82](https://github.com/guidorugo/cert-manager/pull/82) (v2.6.0).** `init-secrets.sh` now generates high-entropy **32-char alphanumeric** PINs and #82 shipped a PIN-migration guide; the live token's **user PIN was re-keyed**. **📌 Residual:** the **SO PIN** can't be rotated in place while the token holds non-extractable keys — deferred, bounded by filesystem access to `./data/softhsm`.

### [PKI-1] Published CRL silently expires 7 days after the last change, with no auto-refresh — Medium — Confirmed
`crl_service.py:120` sets `nextUpdate = now + 7d` (default `validity_days=7`, never overridden); the public serve path (`public.py:29-37`) returns the cached `crl_pem` as-is and never regenerates; `get_crl_*` only regenerate when `crl_pem` is falsy, and there is **no scheduler anywhere in the app** (grep-confirmed). So after the initial CRL is published at CA creation, if no revocation occurs, `nextUpdate` lapses at day 7 and nothing refreshes it. RFC 5280 §6.3.3 makes an expired CRL untrustworthy → CRL-checking clients fail (closed = outage, open = revocation ignored). The app stamps a CRL-DP into every issued cert, so relying parties will hit this. OCSP is unaffected (freshly signed, 24h `nextUpdate`). No config knob to lengthen the window. **Fix:** lazily regenerate when `now > nextUpdate` on an authenticated/serve path, or add a scheduled regeneration, or a much longer configurable `nextUpdate` with documented periodic regen.

> **✅ Fixed — [#74](https://github.com/guidorugo/cert-manager/pull/74) (v2.5.0).** `CRL_VALIDITY_DAYS` sets the `nextUpdate` window and `flask crl refresh [--all]` regenerates stale CRLs (cron-friendly).

### [DoS-1] Unauthenticated Basic-Auth KDF + unbounded audit-flood; OCSP re-signs per request (rate limiting off by default) — Medium — Confirmed
`RATE_LIMIT_ENABLED` defaults false. Any request with `Authorization: Basic <garbage>` on **any** route (`app/__init__.py:130-149`) runs two `User` SELECTs + a full `generate_password_hash` "burn" (`auth_service.py:68-71`) + an `AuditLog` INSERT **and commit**; failures are never cached, so each bogus attempt re-pays the KDF, and the `audit_logs` table has no cap (unbounded disk + write contention against real CA ops on the same SQLite file). Separately, OCSP (`public.py:74-89`, `@csrf.exempt`, no auth) performs a fresh asymmetric **signature per request** for any known serial (`software.py:99` / HSM `softhsm.py` under a process-wide lock) with no response cache — a known serial pins both workers on signing (HSM variant also contends the signing lock with privileged issuance — HSM-2). **Fix:** enable/scope rate limiting by default on the Basic-Auth and `/public/ocsp/*` paths; coalesce repeated `basic_auth_failed` audit writes; add an OCSP response cache keyed by `(ca, serial, status, hash_alg)`; add audit-log retention. (This is the residual of C1: the PBKDF2 key-decrypt amplifier was fixed, but the signing + flood amplifiers remain.)

> **✅ Fixed — [#73](https://github.com/guidorugo/cert-manager/pull/73) + [#74](https://github.com/guidorugo/cert-manager/pull/74) (v2.5.0).** Per-IP rate limiting is **on by default**, initialised **before** the Basic-Auth hook so a flood is 429'd before the KDF/audit write; OCSP responses are cached per `(ca, serial, status, hash_alg)`, ending per-request re-signing.

### [DoS-2] Unauthenticated last-admin lockout DoS — Medium — Confirmed
Lockout (`auth_service.py:116-132`, 5 fails → 15 min) is reachable unauthenticated via the CSRF-exempt Basic-Auth path and has **no last-admin exemption** (unlike deactivate/demote) and **no unlock**: `reset_password`/`toggle_active` don't clear `locked_until` (AUTH-4), and no CLI unlock exists. An attacker who knows the admin username (default `admin`) locks the sole administrator out of the entire admin plane for 15 min, repeatably. The D1 lockout control thus doubles as a self-DoS. **Fix:** prefer IP/endpoint throttling over hard per-account lockout for the admin, or exempt the last active admin while still throttling; clear lockout on password reset/reactivation; add a `users unlock` CLI. **Reproduction:** `for i in 1..5; do curl -u admin:wrong$i host/auth/login; done` → correct creds then rejected.

> **✅ Fixed — [#71](https://github.com/guidorugo/cert-manager/pull/71) (v2.5.0).** The **last active admin is never hard-locked** (throttled instead), `flask users unlock <user>` was added, and password-reset/reactivation now clear `locked_until` (closes AUTH-4).

### [TMPL-1] CSP retains `'unsafe-inline'` in `script-src` — Medium (defense-in-depth) — Confirmed
`app/__init__.py:307-317` ships a CSP, but `script-src ... 'unsafe-inline'` means any injected inline script/`on*` handler executes regardless of origin. The app is XSS-safe **only** because Jinja autoescape holds (verified: no `|safe`/`|urlize`/`autoescape false` anywhere). For a CA console, script execution in an admin session = full CA control, so the compensating control being neutralized matters. Documented as intended pending nonce work (E2 comment). **Fix:** per-response nonce, add `'nonce-…'`, drop `'unsafe-inline'` from `script-src`, and move the existing inline `on*` handlers to `addEventListener` (pattern already used in `base.html:128-134`).

> **✅ Fixed — [#78](https://github.com/guidorugo/cert-manager/pull/78) (v2.5.0).** A per-request nonce (`g.csp_nonce`) authorises inline `<script>` and `script-src` **no longer carries `'unsafe-inline'`**; all inline `on*` handlers were moved to `addEventListener`.

### [META-1] JSON content-negotiation API is untested for authz and omitted from the 05-08 closure claim — Medium — Confirmed
`tests/test_json_api.py` exercises only `auth_admin` happy paths. There is **no** test that a `csr_requester` (or unauthenticated client) using `Accept: application/json` / Basic Auth gets ownership-filtered results and **403/401 JSON** on cross-user or admin routes. `SECURITY_ASSESSMENT_05-08-26.md:113` says "No open residuals remain," but grep shows the assessment never mentions the JSON API (merged after, PR #64). **Verified mitigation:** authz is enforced *before* the `wants_json()` branch in every handler (`certificates.py:164-171`, `csr.py:128-135`, `users.py:15`), so the property holds today — this is a **false-assurance/coverage** gap, not an exploitable bug. **Fix:** add JSON negative-path tests mirroring `test_rbac.py`/`test_csr_requester.py` with `Accept: application/json`; add a dated "JSON API" subsection to the assessment.

> **✅ Fixed — [#77](https://github.com/guidorugo/cert-manager/pull/77) (v2.5.0).** JSON authz/negative-path tests were added (cross-user 403, unauth 401, ownership-filtered results) mirroring the RBAC suite.

### [PKI-3 / API-1] Issued cert `not_after` stored **unclamped** — Low-Medium — Confirmed (independently, twice)
`cert_service.py` clamps the real cert to the CA's expiry (`bounded_not_after`, used at `:270`/`:101`) but stores the **raw** `now + validity_days` in the DB (`:383` in `create_certificate`, `:231` in `sign_csr`). Whenever the requested validity would outlive the issuing CA (routine for intermediates/aging CAs), the DB row, the detail page (`certificates/detail.html:46`), and the JSON `not_after` (`certificate.py:40`) report a **later** expiry than the certificate actually has. `ca_service` does this correctly, so it's isolated to `cert_service`. Impact: wrong renewal scheduling → surprise early expiry. **Fix:** store the clamped `not_after` in both constructors.

> **✅ Fixed — [#68](https://github.com/guidorugo/cert-manager/pull/68) (v2.5.0).** Issuance now stores the **CA-clamped** `not_after` in both constructors; `flask certs recompute-expiry` backfills legacy rows.

### [API-2 / TMPL-2] Cert OCSP/CRL URLs derived from an unvalidated `Host` under default config — Low-Medium — Confirmed
With `SERVER_NAME_FOR_OCSP` at its default, `certificates.py:55-57` / `csr.py:158-160` set the AIA/CRL-DP host from `request.host` (no Flask `SERVER_NAME`/allowlist). A spoofed `Host` (naïve proxy forwarding client Host, cache poisoning, or a tricked admin) bakes attacker-controlled revocation URLs into long-lived certs → serve `GOOD` for a revoked cert / blackhole revocation. Admin-gated issuance, so preconditioned; reaffirms C4 (still trust-the-Host by default). The template also interpolates `request.host` into a JS string without `|tojson` (`certificates/create.html:262`) — **not** exploitable today (autoescape blocks breakout in `<script>` raw-text context) but fragile. **Fix:** require an explicit `SERVER_NAME_FOR_OCSP` in non-debug mode / set a trusted-host allowlist; encode the template value with `|tojson`.

> **📌 Residual — documented mitigation (by design).** Not code-enforced because requiring `SERVER_NAME_FOR_OCSP` would break the zero-config `localhost` default. Instead the host is **auto-detected** from `request.host` and a **warning banner** appears in Advanced Settings when it contains `localhost`; the CRL-DP field is operator-editable. The `{{ ocsp_server }}` value stays autoescape-safe in its (now nonce-gated) `<script>` context. Re-open only if strict host-pinning becomes a requirement.

### Low / Informational (condensed)
- **[HSM-1]** EC CA whose curve `key_size ∉ {256,384,521}` → `migrate-to-hsm` imports fine then bricks on first sign (`_ca_key_info` `KeyError`, `softhsm.py:55`); software copy already scrubbed → irreversible loss of a trust anchor's signing/CRL/OCSP. Reachable because import skips the strength/curve floor (PKI-7). **Fix:** validate curve before scrub; friendly error not `KeyError`.
- **[HSM-3]** `pkcs11_session.py:48-60` caches a session but never clears it on a mid-op token error → every later sign reuses a dead handle until worker restart. **Fix:** best-effort close+clear `_session` on PKCS#11 exception.
- **[PKI-4]** Issuing from an expired-but-non-revoked CA yields a pyca `ValueError` swallowed as a generic 500, or (near-expiry) a silently ultra-short cert. **Fix:** add an expiry filter to `signing_capable()` / explicit route check.
- **[PKI-6]** `create_intermediate_ca` places user `path_length` into BasicConstraints without checking the parent's `pathLenConstraint` (e.g. parent `path_length=0`) → un-validatable chain. **Fix:** validate/derive against parent.
- **[PKI-7]** CA import (`_import_ca_object`) never calls `enforce_public_key_strength`, unlike generation/issuance → a 1024-bit or off-curve CA can be imported and used. **Fix:** enforce (or warn) on import.
- **[PKI-5]** OCSP omits the request nonce (both backends) → replayable within the 24h window; defensible per RFC 5019 but a deviation. Reaffirms B6 (accepted).
- **[AUTH-2]** Distinct "account locked" flash vs generic "invalid" gives a local-username existence oracle (after driving a lock via DoS-2). **Fix:** generic message; keep the reason in the audit log only.
- **[AUTH-3]** The forced first-login password change exempts `g.basic_auth_used` (`__init__.py:100`), so a flagged bootstrap admin keeps full API access via `curl -u admin:SEED` without ever rotating. By-design but weakens the "rotate the seed" control. **Fix:** return 403-with-guidance for `must_change_password` Basic-Auth users, or offer a Basic-Auth change-password path.
- **[AUTH-4]** No operational unlock (see DoS-2): password reset/reactivation leave `locked_until`. **Fix:** clear lockout there; add unlock action/CLI.
- **[CORE-2]** `_check_security` only rejects the *literal* placeholder secrets; an empty/blank `SECRET_KEY`/`MASTER_PASSPHRASE` (truncated secret file) boots. **Fix:** also reject falsy/too-short values.
- **[CORE-3]** `migrate-to-hsm` scrubs `private_key_enc=b""` with no readback/test-sign, contradicting CLAUDE.md's "verified import." **Fix:** verify the token key (public-key match or sign-a-nonce) before scrubbing.
- **[CORE-4]** `update_service._refresh` can raise `AttributeError` on a non-dict JSON body (`data.get`, `:61`), skipping the `refreshing=False` reset → permanent per-worker stall (fail-silent, no crash/leak). **Fix:** reset in `finally`; validate `isinstance(data, dict)`.
- **[CORE-5]** `SESSION_LIFETIME_MINUTES` uses `int(os.environ.get(..., "30"))` not the empty-safe `... or "30"` idiom → a set-but-empty value crashes boot (fail-closed). **Fix:** use the `or` form (as every other numeric var does).
- **[API-3]** The CSRF exemption keys on `g.basic_auth_used`; safe for session/`Accept`-json clients, but a browser holding **cached** Basic creds would auto-attach them to a cross-site POST and skip CSRF. Strong precondition (app never triggers the Basic dialog for fresh browsers). **Fix:** also require `Origin`/`Sec-Fetch-Site`/custom-header before honoring the exemption.
- **[API-4 / CORE-6]** 401/403 key on `g.basic_auth_used` (not `wants_json()`), and there are no 404/405/500 handlers → JSON clients can get HTML redirects/bodies for those statuses. No info leak (bodies emit JSON only when `wants_json()`; browsers send `text/html`); API-contract wart only. **Fix:** base error responses on `wants_json()`; register `wants_json()`-aware 404/405/500 handlers.
- **[API-5]** `csr.reject` (`csr.py:246-262`) lacks the `status=="pending"` guard that `sign` has → an approved CSR can be flipped to `rejected` while its cert stays live. Admin-only. **Fix:** guard on pending.
- **[TMPL-3]** Logout is GET (`auth.py:117`) → `<img src=.../auth/logout>` forces logout. **Fix:** POST-only + CSRF form.
- **[INFRA-2]** CLAUDE.md/prompt claim "Trivy (fs + image scan)"; reality is one **image** scan, `exit-code:0` (non-blocking), gated to `v*` tags only (`docker-publish.yml:126-135`). pip-audit is the only blocking dependency gate. **Fix:** add a real `scan-type: fs` step on PRs/master, or correct the docs.
- **[INFRA-3]** `.claude/settings.local.json` is tracked (since first commit) with auto-approve `Bash(git push*)`/`gh pr*`/`docker compose*` etc. No secret, but pre-authorizes git/registry actions for any checkout. **Fix:** `git rm --cached` + gitignore `.claude/`.
- **[INFRA-4]** Reference `docker-compose.yml` ships `SESSION_COOKIE_SECURE=false` (`:24`) and `ADMIN_PASSWORD` as a `docker inspect`-visible env literal (`:19`, unlike `MASTER_PASSPHRASE`'s `_FILE`). TLS overlay fixes cookies; app rejects literal `admin`. **Fix:** default `SESSION_COOKIE_SECURE` unset (code default true); support `ADMIN_PASSWORD_FILE` in compose.
- **[INFRA-5]** `.dockerignore` omits `secrets/` (also `deploy/`, `scripts/`). Safe today only because the Dockerfile uses selective `COPY`; a future `COPY . .` bakes the master passphrase/PINs into the public image. **Fix:** add `secrets/`, `deploy/`, `scripts/`, `.claude/`.
- **[INFRA-6]** Compose has no `deploy.resources`/`pids_limit`/`healthcheck`/`read_only`. **Fix:** add mem/CPU/pids limits, a healthcheck, and `read_only: true` + `tmpfs`.
- **[META-2]** JSON no-leak tests assert specific field names (`private_key_enc`, `password_hash`) not a key allowlist — safe only because serializers are allowlists. **Fix:** assert `set(body) <= EXPECTED`.

---

## Reconciliation with the prior assessments

- **A1 (CA key protection, "Resolved via HSM"):** software backend confirmed strong; **HSM at-rest strength is gated by PIN entropy** — currently weak (INFRA-1). Refine, don't reopen.
- **C1 (OCSP DoS, "Resolved"):** the PBKDF2 key-decrypt amplifier *is* fixed and OCSP parses/looks-up before decrypting — verified. **Residual:** per-request signing + unbounded Basic-Auth flood remain, gated only by opt-in rate limiting (DoS-1).
- **D1 (lockout, "Mitigated"):** confirmed present and tested (triggers *and* releases), but introduces an **unauthenticated last-admin lockout DoS** with no unlock (DoS-2/AUTH-4).
- **E2 (CSP, "Resolved"):** headers are present and correct (SRI, frame-ancestors, HSTS all verified), but `'unsafe-inline'` makes CSP ineffective as XSS defense (TMPL-1).
- **C4 (host-header):** still trust-the-`Host` by default (API-2) — reaffirmed as documented residual.
- **B6 (OCSP nonce), A4 (insecure example defaults), A5 (subscriber key escrow), G1 (audit tamper-evidence):** reaffirmed as previously **Accepted**; A5+G1 noted as the concentrated blast radius of a single volume/backup theft (all software-CA keys + escrowed leaf keys + a non-tamper-evident audit log; HSM CAs survive it *if* INFRA-1 is fixed).
- **A3/A6 (git-history hygiene):** **independently re-verified clean** — 132 commits, no `.env`/`.key`/`.pem`/`.p12`/`forgejo` blob ever added, `.git` 3.3 MB with no >100 KB blobs, all `v*` tags clean. The A3 credential was `.git/config`-only (local disk), never in history — prior doc accurate.
- **05-08 "No open residuals remain":** accurate *for the 41 findings then known*; this pass adds new lower-severity items and one doc gap (META-1). No Critical/High.

## Positive controls (verified, not taken on faith)

CSR proof-of-possession enforced before signing; leaf certs hardcode `ca=False` + strip `keyCertSign`/`cRLSign` even from caller-supplied KU; 158–160-bit random unique serials; SHA-256 everywhere for signatures; PBKDF2-HMAC-SHA256/600k with unique per-key salt and authenticated Fernet; revocation regenerates the issuing CRL and lists revoked **intermediates** in the parent CRL+OCSP; atomic `crlNumber`; OCSP parses/looks-up before key decrypt and returns unsigned `UNAUTHORIZED` for unknown/keyless. **HSM:** RSA cert/CRL DER byte-identical to software, EC `r‖s`→DER correct and verified, OCSP semantic parity, `CKA_SENSITIVE/EXTRACTABLE=false`, export genuinely refused, cross-backend intermediates correct, fail-closed, PINs never logged. **Auth:** complete decorator coverage, ownership/IDOR enforced on HTML+JSON, local-first break-glass, LDAP injection defended (filter+DN escaping), no anonymous-bind, LDAP TLS verified by default (chain+hostname, confirmed in ldap3 source), safe HMAC Basic-Auth cache that re-reads the User row, robust open-redirect rejection, secure cookie defaults, timing-equalized failures, last-admin guards. **API:** no serializer leaks; CSR one-time key returned once to owner and never persisted; CSRF wired (only OCSP exempt); export POST-only with password from `request.form`; `_safe_filename` blocks header injection; nosniff/frame-deny/CSP/HSTS/Referrer-Policy on all responses. **Templates:** autoescape intact, every state-changing form CSRF-tokened, both CDN assets correct SRI+crossorigin, `rel=noopener` on the one `_blank`. **Infra:** non-root uid-1000 fail-closed privilege drop, digest-pinned base image, fully SHA-pinned actions, hash-locked deps (`--require-hashes`), pip-audit gates publish, publish gated to `v*` tags (a merge cannot auto-publish, `pull_request` not `pull_request_target`), keyless cosign + SLSA + SBOM, idempotent token init, **the prior too-short-PIN bug is fixed** (length now correct), GPLv3 consistent. **Tests:** assert real semantics (REVOKED status, serial-in-CRL, lockout trigger+release, cross-user 403), HSM differential parity gate is real and CI-run (clean binary skip locally), fixtures offline/deterministic. **Docs:** README steers to `init-secrets.sh` + the TLS overlay that pins `SERVER_NAME_FOR_OCSP`.

## Consolidated open questions / needs-verification

1. Confirm the grounded deployment context above (esp. TLS in front, and that the 2 HSM CAs are the live ones affected by INFRA-1).
2. **Live CI:** confirm the HSM differential tests report **run** (not skipped) on HEAD, and check the latest scheduled pip-audit run is green.
3. **Dependency currency (offline):** pins are unusually high for a Jan-2026 knowledge cutoff (cryptography 50.0.0, Werkzeug 3.1.8, gunicorn 26.0.0) — confirm no fresh advisory via OSV/PyPI.
4. `~/.git-credentials` (Forgejo `credential.helper store`) mode-600?
5. Is the P-521/P-384 HSM path signing a SHA-256 digest intentional (honest `ecdsa-with-SHA256`, lower margin than typical for P-521)?
6. Non-Docker `gunicorn --workers N` without the pre-fork migration step could race two `ALTER`s on first upgrade — is that deployment supported?

## Prioritized remediation roadmap

1. **INFRA-1** — regenerate SoftHSM PINs with high entropy (alphanumeric ≥16) and re-key the 2 HSM tokens; exclude the token dir from routine DB backups. *(Highest — protects live root-CA keys at rest.)*
2. **DoS-1 / DoS-2** — enable/scope rate limiting by default on Basic-Auth + `/public/ocsp/*`; exempt the last admin from hard lockout (throttle instead); add an unlock CLI and clear lockout on reset/reactivate; cap/coalesce audit flooding; add an OCSP response cache.
3. **PKI-1** — lazy/scheduled CRL regeneration (or long, configurable `nextUpdate`).
4. **PKI-3/API-1** — store the clamped `not_after` (one-line fix, ×2). **PKI-4/PKI-7/HSM-1** — enforce key/curve floor on import + expired-CA guard, closing the migrate-to-HSM brick.
5. **TMPL-1** — CSP nonce + drop `script-src 'unsafe-inline'`.
6. **META-1/META-2** — JSON API authz/negative-path tests + allowlist-subset no-leak assertions; add the JSON-API subsection to the assessment.
7. **Hygiene sweep** — INFRA-3/-4/-5/-6, CORE-2/-4/-5, API-3/-4/-5, AUTH-2/-3, TMPL-3, INFRA-2 (doc/CI).

## Bottom line

The core CA is cryptographically and authorization-wise **sound** — no Critical/High, no key-exfiltration or unauthorized-issuance path, and the HSM re-implementation is byte-correct. The actionable risk is (1) the **SoftHSM PIN entropy** undercutting at-rest protection for the live HSM CAs, (2) **availability** gaps (CRL expiry, unauthenticated DoS/lockout with rate limiting off by default), (3) **CSP** not backing up autoescape, and (4) the **JSON API** being correct-but-untested and outside the prior closure claim. Everything else is Low/Info hardening.
