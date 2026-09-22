# Upgrading Chancery

Chancery is designed to upgrade in place. Your data (`./data` — the SQLite
database, encrypted CA keys, the SoftHSM token) and your secrets (`./secrets/`)
live outside the image and survive an upgrade, and schema changes apply
themselves on startup through idempotent `ALTER TABLE` migrations. For most
releases, upgrading is fetch-and-restart.

This guide covers the standard procedure, the version-specific one-time steps a
few releases need, and the behaviour-changing settings that are left **off by
default** on purpose so you can adopt them deliberately.

> Always read the [release notes](https://github.com/guidorugo/chancery/releases)
> for the version you are moving to. Any step beyond fetch-and-restart — a new
> `.env` value, a one-time command, a changed default — is called out there.
> Run CLI commands as the `app` user (`docker compose exec -u app app flask …`);
> a plain `exec` runs as root, which cannot read the `0600` secret files.

## Standard upgrade

Back up first. The data and secrets directories are all you need to restore.

```bash
cp -a data data.bak && cp -a secrets secrets.bak
# or a timestamped archive:
tar czf ../chancery-data-$(date +%F).tgz data secrets
```

**Built from source:**

```bash
git pull
docker compose up -d --build      # schema auto-migrates on boot
```

**Pre-built image** (when `docker-compose.yml` uses `image:` rather than `build:`):

```bash
docker compose pull
docker compose up -d
```

Verify:

```bash
curl -fsS http://localhost:5000/health          # {"status":"ok"}
docker compose logs --tail 20 app               # no tracebacks; access-log lines appear
```

The footer version and the *Update available* badge confirm the running
version. After a restart the background scheduler's lease is still held by the
old container for up to three ticks (about three minutes), so its first jobs run
a few minutes in; check `docker compose exec -u app app flask scheduler status`
rather than the lease row if you are verifying immediately.

## Version-specific one-time steps

These are safe to run late and are idempotent; run them once after reaching the
version. The release notes repeat them for the version that introduces each.

| After upgrading to | Run (as the `app` user) | Why |
|---|---|---|
| **2.5.0** | `flask certs recompute-expiry` | Store the real, CA-clamped `notAfter` on certificates issued by older versions |
| **2.6.0** | SoftHSM PIN migration — see the [v2.6.0 notes](https://github.com/guidorugo/chancery/releases/tag/v2.6.0) | Raise auto-generated token PINs to 32 chars; existing tokens keep their PINs unless you rotate |
| **2.11.0** | `flask certs backfill-issuers` (`--dry-run` first) | Fill the new signer/issuer fields on pre-existing CSRs and certificates from the audit log |
| **3.7.0** | *(none — note only)* | Validity caps became three tiers and their defaults changed: leaf `MAX_CERT_VALIDITY_DAYS` 825 → **1825** (5y), a new `MAX_INTERMEDIATE_VALIDITY_DAYS` **3650** (10y), root `MAX_CA_VALIDITY_DAYS` 7305 → **7300** (20y). Existing certs/CAs are untouched (caps apply only at issuance). A default deployment now accepts longer leaves — set `MAX_CERT_VALIDITY_DAYS=825` to keep the old ceiling; intermediates are capped tighter (3650 vs the old 7305), so raise `MAX_INTERMEDIATE_VALIDITY_DAYS` if you issue intermediates beyond 10 years. |

Nothing since 2.11.0 has needed a one-time command: newer schema columns are
populated by their migrations, and the audit hash chain (3.3.0) seals existing
rows automatically on the first scheduler tick.

## Fresh installs and bare `docker run`

- A **fresh clone** must run `./scripts/init-secrets.sh` before the first
  `docker compose up` — it creates `secrets/master_passphrase`, the SoftHSM
  PINs and an `.env` with a strong `SECRET_KEY` and `ADMIN_PASSWORD`. It is
  idempotent and never overwrites values you have set.
- A bare `docker run` (no compose) additionally needs
  `DATABASE_URL=sqlite:////app/data/cert-manager.db`, an `ADMIN_PASSWORD`, and
  `SESSION_COOKIE_SECURE=false` on plain HTTP. Compose sets these for you.

## Read-only root filesystem (since 3.5.0)

The reference `docker-compose.yml` runs the container with a read-only root
filesystem and tmpfs scratch for `/tmp` and `/home/app`. Everything persistent
already lives under the `/app/data` volume, so no data moves and no migration
runs. Two consequences for operators:

- If you set `AUDIT_ARCHIVE_DIR`, it must resolve **under `/app/data`** — the
  rest of the filesystem is not writable.
- If you run the image from your **own** compose file or `docker run`, either
  add the same options —
  `--read-only --tmpfs /tmp:rw,nosuid,noexec,size=64m,mode=1777 --tmpfs /home/app:rw,nosuid,noexec,size=16m,uid=1000,gid=1000,mode=0700`
  — or keep your current writable setup. The image works either way; the
  read-only rootfs is defence in depth, not a requirement.

## Recommended opt-in settings

The following change what an existing deployment emits or accepts. They are
kept **off by default** so that upgrading never changes behaviour on its own.
Adopt each deliberately, ideally after the standard upgrade has settled, by
adding the variable to `.env` and running `docker compose up -d` (recreates the
container so the new environment is read). Each is reversible: remove the
variable and recreate to return to the default.

### Hash matched to the curve — `SIGNATURE_HASH_POLICY=match-curve`

By default every RSA and EC signature uses SHA-256 (`legacy`). With
`match-curve`, a P-256 CA keeps SHA-256, a P-384 CA signs with SHA-384 and a
P-521 CA with SHA-512, and RSA uses `RSA_SIGNATURE_HASH` (default SHA-256) —
the pairing the CA/Browser Forum and RFC 5759 profiles expect. Ed25519 and
Ed448 never take a separate digest.

- **What changes:** *new* signatures from P-384 and P-521 CAs — certificates,
  CRLs, OCSP responses, generated CSRs — change algorithm. Existing objects are
  untouched, and a P-256-only or RSA-only deployment sees no change.
- **Enable:** `SIGNATURE_HASH_POLICY=match-curve` (optionally
  `RSA_SIGNATURE_HASH=sha384|sha512`).
- **Verify:** issue a certificate from a P-384 CA and check
  `openssl x509 -noout -text` shows `ecdsa-with-SHA384`.

### Delegated OCSP responder — `OCSP_DELEGATED_RESPONDER=true`

By default OCSP responses are signed by the CA key itself (a byKey responder
ID). With this on, each CA issues a short-lived responder certificate
(EKU OCSPSigning, `id-pkix-ocsp-nocheck`) and signs responses with that; the
scheduler renews responders hourly and the request path renews lazily.

- **What changes:** every CA's OCSP **responder ID changes** the moment you
  flip it, because the signer is now the responder certificate, not the CA.
  Clients that pinned the responder identity must re-fetch. An expired CA keeps
  answering with its own key (a responder cannot be issued from it).
- **Enable:** `OCSP_DELEGATED_RESPONDER=true`. Optionally pre-issue the
  responders instead of waiting for the scheduler:
  `docker compose exec -u app app flask ocsp rotate-responders`.
- **Verify:** the CA detail page shows the responder mode and validity;
  `openssl ocsp` against a leaf shows the response signed by the responder cert.

### Mandatory certificate profiles — `PROFILES_REQUIRE_SELECTION=true`

By default an issuance request that names no profile falls back to the
unrestricted `custom` profile (legacy behaviour). With this on, such a request
is refused so every certificate is issued under an explicit, enforced policy.

- **What changes:** API or CLI callers that post raw `ku_*`/`eku_*` fields with
  **no** `profile` start getting `400`. The web forms always send a profile, so
  interactive use is unaffected.
- **Before enabling:** make sure your automation names a profile
  (`profile=<key>`); `docker compose exec -u app app flask profiles list` shows
  the keys.
- **Enable:** `PROFILES_REQUIRE_SELECTION=true`.

### Other behaviour-changing toggles

These are opt-in too and documented in full in the README, but are worth knowing
when you plan a deployment's policy:

- **`REQUIRE_2FA=admins|all`** forces TOTP enrolment before anything else and
  refuses Basic Auth for an un-enrolled account. Enrol the bootstrap admin
  first, and keep the recovery codes.
- **`DUAL_CONTROL_ENABLED=true`** turns on four-eyes issuance once a second
  active user exists: direct certificate creation is disabled, a CSR's creator
  cannot sign it, new CAs and new user accounts need approval by a different
  admin. The literal `ADMIN_USERNAME` account is exempt as break-glass.

## Rotating the master passphrase

Not part of a version upgrade, but the one procedure with an ordering that
matters. Rotate the stored ciphertext first, then swap the secret file, then
recreate:

```bash
docker compose exec -T -u app app flask keys rotate-passphrase --new-file - < secrets/master_passphrase.new
mv secrets/master_passphrase.new secrets/master_passphrase
docker compose up -d --force-recreate
docker compose exec -u app app flask keys check-passphrase
```

The full walk-through, including the `--dry-run` preview, is in the README under
*Rotating the master passphrase*.

## Rollback

The pre-upgrade backup is the rollback path. Migrations only add columns and
tables, so a newer database keeps working with the version that created it, but
Chancery does not down-migrate. To go back to an older image, restore `data/`
(and `secrets/` if you rotated anything) from the backup you took above and
start the older version.
