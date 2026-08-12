# Container Image Vulnerability Scan — 2026-08-12

**Image:** `ghcr.io/guidorugo/cert-manager:latest` (base: Debian 13.6 "trixie", `python:3.13-slim` derived — Python 3.13.14)
**Scanners:** Trivy (gate fails on HIGH,CRITICAL) + Grype (informational NVD second opinion, EPSS/risk scored)
**Trivy totals:** 200 findings — CRITICAL: 5, HIGH: 25, MEDIUM: 68, LOW: 69, UNKNOWN: 33

Findings below are **deduplicated by CVE + source package** (Trivy reports each binary package separately, so e.g. one util-linux CVE appears 9 times in the raw output).

---

## Triage summary

| Bucket | Count (unique CVEs) | Actionable? |
|---|---|---|
| Python interpreter (binary, Grype-only) | 9 | **Yes** — fixed upstream in 3.15.x / betas; watch for 3.13.x backports and bump base image |
| Debian OS packages, `won't fix` / `fix_deferred` / no fixed version | ~60 | **Not via upgrade** — Debian stable will not ship fixes; mitigate via attack-surface reduction + scan-gate policy |
| Debian OS packages with a fixed version available | 0 | Nothing currently upgradeable — image is already on latest trixie point-release packages (`deb13u3` etc.) |

**Key fact:** every single deb finding has an empty "Fixed Version" column in Trivy. `apt-get upgrade` / a base-image digest bump fixes *nothing* in this list today. The levers are: (1) Python version bump when a patched 3.13.x lands, (2) removing packages we don't need, (3) a `.trivyignore`/VEX policy so the HIGH/CRITICAL gate only fails on *actionable* findings.

---

## 1. Python interpreter (Grype only — Trivy doesn't flag the binary)

Installed: **3.13.14**. All fixes are in 3.15.x per Grype; CPython typically backports security fixes to 3.13.x patch releases — track and bump the base image when available.

| CVE | Severity | Fixed in (upstream) | EPSS |
|---|---|---|---|
| CVE-2026-11940 | High | 3.15.0b4 | 0.7% (50th) |
| CVE-2026-15308 | High | 3.15.0 | 0.6% (46th) |
| CVE-2026-11972 | High | 3.15.0b4 | 0.4% (36th) |
| CVE-2025-15366 | Medium | 3.15.0a6 | 0.4% |
| CVE-2025-15367 | Medium | 3.15.0a6 | 0.3% |
| CVE-2026-4360 | Medium | — | 0.3% |
| CVE-2026-12003 | Medium | 3.15.0b3 | 0.1% |
| CVE-2026-0864 | Medium | 3.15.0b4 | 0.1% |
| CVE-2026-6879 | Low | — | 0.3% |

## 2. CRITICAL (Trivy: 5 unique)

| CVE | Package(s) | Status | Notes |
|---|---|---|---|
| CVE-2026-58016 | libglib2.0-0t64 2.84.4-3~deb13u3 | won't fix | Integer underflow in gio/gdbusintrospection (`g_dbus_node_info_new_for_xml`). App never parses D-Bus introspection XML. |
| CVE-2026-13221 | perl-base 5.40.1-6 | affected, no fix | Perl regex silently incorrect results. perl-base is a slim-image essential; app runs no Perl. |
| CVE-2026-42496 | perl-base | fix_deferred | Archive::Tar path traversal via symlinks. |
| CVE-2026-57433 | perl-base | affected | Storable signed integer overflow. |
| CVE-2026-8376 | perl-base | affected/won't fix | Regex heap overflow on 32-bit builds (we're amd64). |

Grype additionally rates as Critical: CVE-2026-5450 (glibc `scanf %mc` heap overflow — won't fix) and CVE-2026-12087 (perl Socket OOB read — Trivy: Medium).

## 3. HIGH (Trivy: 25 unique CVEs after dedup)

### glibc 2.41-12+deb13u3 (libc6, libc-bin) — all won't fix
- CVE-2026-5450 — heap overflow in `scanf` with `%mc` (Grype: Critical)
- CVE-2026-5435 — OOB write via TSIG record processing (Grype: High, Trivy: Medium)
- CVE-2026-5928 — info disclosure/DoS via `ungetwc` (Grype: High, Trivy: Medium)

### glib2 2.84.4-3~deb13u3 (libglib2.0-0t64) — all won't fix
- CVE-2026-58010 — buffer over-read gvariant-serialiser `gvs_tuple_is_normal()`
- CVE-2026-58011 — OOB read `g_date_time_get_ymd`
- CVE-2026-58012 — buffer over-read `g_regex_replace()`
- CVE-2026-58013 — buffer over-read `g_io_channel_read_line_backend`
- CVE-2026-58014 — off-by-one `g_key_file_get_locale_string_list`
- CVE-2026-58015 — path traversal gdbusauthmechanismsha1
- CVE-2026-16118 — xdgmime heap overflow (Grype: High, Trivy: Medium)

Note: check whether libglib2.0 is even needed in the image (likely pulled in as a dependency — candidate for removal).

### util-linux 2.41-5 (bsdutils, libblkid1, liblastlog2-2, libmount1, libsmartcols1, libuuid1, login, mount, util-linux — 9 binary packages)
- CVE-2026-53615 — HIGH — integer overflow in libblkid dos.c partition probing (won't fix)
- CVE-2026-13595 — Medium — heap UAF in libblkid nested partition probing
- CVE-2026-27456 — Medium — TOCTOU in mount loop-device setup
- CVE-2026-3184 — Medium — access-control bypass via hostname canonicalization
- CVE-2026-53612 / 53613 / 53614 — Unknown — local privesc via TOCTOU in mount(8) / `LIBMOUNT_FORCE_MOUNT2` nosuid bypass
- CVE-2022-0563, CVE-2025-14104 — Low

All local-attacker / block-device-probing vectors; container runs as non-root with `cap_drop: ALL` and `no-new-privileges`, no block devices, no suid mount usable.

### ncurses 6.5+20250216-2 (libncursesw6, libtinfo6, ncurses-base, ncurses-bin) — won't fix
- CVE-2025-69720 — HIGH — buffer overflow, potential code exec (requires processing malicious terminfo — no interactive terminal use at runtime)
- CVE-2025-6141 — Low

### perl-base 5.40.1-6 (continued)
- CVE-2026-42497 — HIGH — Archive::Tar arbitrary file modification via hardlinks (fix_deferred)
- CVE-2026-48962 — HIGH — IO::Compress arbitrary code exec via output glob
- CVE-2026-57432 — HIGH — pack/unpack integer overflow info disclosure
- CVE-2026-9538 — HIGH — Archive::Tar DoS (fix_deferred)

### Misc HIGH
- CVE-2026-41992 — gzip 1.13-1 — global buffer overflow in LZH decoder (won't fix)
- CVE-2026-54369 — libacl1 2.3.2-2+b1 — symlink traversal privesc (won't fix)
- CVE-2026-11822 / CVE-2026-11824 — libsqlite3-0 3.46.1-7+deb13u1 — memory corruption / heap overflow, fixed upstream in SQLite 3.53.2 (Grype: High, Trivy: Medium; won't fix in trixie). Relevant-ish: this is our DB engine, but SQL input is app-generated via SQLAlchemy, not attacker-supplied.

## 4. MEDIUM (remaining unique, grouped)

- **perl-base:** CVE-2025-15649, CVE-2026-48959, CVE-2026-48961 (IO::Compress DoS variants), CVE-2026-7010 (HTTP::Tiny CRLF injection), CVE-2026-12087 (Socket OOB read)
- **glibc:** CVE-2026-6238 (crash/uninit read via crafted DNS response — mildly relevant, app does DNS lookups for update-check/LDAP)
- **glib2:** CVE-2026-15588 (GDBusServer pre-auth DoS)
- **opensc / opensc-pkcs11 0.26.1-2** (installed for the SoftHSM/PKCS#11 stack): CVE-2025-49010, CVE-2025-66037, CVE-2025-66038, CVE-2025-66215, CVE-2026-10275 — all require crafted smart card / USB device responses; no physical smart cards in this deployment (SoftHSM is software-only). All won't fix.
- **libsqlite3-0:** CVE-2026-50812 (session-ext NULL deref), CVE-2026-50813 (local)
- **tar 1.35+dfsg-3.1:** CVE-2026-18477, CVE-2026-18508, CVE-2026-5704 (extraction attacks; tar unused at runtime)
- **gzip:** CVE-2026-41991 (gzexe insecure tmp file)
- **libpam\* 1.7.0-5:** CVE-2026-54411 (pam_userdb timing — fix_deferred; PAM unused by the app)
- **libacl1:** CVE-2026-54370; **libattr1:** CVE-2026-54371 (getfattr/setfattr symlink TOCTOU)
- **libbz2-1.0:** CVE-2026-42250 (bzip2recover DoS)
- **zlib1g:** CVE-2026-27171 (CRC32-combine infinite loop DoS)

## 5. LOW / UNKNOWN / legacy (accepted-risk candidates)

Long tail of decade-old "Negligible" Debian entries that ship in every Debian-based image and will never be fixed:

- glibc: CVE-2010-4756, CVE-2018-20796, CVE-2019-9192, CVE-2019-1010022/23/24/25; CVE-2026-6368 (wordexp), CVE-2026-6791 (tilde expansion)
- apt/libapt-pkg7.0: CVE-2011-3374 · bash: TEMP-0841856 · coreutils: CVE-2017-18018, CVE-2025-5278, CVE-2026-56391/56392 · diffutils: CVE-2026-53910 · shadow (login.defs/passwd): CVE-2007-5686, CVE-2024-56433, TEMP-0628843 · sysvinit-utils: TEMP-0517018 · tar: CVE-2005-2541, TEMP-0290435 · systemd libs (libsystemd0/libudev1): CVE-2013-4392, CVE-2023-31437/38/39, CVE-2026-40228 · sqlite: CVE-2021-45346, CVE-2025-70873 · perl: CVE-2011-4116, CVE-2026-15534, CVE-2026-7017 · opensc: CVE-2025-13763 · ncurses: CVE-2025-6141

---

## Remediation plan (proposed)

Context: app already runs as non-root uid 1000, `cap_drop: ALL`, `no-new-privileges`, read-only-ish surface. Nearly all OS findings require local code execution or feeding crafted input to binaries the app never invokes (perl, tar, gzip, mount, ncurses, D-Bus). Practical exploitability inside this container is very low — but the HIGH/CRITICAL gate fails, so we need both real fixes and a policy layer.

- [ ] **1. Refresh base image digest pin** — rebuild against the latest `python:3.13-slim` digest (Dependabot may already have a PR). Won't clear the won't-fix list but picks up any new deb13u point fixes and a possible 3.13.15 Python.
- [ ] **2. Python CVEs** — check whether CVE-2026-11940 / CVE-2026-15308 / CVE-2026-11972 have 3.13.x backports; bump base tag as soon as a patched 3.13 image exists. These are the only High findings with real fixes available.
- [ ] **3. Attack-surface reduction in the Dockerfile final stage** — audit and remove packages the runtime doesn't need. Candidates: `libglib2.0-0t64` (why is it installed? — check apt rdepends), `opensc`/`opensc-pkcs11` (verify whether entrypoint token init uses `pkcs11-tool` or only `softhsm2-util`), ncurses bins. Note: `perl-base`, `tar`, `gzip`, `util-linux`, `mount`, `login` are Debian Essential/Required — removing them means `dpkg --force-remove-essential` or moving to a distroless/chiseled final stage (bigger project, evaluate separately).
- [ ] **4. Scan-gate policy** — add a `.trivyignore` (or better, an OpenVEX statement) covering the won't-fix OS CVEs with justification (`vulnerable_code_not_in_execute_path`), and/or run the gate with `--ignore-unfixed` so it only trips on findings we can actually act on. Keep the full unfiltered report as an artifact.
- [ ] **5. Recurring rebuild** — the weekly pip-audit cron exists; consider a scheduled image rebuild + republish so point-release fixes flow into `:latest` without a code release.
- [ ] **6. Re-scan after each step** and update this document.

## Accepted risks (proposed — confirm before closing)

- All Debian `won't fix` / `Negligible` entries in section 5, and the util-linux/mount local-privesc family (no suid path in a `no-new-privileges`, cap-dropped, non-root container).
- opensc smart-card CVEs (no physical card reader; SoftHSM only).
- perl-base module CVEs (Perl never executed by the app; package is Debian Essential).

---

## Resolution — 2026-08-12: migrated to Alpine (v2.8.0)

Since **nothing in the Debian list was upgradeable** (all `won't fix`/`fix_deferred` in trixie stable), the remediation plan above was superseded by moving the image off Debian entirely. The base is now `python:3.13-alpine` (digest-pinned), which carries none of the flagged packages — no perl, util-linux, glib2, ncurses, tar, gzip binaries, PAM, systemd libs, or Debian sqlite.

**Post-migration Trivy scan: 0 findings** (was 200) — 0 OS-package vulns on Alpine 3.24.1, 0 Python vulns. Grype's Python-interpreter findings also improve: Alpine ships 3.13.15 (Debian image was on 3.13.14).

Changes (branch `refactor/alpine-image`):
- `Dockerfile`: both stages on `python:3.13-alpine@sha256:540c7d…`; builder uses `apk add build-base libffi-dev`; runtime `apk add softhsm su-exec`; **pip uninstalled from the final image** (the last 3 findings were against pip's *vendored* setuptools/msgpack metadata, and removing pip also denies tool-install to an attacker in the container). Image size: 198MB → **123MB**.
- `entrypoint.sh` / `entrypoint-app.sh`: `#!/bin/sh` (no bash on Alpine); privilege drop via `su-exec` (busybox `setpriv` lacks `--reuid`). Same CAP_CHOWN/SETUID/SETGID model.
- **opensc dropped** (image + CI test deps): diagnostics-only, verified unused — clears its 6 CVEs.
- No app-code, config, or lockfile changes: Alpine's `softhsm` package uses the identical `/usr/lib/softhsm/libsofthsm2.so` path, and every locked dependency resolved as a musllinux wheel or built from its hash-pinned sdist (`--require-hashes` kept).

Verified: image builds; container healthy under compose-equivalent hardening (cap_drop ALL, no-new-privileges, non-root uid 1000); SoftHSM token init works; **full 532-test suite passes inside the Alpine image** (incl. SoftHSM byte-parity differential tests on musl).
