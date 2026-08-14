# Base image pinned by digest (H2). python:3.14.7-alpine3.24.
# Alpine base (musl) replaces debian-slim: the Debian image carried ~200
# unfixable ("won't fix" in stable) CVEs in Essential packages the app never
# executes (perl, util-linux, glib2, ncurses, ...) — see IMAGE_VULN_SCAN_12-08-26.md.
# Update via Dependabot (docker ecosystem) or re-resolve the tag's digest.
FROM python:3.14-alpine@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc AS builder

WORKDIR /build
# build-base + libffi-dev let C extensions compile from sdist when a musllinux
# wheel is unavailable (python-pkcs11 has no wheels); these stay in the builder
# stage and never reach the final image.
RUN apk add --no-cache build-base libffi-dev
COPY requirements.txt .
# --require-hashes enforces the hash-locked lockfile (I1): every artifact must
# match a pinned sha256, and every dependency (incl. transitive) must be pinned.
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.txt

FROM python:3.14-alpine@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc

WORKDIR /app

# softhsm provides libsofthsm2.so + softhsm2-util (token init; same paths as the
# Debian package, only exercised when KEY_BACKEND=softhsm). su-exec is the
# privilege-drop helper for entrypoint.sh (busybox setpriv lacks --reuid).
# opensc (pkcs11-tool, diagnostics-only on the old image) is intentionally
# dropped — it carried 6 CVEs and nothing in the app uses it.
RUN apk add --no-cache softhsm su-exec

# H1: non-root runtime user (uid 1000 to match the host secret/volume owner).
# The entrypoint starts as root only to fix volume ownership, then drops to it.
RUN addgroup -g 1000 -S app && adduser -S -u 1000 -G app -h /home/app app

COPY --from=builder /install /usr/local

# The runtime never installs packages: drop pip (and the ensurepip bundled
# wheel) from the final image. Clears the scanner findings against pip's
# vendored setuptools/msgpack and denies an attacker in the container the
# easiest tool-install path.
RUN pip uninstall -y pip && rm -rf /usr/local/lib/python3.*/ensurepip

COPY app/ app/
COPY entrypoint.sh entrypoint-app.sh ./
RUN chmod +x entrypoint.sh entrypoint-app.sh

RUN mkdir -p /app/data

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]
