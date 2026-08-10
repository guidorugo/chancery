#!/usr/bin/env bash
#
# Bootstrap the local secrets and .env the Docker Compose stack needs.
#
# A fresh clone cannot `docker compose up` out of the box: the compose file
# bind-mounts ./secrets/master_passphrase (gitignored, so absent on a new
# checkout) and the app refuses to start while ADMIN_PASSWORD / SECRET_KEY hold
# their shipped placeholder values. This script creates those with strong,
# random values so the stack starts cleanly.
#
# Safe to re-run: it never overwrites an existing secret or a value you have
# already customised — it only fills in what is missing or still a placeholder.
#
# Creates: secrets/master_passphrase, .env (strong SECRET_KEY / ADMIN_PASSWORD),
# and the SoftHSM token PINs (the SoftHSM backend is enabled by default).
#
# Usage:
#   ./scripts/init-secrets.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

umask 077
mkdir -p secrets

gen() { openssl rand "$@"; }   # fail early & clearly if openssl is missing

note() { printf '  %s\n' "$1"; }

# Fixed-length generators using a finite producer (openssl), so no infinite
# `/dev/urandom | head` pipe that would SIGPIPE under `set -o pipefail`.
rand_alnum() {  # $1 = length
  gen -base64 $(( $1 * 3 )) | tr -dc 'A-Za-z0-9' | head -c "$1"
}
rand_pin() {    # $1 = number of digits
  local len=$1
  printf '%0*d' "$len" "$(( 0x$(gen -hex 4) % (10 ** len) ))"
}

echo "cert-manager :: init-secrets"

# 1. Master passphrase (Docker secret). NEVER overwrite an existing one — it
#    encrypts every CA private key, so a new value would orphan all existing
#    keys. Only create it when absent.
if [ ! -f secrets/master_passphrase ]; then
  gen -base64 24 | tr -d '\n' > secrets/master_passphrase
  chmod 600 secrets/master_passphrase
  note "created secrets/master_passphrase (random)"
  note ">> BACK THIS UP. It encrypts all CA keys; lose it and the keys are unrecoverable. <<"
else
  note "secrets/master_passphrase already exists — left unchanged"
fi

# 2. .env — created from the example, then any still-placeholder secret is
#    replaced with a strong random value (the app rejects the insecure defaults
#    'dev-secret-key' / 'admin' at startup; the shipped SECRET_KEY placeholder is
#    also regenerated so a real deployment never ships a guessable key).
if [ ! -f .env ]; then
  cp .env.example .env
  note "created .env from .env.example"
fi

if grep -qE '^SECRET_KEY=(change-me|dev-secret-key)' .env; then
  sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$(gen -hex 32)|" .env
  note "set a random SECRET_KEY in .env"
fi

if grep -qE '^ADMIN_PASSWORD=admin$' .env; then
  ADMIN_PW=$(rand_alnum 20)
  sed -i "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${ADMIN_PW}|" .env
  note "set a random ADMIN_PASSWORD in .env: ${ADMIN_PW}"
  note "(log in as the ADMIN_USERNAME from .env, then change this after first login)"
fi

# 3. SoftHSM token PINs — the SoftHSM backend is enabled by default in
#    docker-compose.yml, so these are always generated. Never overwrite an
#    existing PIN (it belongs to an already-initialised token).
if [ ! -f secrets/pkcs11_user_pin ]; then
  rand_alnum 20 > secrets/pkcs11_user_pin
  chmod 600 secrets/pkcs11_user_pin
  note "created secrets/pkcs11_user_pin (random 20-char alphanumeric)"
else
  note "secrets/pkcs11_user_pin already exists — left unchanged"
fi
if [ ! -f secrets/pkcs11_so_pin ]; then
  rand_alnum 20 > secrets/pkcs11_so_pin
  chmod 600 secrets/pkcs11_so_pin
  note "created secrets/pkcs11_so_pin (random 20-char alphanumeric)"
else
  note "secrets/pkcs11_so_pin already exists — left unchanged"
fi

echo "Done. Next: docker compose up --build"
