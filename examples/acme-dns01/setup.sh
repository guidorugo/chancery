#!/bin/sh
# Renders named.conf from named.conf.template with a fresh TSIG secret and
# writes the same key in nsupdate/acme.sh format (tsig.key). Idempotent: an
# existing secret is kept. Requires openssl.
set -eu
cd "$(dirname "$0")"
KEY_NAME="${TSIG_KEY_NAME:-chancery-acme}"
if [ ! -f tsig.secret ]; then
    umask 077
    openssl rand -base64 32 > tsig.secret
    umask 022
fi
SECRET="$(cat tsig.secret)"
sed -e "s|@@KEY_NAME@@|$KEY_NAME|g" -e "s|@@SECRET@@|$SECRET|g" named.conf.template > named.conf
# BIND reads the file as its own unprivileged user inside the container, so it
# must be world-readable there; the secret only allows TXT updates in the zone.
chmod 644 named.conf
printf 'key "%s" {\n    algorithm hmac-sha256;\n    secret "%s";\n};\n' "$KEY_NAME" "$SECRET" > tsig.key
chmod 600 tsig.key tsig.secret
echo "TSIG key '$KEY_NAME' (hmac-sha256) ready: secret in tsig.secret, nsupdate format in tsig.key; named.conf rendered."
