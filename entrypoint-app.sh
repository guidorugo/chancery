#!/bin/sh
# App phase (H1): runs as the non-root 'app' user. It reads the 1000-owned Docker
# secrets, writes the app-owned data volume, and runs gunicorn — so the
# long-running, network-facing process never has root.
set -e

echo "Starting Certificate Manager..."

# A2: owner-only permissions on new DB files (encrypted CA keys, hashes, audit).
umask 077

# A1: initialise the SoftHSM token if a store is configured. Self-gating: the
# default software deployment does not set SOFTHSM2_CONF, so this is skipped.
if [ -n "${SOFTHSM2_CONF:-}" ] && command -v softhsm2-util >/dev/null 2>&1; then
    TOKEN_DIR="$(dirname "$SOFTHSM2_CONF")/tokens"
    mkdir -p "$TOKEN_DIR"
    chmod 700 "$(dirname "$SOFTHSM2_CONF")" "$TOKEN_DIR" 2>/dev/null || true
    if [ ! -f "$SOFTHSM2_CONF" ]; then
        printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
            "$TOKEN_DIR" > "$SOFTHSM2_CONF"
        chmod 600 "$SOFTHSM2_CONF" 2>/dev/null || true
    fi
    MODULE="${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}"
    LABEL="${PKCS11_TOKEN_LABEL:-cert-manager}"
    USER_PIN="${PKCS11_USER_PIN:-}"
    [ -n "${PKCS11_USER_PIN_FILE:-}" ] && [ -f "${PKCS11_USER_PIN_FILE}" ] && USER_PIN="$(cat "$PKCS11_USER_PIN_FILE")"
    SO_PIN="${PKCS11_SO_PIN:-}"
    [ -n "${PKCS11_SO_PIN_FILE:-}" ] && [ -f "${PKCS11_SO_PIN_FILE}" ] && SO_PIN="$(cat "$PKCS11_SO_PIN_FILE")"
    # Match the label allowing softhsm2-util's trailing padding spaces (a bare
    # "...${LABEL}$" fails to match and would re-init a duplicate token each boot).
    if ! softhsm2-util --show-slots --module "$MODULE" 2>/dev/null | grep -qE "Label:[[:space:]]*${LABEL}[[:space:]]*$"; then
        if [ -n "$SO_PIN" ] && [ -n "$USER_PIN" ]; then
            echo "Initialising SoftHSM token '$LABEL'..."
            softhsm2-util --init-token --free --label "$LABEL" \
                --so-pin "$SO_PIN" --pin "$USER_PIN" --module "$MODULE"
        else
            echo "WARNING: SOFTHSM2_CONF set but PKCS11_SO_PIN/PKCS11_USER_PIN unavailable; skipping token init." >&2
        fi
    fi
fi

# Run database initialization via Python
python -c "from app import create_app; create_app()"

# Tighten permissions on the data directory and any existing DB files.
chmod 700 /app/data 2>/dev/null || true
find /app/data -type f -name '*.db*' -exec chmod 600 {} + 2>/dev/null || true

echo "Database initialized."

# Start gunicorn
exec gunicorn \
    --bind 0.0.0.0:5000 \
    --workers 2 \
    --timeout 120 \
    "app:create_app()"
