#!/bin/sh
# Root phase (H1): the ONLY thing done as root is claiming ownership of the
# bind-mounted data volume for the non-root 'app' user (uid 1000). Everything
# else — token init, DB migration, gunicorn — runs unprivileged via entrypoint-app.sh.
set -e

APP_UID=1000

# Hand the data volume (which a fresh bind mount creates root-owned) to the app
# user so the unprivileged phase can read/write it. Needs only CAP_CHOWN; the
# app phase (as owner) sets the 700/600 modes.
mkdir -p /app/data
chown -R "${APP_UID}:${APP_UID}" /app/data 2>/dev/null || true

# gunicorn's control socket lives under $HOME; point it at the app user's home.
export HOME=/home/app

# Drop to the non-root user (needs CAP_SETUID/SETGID) and run the app.
# su-exec (Alpine) replaces util-linux setpriv: it setgroups/setgid/setuid's to
# the target user then execs, leaving no privileged parent process.
exec su-exec "${APP_UID}:${APP_UID}" /app/entrypoint-app.sh
