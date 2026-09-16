#!/usr/bin/env bash
#
# seed_demo.sh — create or remove chancery demo data by running the Python
# seeder (seed_demo.py) INSIDE the running container.
#
# Why not pure curl?  The container image ships only python3 (no curl/jq/sqlite3),
# and the app exposes no delete endpoint — so "remove" is impossible over the HTTP
# API. The seeder talks to the DB through the app itself, which can both create
# AND remove, needs no admin password, and no extra packages.
#
#   ./scripts/seed_demo.sh            # create demo CAs, certificates, CSRs
#   ./scripts/seed_demo.sh --remove   # delete everything it created
#   ./scripts/seed_demo.sh --reset    # remove, then recreate
#   ./scripts/seed_demo.sh --remove --force   # also delete real CAs chained under a demo CA
#
#   CONTAINER=my-app ./scripts/seed_demo.sh    # target a different container
#                                              # (default: chancery-app-1)
#
# Everything it creates is tagged ("Demo " CA names, *.demo.example.com CNs);
# --remove deletes only those and never touches real data.
set -euo pipefail

CONTAINER="${CONTAINER:-chancery-app-1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v docker >/dev/null || { echo "docker not found on PATH." >&2; exit 1; }
docker inspect -f '{{.State.Running}}' "$CONTAINER" >/dev/null 2>&1 \
  || { echo "Container '$CONTAINER' is not running (set CONTAINER=<name>)." >&2; exit 1; }

# Copy the seeder in, run it as the app user with /app importable, clean up.
docker cp "$HERE/seed_demo.py" "$CONTAINER:/tmp/seed_demo.py"
trap 'docker exec "$CONTAINER" rm -f /tmp/seed_demo.py 2>/dev/null || true' EXIT
docker exec -u 1000 -e PYTHONPATH=/app "$CONTAINER" python3 /tmp/seed_demo.py "$@"
