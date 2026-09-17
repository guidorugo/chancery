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
#   ./scripts/seed_demo.sh                    # create demo CAs, certificates, CSRs
#   ./scripts/seed_demo.sh --remove           # delete everything it created
#   ./scripts/seed_demo.sh --remove --force   # also delete real CAs chained under a demo CA
#   ./scripts/seed_demo.sh --reset            # remove, then recreate
#
# The container is found through the compose project this checkout belongs to
# (`docker compose ps app` next to docker-compose.yml), so the project name —
# chancery-app-1, cert-manager-app-1, … — does not matter. Override with
#   CONTAINER=<name-or-id> ./scripts/seed_demo.sh
#
# Everything it creates is tagged ("Demo " CA names, *.demo.example.com CNs);
# --remove deletes only those (plus what a demo CA issued) and never touches
# real data.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$HERE/.." && pwd)"

usage() {
  sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

command -v docker >/dev/null || { echo "docker not found on PATH." >&2; exit 1; }

# 1. explicit CONTAINER; 2. the compose project in this checkout; 3. the default name.
if [[ -z "${CONTAINER:-}" ]]; then
  CONTAINER="$(cd "$PROJECT_DIR" && docker compose ps -q app 2>/dev/null | head -n1 || true)"
fi
if [[ -z "${CONTAINER:-}" ]]; then
  CONTAINER=chancery-app-1
fi
if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
  echo "No running app container found (tried CONTAINER='${CONTAINER}')." >&2
  echo "Start it with 'docker compose up -d' in $PROJECT_DIR, or pass CONTAINER=<name-or-id>" >&2
  echo "(e.g. the 'app' service of your compose project: $(cd "$PROJECT_DIR" && docker compose ps --format '{{.Name}}' app 2>/dev/null | head -n1 || echo '?'))." >&2
  exit 1
fi
NAME="$(docker inspect -f '{{.Name}}' "$CONTAINER" | sed 's#^/##')"

# Copy the seeder in, run it as the app user with /app importable, clean up.
docker cp "$HERE/seed_demo.py" "$CONTAINER:/tmp/seed_demo.py"
trap 'docker exec "$CONTAINER" rm -f /tmp/seed_demo.py 2>/dev/null || true' EXIT
echo "Using container $NAME"
docker exec -u 1000 -e PYTHONPATH=/app "$CONTAINER" python3 /tmp/seed_demo.py "$@"
