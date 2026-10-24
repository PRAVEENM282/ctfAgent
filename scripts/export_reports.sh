#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(git rev-parse --show-toplevel)"
PROJECT="${COMPOSE_PROJECT_NAME:-ctfagent-cleanboot-20261022}"
DEST="$ROOT/reports"

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  else
    docker-compose "$@"
  fi
}

container_id="$(compose -p "$PROJECT" ps -q api)"
if [[ -z "$container_id" ]]; then
  printf '%s\n' "No running api container for project=$PROJECT" >&2
  exit 1
fi

mkdir -p "$DEST"
docker cp "$container_id:/app/reports/." "$DEST/"
printf 'reports_export=pass project=%s destination=reports\n' "$PROJECT"
