#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(git rev-parse --show-toplevel)"; LOG="$ROOT/reports/evidence/live_lifecycle.log"; PROJECT="${COMPOSE_PROJECT_NAME:-ctfagent-cleanboot-20261022}"
redact(){ sed -E -e 's/(CELESTO_API_KEY|LLM_API_KEY|OPERATOR_TOKEN)=([^[:space:]]+)/\1=[REDACTED]/g' -e 's/Bearer[[:space:]]+[A-Za-z0-9._~+\/-]+/Bearer [REDACTED]/g' -e 's/VF\{[0-9a-fA-F]{32}\}/[REDACTED_FLAG]/g'; }
: >"$LOG"; { date -u +%Y-%m-%dT%H:%M:%SZ; docker compose -p "$PROJECT" exec -T api python scripts/reap_orphans.py; docker compose -p "$PROJECT" exec -T api python scripts/m3_live_lifecycle.py; } 2>&1 | redact | tee "$LOG"
