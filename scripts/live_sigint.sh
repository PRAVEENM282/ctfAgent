#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(git rev-parse --show-toplevel)"; LOG="$ROOT/reports/evidence/live_sigint.log"; PROJECT="${COMPOSE_PROJECT_NAME:-ctfagent-cleanboot-20261022}"
redact(){ sed -E -e 's/(CELESTO_API_KEY|LLM_API_KEY|OPERATOR_TOKEN)=([^[:space:]]+)/\1=[REDACTED]/g' -e 's/Bearer[[:space:]]+[A-Za-z0-9._~+\/-]+/Bearer [REDACTED]/g' -e 's/VF\{[0-9a-fA-F]{32}\}/[REDACTED_FLAG]/g'; }
: >"$LOG"; docker compose -p "$PROJECT" exec -T api python scripts/reap_orphans.py 2>&1 | redact | tee -a "$LOG"
set +e
docker compose -p "$PROJECT" exec -T api python scripts/m3_live_lifecycle.py 2>&1 | redact | tee -a "$LOG" &
pid=$!
set -e
for _ in $(seq 1 180); do
  grep -q 'LIFECYCLE_ACTIVE waiting_for_sigint=true' "$LOG" && break
  sleep 1
done
if ! grep -q 'LIFECYCLE_ACTIVE waiting_for_sigint=true' "$LOG"; then
  kill "$pid" 2>/dev/null || true; wait "$pid" || true; echo 'SIGINT gate never became active' | tee -a "$LOG"; exit 1
fi
kill -INT "$pid"
wait "$pid"; rc=$?
[[ "$rc" -eq 0 ]] || { echo "SIGINT runner exit=$rc" | tee -a "$LOG"; exit "$rc"; }
