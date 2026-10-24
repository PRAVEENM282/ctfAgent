#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(git rev-parse --show-toplevel)"
LOG="$ROOT/reports/evidence/live_batch.log"
PROJECT="${COMPOSE_PROJECT_NAME:-ctfagent-cleanboot-20261022}"
ACCOUNT_LIMIT_VERIFIED="${VULNFORGE_ACCOUNT_LIMIT_VERIFIED:-0}"
redact(){ sed -E -e 's/(CELESTO_API_KEY|LLM_API_KEY|OPERATOR_TOKEN)=([^[:space:]]+)/\1=[REDACTED]/g' -e 's/Bearer[[:space:]]+[A-Za-z0-9._~+\/-]+/Bearer [REDACTED]/g' -e 's/VF\{[0-9a-fA-F]{32}\}/[REDACTED_FLAG]/g'; }
run_logged(){
  set +e
  "$@" 2>&1 | redact | tee -a "$LOG"
  local rc=${PIPESTATUS[0]}
  set -e
  return "$rc"
}
: >"$LOG"
printf '%s\n' "live batch started $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$LOG"
if [[ "$ACCOUNT_LIMIT_VERIFIED" != "1" ]]; then
  printf '%s\n' 'VULNFORGE_ACCOUNT_LIMIT_VERIFIED=1 must be exported only after account-specific limits are verified' | tee -a "$LOG"
  exit 2
fi
run_logged docker compose -p "$PROJECT" exec -T api python scripts/reap_orphans.py
run_logged docker compose -p "$PROJECT" exec -T -e VULNFORGE_ACCOUNT_LIMIT_VERIFIED="$ACCOUNT_LIMIT_VERIFIED" api python scripts/run_evaluation.py --attempts 20
run_logged docker compose -p "$PROJECT" exec -T -e VULNFORGE_ACCOUNT_LIMIT_VERIFIED="$ACCOUNT_LIMIT_VERIFIED" -e VULNFORGE_APPROVAL_MODE=pre_approved api python scripts/run_evaluation.py --attempts 20 --execute
run_logged "$ROOT/scripts/export_reports.sh"
