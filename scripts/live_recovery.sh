#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(git rev-parse --show-toplevel)"
LOG="$ROOT/reports/evidence/live_recovery.log"
PROJECT="${COMPOSE_PROJECT_NAME:-ctfagent-cleanboot-20261022}"
redact(){ sed -E -e 's/(CELESTO_API_KEY|LLM_API_KEY|OPERATOR_TOKEN)=([^[:space:]]+)/\1=[REDACTED]/g' -e 's/(Bearer )[A-Za-z0-9._~+\/-]+/\1[REDACTED]/g' -e 's/VF\{[0-9a-fA-F]{32}\}/[REDACTED_FLAG]/g' -e 's/approval-[a-z0-9]{16,}/[REDACTED_APPROVAL_ID]/g'; }
run_logged(){
  set +e
  "$@" 2>&1 | redact | tee -a "$LOG"
  local rc=${PIPESTATUS[0]}
  set -e
  return "$rc"
}
: >"$LOG"
printf '%s\n' "live recovery started $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$LOG"
run_logged docker compose -p "$PROJECT" exec -T api python scripts/reap_orphans.py
set +e
docker compose -p "$PROJECT" exec -T -e VULNFORGE_INJECT_STEP7_FAILURE=1 -e VULNFORGE_APPROVAL_MODE=pre_approved api python scripts/run_recovery.py 2>&1 | redact | tee -a "$LOG"
recovery_rc=${PIPESTATUS[0]}
set -e
set +e
"$ROOT/scripts/export_reports.sh" 2>&1 | redact | tee -a "$LOG"
export_rc=${PIPESTATUS[0]}
set -e
if [[ "$recovery_rc" -ne 0 ]]; then exit "$recovery_rc"; fi
exit "$export_rc"
