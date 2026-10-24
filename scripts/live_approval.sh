#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
PROJECT="${COMPOSE_PROJECT_NAME:-ctfagent-cleanboot-20261022}"
LOG="$ROOT/reports/evidence/live_approval.log"
BASE_URL="${APPROVAL_API_BASE_URL:-http://127.0.0.1:8080}"
TMP_DIR="$(mktemp -d /tmp/vulnforge-approval.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

redact() {
  sed -E \
    -e 's/(CELESTO_API_KEY|LLM_API_KEY|OPERATOR_TOKEN)=([^[:space:]]+)/\1=[REDACTED]/g' \
    -e 's/(Bearer )[A-Za-z0-9._~+\/-]+/\1[REDACTED]/g' \
    -e 's/VF\{[0-9a-fA-F]{32}\}/[REDACTED_FLAG]/g' \
    -e 's/approval-[a-z0-9]{16,}/[REDACTED_APPROVAL_ID]/g'
}

run_case() {
  local label="$1"
  local decision="$2"
  local expected_rc="$3"
  local raw="$TMP_DIR/$label.log"
  : >"$raw"
  docker compose -p "$PROJECT" exec -T -e VULNFORGE_APPROVAL_MODE=interactive api \
    python scripts/run_m6.py >"$raw" 2>&1 &
  local pid=$!
  local approval_id=""
  for _ in $(seq 1 900); do
    approval_id="$(python - "$raw" <<'PYINNER'
from pathlib import Path
import re
import sys
match = re.search(r"APPROVAL_REQUIRED approval_id=([^ ]+)", Path(sys.argv[1]).read_text(errors="ignore"))
print(match.group(1) if match else "")
PYINNER
)"
    [[ -n "$approval_id" ]] && break
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  if [[ -z "$approval_id" ]]; then
    wait "$pid" || true
    redact <"$raw" | tee -a "$LOG"
    printf 'FAIL approval_case=%s reason=approval_request_not_observed\n' "$label" | tee -a "$LOG"
    return 1
  fi
  printf 'APPROVAL_CASE label=%s decision=%s approval_id=[REDACTED_APPROVAL_ID]\n' "$label" "$decision" | tee -a "$LOG"
  OPERATOR_TOKEN="${OPERATOR_TOKEN:?OPERATOR_TOKEN must be exported in the terminal}" \
    python scripts/approve_publication.py "$approval_id" --decision "$decision" \
      --decided-by "ask-gate-3-$label" --base-url "$BASE_URL" 2>&1 | redact | tee -a "$LOG"
  set +e
  wait "$pid"
  local rc=$?
  set -e
  redact <"$raw" | tee -a "$LOG"
  if [[ "$rc" -ne "$expected_rc" ]]; then
    printf 'FAIL approval_case=%s expected_rc=%s actual_rc=%s\n' "$label" "$expected_rc" "$rc" | tee -a "$LOG"
    return 1
  fi
  if [[ "$decision" == approved ]] && ! grep -q "final_state.*deleted" "$raw"; then
    printf 'FAIL approval_case=%s missing_deleted_final_state\n' "$label" | tee -a "$LOG"
    return 1
  fi
  if [[ "$decision" == denied ]] && ! grep -q "ApprovalRequired" "$raw"; then
    printf 'FAIL approval_case=%s missing_approval_required_failure\n' "$label" | tee -a "$LOG"
    return 1
  fi
  printf 'PASS approval_case=%s\n' "$label" | tee -a "$LOG"
}

: >"$LOG"
printf '%s\n' "live approval gate started $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$LOG"
docker compose -p "$PROJECT" exec -T api python scripts/reap_orphans.py 2>&1 | redact | tee -a "$LOG"
run_case approved approved 0
run_case denied denied 2
printf '%s\n' 'PASS live approval approve-and-deny cases' | tee -a "$LOG"
