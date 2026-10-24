#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(git rev-parse --show-toplevel)"
LOG="$ROOT/reports/evidence/fresh_checkout_boot.log"
TMP="$(mktemp -d /tmp/vulnforge-fresh.XXXXXX)"
CLONE="$TMP/repo"
PROJECT="vf-fresh-$(date +%s)"
PORT="${VULNFORGE_FRESH_PORT:-18081}"
BASE="http://127.0.0.1:${PORT}"
STARTED=0

redact() {
  sed -E \
    -e 's/(CELESTO_API_KEY|LLM_API_KEY|OPERATOR_TOKEN)=([^[:space:]]+)/\1=[REDACTED]/g' \
    -e 's/(Bearer )[A-Za-z0-9._~+\/-]+/\1[REDACTED]/g' \
    -e 's/VF\{[0-9a-fA-F]{32}\}/[REDACTED_FLAG]/g'
}

log() { printf '%s\n' "$*" | redact | tee -a "$LOG"; }
run() {
  log "+ $*"
  set +e
  "$@" 2>&1 | redact | tee -a "$LOG"
  local rc=${PIPESTATUS[0]}
  set -e
  if [[ $rc -ne 0 ]]; then
    log "FAIL rc=$rc command=$1"
    exit "$rc"
  fi
}
check() {
  local label=$1
  shift
  log "CHECK $label"
  set +e
  "$@" >/tmp/vf-check.out 2>&1
  local rc=$?
  redact </tmp/vf-check.out | tee -a "$LOG"
  set -e
  if [[ $rc -ne 0 ]]; then
    log "FAIL check=$label rc=$rc"
    exit "$rc"
  fi
  log "PASS check=$label"
}

cleanup() {
  if [[ "$STARTED" == 1 ]]; then
    docker compose --project-directory "$CLONE" -p "$PROJECT" --env-file "$CLONE/.env.example" down -v --remove-orphans 2>&1 | redact | tee -a "$LOG" || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]]; then
  printf '%s\n' 'FAIL fresh-clone audit requires a clean committed worktree; refusing to test a stale HEAD snapshot' >&2
  exit 2
fi
: >"$LOG"
log "VulnForge fresh-clone boot audit started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
run git clone --no-hardlinks "$ROOT" "$CLONE"
run git -C "$CLONE" status --short --branch
run docker compose --project-directory "$CLONE" -p "$PROJECT" --env-file "$CLONE/.env.example" down -v --remove-orphans
start_time=$(date +%s)
run env API_PORT="$PORT" docker compose --project-directory "$CLONE" -p "$PROJECT" --env-file "$CLONE/.env.example" up --build --wait -d
STARTED=1
elapsed=$(( $(date +%s) - start_time ))
log "compose_elapsed_seconds=$elapsed"
if (( elapsed >= 300 )); then log "FAIL compose exceeded 300 seconds"; exit 1; fi

check health curl --fail --silent --show-error "$BASE/health"
check health_db curl --fail --silent --show-error "$BASE/health/db"
check seed curl --fail --silent --show-error "$BASE/api/runs"
curl --fail --silent --show-error "$BASE/api/runs" | python3 -c 'import json,sys; rows=json.load(sys.stdin); assert any(row.get("sandbox_name")=="sbx-seeddemo1" for row in rows)' 2>&1 | tee -a "$LOG"

run_id="run-audit$(date +%s%N | tr -cd 'a-z0-9' | cut -c1-20)"
sandbox="sbx-audit$(date +%s%N | tr -cd 'a-z0-9' | cut -c1-16)"
body=$(python3 -c 'import json,sys; print(json.dumps({"run_id":sys.argv[1],"sandbox_name":sys.argv[2],"problem_id":"audit-fresh-boot","state":"created","execution_target":"celesto_sandbox"}))' "$run_id" "$sandbox")
status=$(curl --silent --show-error -o /tmp/vf-post.out -w '%{http_code}' -H 'Content-Type: application/json' -d "$body" "$BASE/api/runs")
cat /tmp/vf-post.out | redact | tee -a "$LOG"
[[ "$status" == 201 ]] || { log "FAIL valid POST status=$status"; exit 1; }
for case in duplicate host_target bad_state bad_sandbox bad_run_id; do
  case "$case" in
    duplicate) payload="$body";;
    host_target) payload=$(python3 -c 'import json,sys; x=json.loads(sys.argv[1]); x["run_id"]="run-hosttarget0001"; x["sandbox_name"]="sbx-hosttarget"; x["execution_target"]="host"; print(json.dumps(x))' "$body");;
    bad_state) payload=$(python3 -c 'import json,sys; x=json.loads(sys.argv[1]); x["run_id"]="run-badstate00001"; x["sandbox_name"]="sbx-badstate"; x["state"]="unknown"; print(json.dumps(x))' "$body");;
    bad_sandbox) payload=$(python3 -c 'import json,sys; x=json.loads(sys.argv[1]); x["run_id"]="run-badsandbox01"; x["sandbox_name"]="bad"; print(json.dumps(x))' "$body");;
    bad_run_id) payload=$(python3 -c 'import json,sys; x=json.loads(sys.argv[1]); x["run_id"]="bad"; x["sandbox_name"]="sbx-bad-run-id"; print(json.dumps(x))' "$body");;
  esac
  status=$(curl --silent --show-error -o /tmp/vf-post.out -w '%{http_code}' -H 'Content-Type: application/json' -d "$payload" "$BASE/api/runs")
  cat /tmp/vf-post.out | redact | tee -a "$LOG"
  [[ "$status" == 400 ]] || { log "FAIL $case status=$status"; exit 1; }
done

for pass in 1 2; do
  for seed in "$CLONE"/seeds/*.sql; do
    file=$(basename "$seed")
    run docker compose --project-directory "$CLONE" -p "$PROJECT" --env-file "$CLONE/.env.example" exec -T ledger psql -U ledger -d ledger -v ON_ERROR_STOP=1 -f "/docker-entrypoint-initdb.d/$file"
  done
done
count=$(docker compose --project-directory "$CLONE" -p "$PROJECT" --env-file "$CLONE/.env.example" exec -T ledger psql -U ledger -d ledger -Atqc 'SELECT count(*) FROM runs WHERE sandbox_name = '\''sbx-seeddemo1'\'';')
log "seed_row_count=$count"
[[ "$count" == 1 ]] || { log "FAIL seed row count"; exit 1; }

run docker compose --project-directory "$CLONE" -p "$PROJECT" --env-file "$CLONE/.env.example" stop ledger
status=$(curl --silent --show-error -o /tmp/vf-health.out -w '%{http_code}' "$BASE/health")
cat /tmp/vf-health.out | redact | tee -a "$LOG"
[[ "$status" == 200 ]] || { log "FAIL /health during DB outage status=$status"; exit 1; }
status=$(curl --silent --show-error -o /tmp/vf-health-db.out -w '%{http_code}' "$BASE/health/db")
cat /tmp/vf-health-db.out | redact | tee -a "$LOG"
[[ "$status" == 503 ]] || { log "FAIL /health/db during DB outage status=$status"; exit 1; }
run docker compose --project-directory "$CLONE" -p "$PROJECT" --env-file "$CLONE/.env.example" start ledger
for _ in $(seq 1 30); do
  if curl --silent --fail "$BASE/health/db" >/dev/null; then break; fi
  sleep 2
done
check health_db_recovered curl --fail --silent --show-error "$BASE/health/db"

status=$(curl --path-as-is --silent --show-error -o /tmp/vf-report.out -w '%{http_code}' "$BASE/reports/%2e%2e/.env")
cat /tmp/vf-report.out | redact | tee -a "$LOG"
[[ "$status" == 404 ]] || { log "FAIL traversal status=$status"; exit 1; }
check report curl --fail --silent --show-error "$BASE/reports/containment.json"
run docker compose --project-directory "$CLONE" -p "$PROJECT" --env-file "$CLONE/.env.example" exec -T api python scripts/test_reports_mount.py
run docker compose --project-directory "$CLONE" -p "$PROJECT" --env-file "$CLONE/.env.example" exec -T api python -m pytest -q -rs tests/test_ledger_integration.py tests/test_llm_budget_integration.py
run docker compose --project-directory "$CLONE" -p "$PROJECT" --env-file "$CLONE/.env.example" exec -T api python -m pytest -q -rs tests/test_report_serving_safety.py
run docker compose --project-directory "$CLONE" -p "$PROJECT" --env-file "$CLONE/.env.example" exec -T api python -m pytest -q -rs
log "PASS fresh-clone boot audit completed"
