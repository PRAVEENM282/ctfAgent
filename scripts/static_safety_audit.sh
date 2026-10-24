#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
fail=0
check_no_match() {
  local pattern=$1
  if grep -RInE "$pattern" src scripts --exclude-dir='__pycache__'; then
    echo "FAIL forbidden pattern: $pattern"; fail=1
  else
    echo "PASS no forbidden pattern: $pattern"
  fi
}
check_no_match 'os\.system|(^|[^[:alnum:]_])eval\(|(^|[^[:alnum:]_])exec\('
python scripts/check_env_example.py || fail=1
python scripts/secret_scan.py || fail=1
if [[ -e logs/commands.jsonl ]]; then
  echo "PASS command audit path is present"
else
  echo "INFO command audit path will be created on first dispatch"
fi
python -m pytest -q tests/test_command_guard.py tests/test_celesto_adapter.py tests/test_verification.py || fail=1
exit "$fail"
