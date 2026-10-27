#!/usr/bin/env python3
"""Collect fresh Cloud reliability attempts with durable per-attempt evidence."""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.cloud_reliability_batch import run_one

EVIDENCE = ROOT / "reports" / "evidence"
ROWS_PATH = EVIDENCE / "realtime_reliability_rows_v2.json"
JSONL_PATH = EVIDENCE / "realtime_reliability_attempts_v2.jsonl"
ATTEMPTS_DIR = EVIDENCE / "reliability_attempts_v2"
TARGET_ATTEMPTS = 20


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def load_rows() -> list[dict[str, object]]:
    if not JSONL_PATH.is_file():
        return []
    rows: list[dict[str, object]] = []
    for line in JSONL_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def persist(rows: list[dict[str, object]], attempt_number: int, row: dict[str, object]) -> None:
    record = {
        "attempt_number": attempt_number,
        "started_at_utc": row.pop("_started_at_utc"),
        "finished_at_utc": utc_now(),
        "row": row,
        "evidence": {
            "command_audit": "logs/commands.jsonl",
            "attempt_record": (
                f"reports/evidence/reliability_attempts_v2/attempt-{attempt_number:02d}.json"
            ),
        },
    }
    with JSONL_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    ATTEMPTS_DIR.mkdir(parents=True, exist_ok=True)
    (ATTEMPTS_DIR / f"attempt-{attempt_number:02d}.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    rows.append(row)
    ROWS_PATH.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    rows = [record["row"] for record in load_rows()]
    if len(rows) >= TARGET_ATTEMPTS:
        print(json.dumps({"status": "already_complete", "attempts": len(rows)}))
        return 0

    for attempt_number in range(len(rows) + 1, TARGET_ATTEMPTS + 1):
        started_at = utc_now()
        row = run_one(attempt_number)
        row["_started_at_utc"] = started_at
        persist(rows, attempt_number, row)
        print(
            json.dumps(
                {
                    "attempt_number": attempt_number,
                    "sandbox_name": row["sandbox_name"],
                    "success": row["success"],
                    "provider_status": row["provider_status"],
                    "cleanup_confirmed": row["cleanup_confirmed"],
                },
                sort_keys=True,
            ),
            flush=True,
        )
        if row.get("provider_status") == 429 and attempt_number < TARGET_ATTEMPTS:
            time.sleep(65)

    manifest = {
        "collected_at_utc": utc_now(),
        "target_attempts": TARGET_ATTEMPTS,
        "attempt_count": len(rows),
        "successful_attempts": sum(bool(row["success"]) for row in rows),
        "evidence_rows": "reports/evidence/realtime_reliability_rows_v2.json",
        "evidence_jsonl": "reports/evidence/realtime_reliability_attempts_v2.jsonl",
        "per_attempt_evidence": "reports/evidence/reliability_attempts_v2/",
        "command_audit": "logs/commands.jsonl",
        "model_mode": "deterministic_test_policy",
        "execution_scope": "real_cloud_guest_benign_command",
    }
    (EVIDENCE / "realtime_reliability_manifest_v2.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
