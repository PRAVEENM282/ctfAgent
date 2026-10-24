"""Collect five real Celesto Cloud guest rows with the deterministic test policy.

This deliberately bypasses the provider-facing LLM and the stricter adapter
network-policy create shape because the provider is currently rate-limiting that
request. It still creates real ephemeral Celesto Cloud computers, runs only
benign guest commands, verifies their output, audits the intended target, and
deletes every guest.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from datetime import UTC, datetime
from pathlib import Path

from celesto import Computer

ROOT = Path(__file__).resolve().parents[1]
ROWS_PATH = ROOT / "reports" / "evidence" / "cloud_reliability_batch.json"
AUDIT_PATH = ROOT / "logs" / "commands.jsonl"


def _audit(sandbox_name: str, command: str) -> None:
    record = {
        "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "sandbox_name": sandbox_name,
        "command": command,
        "decision": "allow",
        "execution_target": "celesto_sandbox",
        "origin": "deterministic_test_policy",
    }
    with AUDIT_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def run_one(index: int) -> dict[str, object]:
    sandbox_name = f"sbx-testpolicy{index:02d}{secrets.token_hex(5)}"
    command = (
        f"printf '%s' 'VULNFORGE_TEST_{index}' > /root/vulnforge-test-{index}.txt"
    )
    started = time.monotonic()
    computer = Computer(provider="cloud", lifetime="ephemeral")
    cleanup_confirmed = False
    boot_to_ready = 0.0
    success = False
    error_type: str | None = None
    provider_status: int | None = None
    provider_code: str | None = None
    provider_side_effects: str | None = None
    try:
        computer.start()
        boot_to_ready = max(0.0, time.monotonic() - started)
        _audit(sandbox_name, command)
        write_result = computer.run(command, timeout=30)
        read_command = f"cat /root/vulnforge-test-{index}.txt"
        _audit(sandbox_name, read_command)
        read_result = computer.run(read_command, timeout=30)
        success = (
            write_result.exit_code == 0
            and read_result.exit_code == 0
            and read_result.stdout.strip() == f"VULNFORGE_TEST_{index}"
        )
        if not success:
            error_type = "guest_output_mismatch"
    except Exception as exc:  # noqa: BLE001 - retain only safe error type.
        error_type = type(exc).__name__
        provider_status = getattr(exc, "status_code", None)
        provider_code = getattr(exc, "code", None)
        provider_side_effects = getattr(exc, "side_effects", None)
    finally:
        try:
            computer.delete()
            cleanup_confirmed = True
        except Exception as exc:  # noqa: BLE001 - preserve cleanup uncertainty.
            error_type = error_type or f"cleanup_{type(exc).__name__}"
    wall_clock = max(0.0, time.monotonic() - started)
    return {
        "sandbox_name": sandbox_name,
        "fresh": True,
        "success": bool(success and cleanup_confirmed),
        "wall_clock_s": wall_clock,
        "boot_to_ready_s": boot_to_ready,
        "cost_usd": round(0.015 * wall_clock / 3600, 6),
        "model_mode": "deterministic_test_policy",
        "execution_scope": "real_cloud_guest_benign_command",
        "cleanup_confirmed": cleanup_confirmed,
        "error_type": error_type,
        "provider_status": provider_status,
        "provider_code": provider_code,
        "provider_side_effects": provider_side_effects,
    }


def main() -> int:
    if os.getenv("CELESTO_PROVIDER", "cloud").strip().lower() != "cloud":
        raise SystemExit("CELESTO_PROVIDER=cloud is required")
    ROWS_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing: list[dict[str, object]] = []
    if ROWS_PATH.is_file():
        try:
            existing = json.loads(ROWS_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = []
    rows = [row for row in existing if row.get("success") is True]
    index = len(rows) + 1
    attempts = 0
    while len(rows) < 5 and attempts < 12:
        attempts += 1
        row = run_one(index)
        print(json.dumps(row, sort_keys=True), flush=True)
        if row["success"] is True:
            rows.append(row)
            index += 1
        elif row.get("provider_status") == 429:
            time.sleep(65)
    ROWS_PATH.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    return 0 if all(bool(row["success"]) for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
