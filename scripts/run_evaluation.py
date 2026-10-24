"""Run the sequential clean evaluation only when all real gates are available."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_m6 import run_once
from src.ledger.repository import LedgerUnavailable, LlmBudgetExceeded, RunRepository


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value or value.startswith("replace-"):
        raise RuntimeError(f"{name} is not configured")
    return value


async def preflight(attempts: int) -> dict[str, object]:
    if attempts < 1:
        raise ValueError("attempts must be positive")
    database_url = _required("DATABASE_URL")
    model = _required("LLM_MODEL")
    repository = RunRepository(database_url)
    await repository.check_health()
    await repository.migrate_runtime_schema()
    result = await repository.preflight_llm_batch(
        provider="groq",
        model=model,
        attempt_count=attempts,
        max_http_attempts=int(os.getenv("LLM_MAX_HTTP_ATTEMPTS", "8")),
        token_budget=int(os.getenv("VULNFORGE_TOKEN_BUDGET", "8000")),
        daily_request_limit=int(os.getenv("LLM_DAILY_REQUEST_LIMIT", "1000")),
        daily_token_limit=int(os.getenv("LLM_DAILY_TOKEN_LIMIT", "200000")),
    )
    verified = os.getenv("VULNFORGE_ACCOUNT_LIMIT_VERIFIED", "0") == "1"
    result["account_specific_limit_verified"] = verified
    result["status"] = "ready" if verified else "blocked_until_account_limit_verified"
    if not verified:
        raise RuntimeError(
            "account-specific provider limits are unknown; set VULNFORGE_ACCOUNT_LIMIT_VERIFIED=1 only after measuring the provider account"
        )
    return result


async def execute_batch(attempts: int) -> dict[str, object]:
    if os.getenv("VULNFORGE_APPROVAL_MODE", "interactive").strip().lower() != "pre_approved":
        raise RuntimeError(
            "batch execution requires VULNFORGE_APPROVAL_MODE=pre_approved; interactive publication approvals would block the batch"
        )
    preflight_result = await preflight(attempts)
    repository = RunRepository()
    rows: list[dict[str, object]] = []
    for index in range(attempts):
        os.environ["VULNFORGE_VARIATION_SEED"] = f"batch-{index + 1}-{secrets.token_hex(4)}"
        try:
            await run_once()
        except Exception as exc:  # noqa: BLE001 - preserve failed rows and continue the batch.
            print(f"BATCH_ATTEMPT_FAILED index={index + 1} error_type={type(exc).__name__}")
        current = await repository.list_runs()
        candidates = [row for row in current if str(row.get("variation_seed") or "").startswith("batch-")]
        if candidates:
            row = candidates[-1]
            if any(row.get(field) is None for field in ("wall_clock_s", "boot_to_ready_s")):
                continue
            row["fresh"] = True
            row["success"] = row.get("state") == "deleted" and row.get("error_code") is None
            row["cost_usd"] = float(row.get("total_cost_usd") or 0)
            rows.append(row)
    if len(rows) >= 20:
        from src.evaluation import summarize_runs
        report = summarize_runs(rows)
        (ROOT / "reports" / "reliability.json").write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    else:
        partial = {"attempts_requested": attempts, "attempts_recorded": len(rows), "preflight": preflight_result, "runs": rows}
        (ROOT / "reports" / "reliability_partial.json").write_text(json.dumps(partial, indent=2, default=str) + "\n", encoding="utf-8")
    return {"attempts_requested": attempts, "attempts_recorded": len(rows), "preflight": preflight_result}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts", type=int, default=20)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(execute_batch(args.attempts) if args.execute else preflight(args.attempts))
        if result is not None:
            print(json.dumps(result, default=str))
    except (LlmBudgetExceeded, LedgerUnavailable, RuntimeError, ValueError) as exc:
        frames = traceback.extract_tb(exc.__traceback__)
        frame = frames[-1] if frames else None
        location = f"{frame.filename}:{frame.lineno}" if frame else "unavailable"
        print(
            f"M9 blocked step=account_preflight error={type(exc).__name__}: {exc} last_frame={location}",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
