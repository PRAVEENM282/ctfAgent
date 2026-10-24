"""Run one injected Step-7 FRESH recovery flow when live gates exist."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_m6 import run_once
from src.agent.provider import ProviderTransportError
from src.ledger.repository import LedgerUnavailable, LlmBudgetExceeded, RunRepository
from src.recovery import (
    FailureClass,
    FreshRetryCoordinator,
    Step7FaultInjector,
    append_failure_trace,
    write_failure_policy,
)


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value or value.startswith("replace-"):
        raise RuntimeError(f"{name} is not configured")
    return value


def _classify(exc: BaseException) -> FailureClass:
    if isinstance(exc, (ProviderTransportError, TimeoutError, ConnectionError, LedgerUnavailable)):
        return FailureClass.INFRASTRUCTURE
    return FailureClass.VERIFIER


async def run_recovery(trace_path: Path, policy_path: Path) -> dict[str, object]:
    if os.environ.get("VULNFORGE_INJECT_STEP7_FAILURE", "").lower() not in {"1", "true", "yes", "on"}:
        raise RuntimeError("set VULNFORGE_INJECT_STEP7_FAILURE=1 in trusted control-plane configuration")
    repository = RunRepository(_required("DATABASE_URL"))
    await repository.check_health()
    await repository.migrate_runtime_schema()
    model = _required("LLM_MODEL")
    await repository.preflight_llm_batch(
        provider="groq",
        model=model,
        attempt_count=3,
        max_http_attempts=int(os.getenv("LLM_MAX_HTTP_ATTEMPTS", "8")),
        token_budget=int(os.getenv("VULNFORGE_TOKEN_BUDGET", "8000")),
        daily_request_limit=int(os.getenv("LLM_DAILY_REQUEST_LIMIT", "1000")),
        daily_token_limit=int(os.getenv("LLM_DAILY_TOKEN_LIMIT", "200000")),
    )
    coordinator = FreshRetryCoordinator(
        batch_id=f"batch-{os.urandom(6).hex()}",
        parent_run_id=f"run-{os.urandom(6).hex()}",
        max_retries=int(os.getenv("VULNFORGE_MAX_RETRIES", "2")),
        trace_writer=lambda record: append_failure_trace(trace_path, record),
    )
    injector = Step7FaultInjector.from_environment()
    result = await coordinator.run(
        lambda attempt: run_once(attempt, injector),
        source_revision="source-r1",
        spec_revision="spec-r1",
        classify=_classify,
    )
    write_failure_policy(policy_path)
    return {
        "outcome": result.get("outcome", "succeeded"),
        "sandbox_name": result.get("sandbox_name"),
        "trace_path": str(trace_path),
        "policy_path": str(policy_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace-path", type=Path, default=ROOT / "reports" / "failure_trace.jsonl")
    parser.add_argument("--policy-path", type=Path, default=ROOT / "reports" / "failure_policy.json")
    args = parser.parse_args()
    try:
        args.trace_path.parent.mkdir(parents=True, exist_ok=True)
        result = asyncio.run(run_recovery(args.trace_path, args.policy_path))
        print(result)
        return 0
    except (LlmBudgetExceeded, LedgerUnavailable, RuntimeError, ValueError) as exc:
        frames = traceback.extract_tb(exc.__traceback__)
        frame = frames[-1] if frames else None
        location = f"{frame.filename}:{frame.lineno}" if frame else "unavailable"
        print(f"M8 blocked/failed error={type(exc).__name__}: {exc} last_frame={location}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
