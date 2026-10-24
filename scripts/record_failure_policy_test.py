"""Exercise the Step-7 recovery policy without contacting a model provider."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.recovery import (
    FailureClass,
    FreshRetryCoordinator,
    InjectedStep7Failure,
    RecoveryAttempt,
    failure_policy_document,
)


def run() -> int:
    trace_path = ROOT / "reports" / "failure_trace.jsonl"
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    trace_path.write_text("", encoding="utf-8")

    def write(record: dict[str, object]) -> None:
        with trace_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    ids = iter(("run-recovery0001", "run-recovery0002"))
    attempts = iter(("sbx-recovery01", "sbx-recovery02"))

    async def attempt(_attempt: RecoveryAttempt) -> dict[str, object]:
        sandbox_name = next(attempts)
        if sandbox_name.endswith("01"):
            error = InjectedStep7Failure("test-only Step-7 failure")
            error.sandbox_name = sandbox_name
            raise error
        return {"sandbox_name": sandbox_name, "outcome": "succeeded"}

    async def execute() -> dict[str, object]:
        coordinator = FreshRetryCoordinator(
            batch_id="batch-recovery01",
            parent_run_id="run-recovery0001",
            max_retries=1,
            trace_writer=write,
            id_factory=lambda: next(ids),
        )
        return await coordinator.run(
            attempt,
            source_revision="source-r1",
            spec_revision="spec-r1",
            classify=lambda _exc: FailureClass.VERIFIER,
        )

    result = asyncio.run(execute())
    policy_path = ROOT / "reports" / "failure_policy.json"
    policy_path.write_text(json.dumps(failure_policy_document(), indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": result, "trace_path": str(trace_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
