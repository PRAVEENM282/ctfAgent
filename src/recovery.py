"""Step-7 failure injection and FRESH retry coordination."""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class FailureClass(StrEnum):
    INFRASTRUCTURE = "infrastructure_transient"
    GENERATED_CODE = "generated_code_or_build_defect"
    VERIFIER = "verifier_or_challenge_defect"


class InjectedStep7Failure(RuntimeError):
    """A trusted control-plane-only Step-7 fault injection."""


@dataclass(frozen=True)
class RecoveryAttempt:
    run_id: str
    attempt_id: str
    parent_run_id: str
    batch_id: str
    retry_index: int
    source_revision: str
    spec_revision: str


@dataclass
class Step7FaultInjector:
    enabled: bool
    fired: bool = False

    @classmethod
    def from_environment(cls) -> Step7FaultInjector:
        value = os.environ.get("VULNFORGE_INJECT_STEP7_FAILURE", "")
        return cls(value.strip().lower() in {"1", "true", "yes", "on"})

    def before_verifier(self) -> None:
        if self.enabled and not self.fired:
            self.fired = True
            raise InjectedStep7Failure("control-plane Step-7 failure injection")


class FreshRetryCoordinator:
    def __init__(
        self,
        *,
        batch_id: str,
        parent_run_id: str,
        max_retries: int = 2,
        trace_writer: Callable[[dict[str, object]], None] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        if max_retries < 0 or max_retries > 2:
            raise ValueError("max_retries must be between 0 and 2")
        self.batch_id = batch_id
        self.parent_run_id = parent_run_id
        self.max_retries = max_retries
        self.trace_writer = trace_writer or (lambda _record: None)
        self.id_factory = id_factory or (lambda: f"run-{secrets.token_hex(6)}")

    async def run(
        self,
        run_attempt: Callable[[RecoveryAttempt], Awaitable[dict[str, object]]],
        *,
        source_revision: str,
        spec_revision: str,
        classify: Callable[[BaseException], FailureClass],
    ) -> dict[str, object]:
        current_source = source_revision
        for retry_index in range(self.max_retries + 1):
            run_id = self.id_factory()
            attempt = RecoveryAttempt(
                run_id=run_id,
                attempt_id=f"attempt-{secrets.token_hex(6)}",
                parent_run_id=self.parent_run_id,
                batch_id=self.batch_id,
                retry_index=retry_index,
                source_revision=current_source,
                spec_revision=spec_revision,
            )
            try:
                result = await run_attempt(attempt)
            except Exception as exc:
                failure_class = classify(exc)
                can_retry = retry_index < self.max_retries
                next_source = (
                    f"{source_revision}-rev{retry_index + 2}"
                    if failure_class in {FailureClass.GENERATED_CODE, FailureClass.VERIFIER}
                    else current_source
                )
                trace = {
                    "event": "step7_failure",
                    "batch_id": self.batch_id,
                    "parent_run_id": self.parent_run_id,
                    "run_id": run_id,
                    "attempt_id": attempt.attempt_id,
                    "sandbox_name": getattr(exc, "sandbox_name", None),
                    "failed_step": 7,
                    "fault_injected": isinstance(exc, InjectedStep7Failure),
                    "source_revision": attempt.source_revision,
                    "spec_revision": spec_revision,
                    "classification": failure_class.value,
                    "retry_decision": "fresh" if can_retry else "stop",
                    "new_source_revision": next_source if can_retry else None,
                    "final_outcome": "retrying" if can_retry else "failed",
                }
                self.trace_writer(trace)
                if not can_retry:
                    raise
                current_source = next_source
                continue
            sandbox_name = result.get("sandbox_name")
            self.trace_writer(
                {
                    "event": "policy_applied",
                    "policy": "fresh",
                    "batch_id": self.batch_id,
                    "parent_run_id": self.parent_run_id,
                    "run_id": run_id,
                    "attempt_id": attempt.attempt_id,
                    "sandbox_name": sandbox_name,
                    "failed_step": 7,
                    "fault_injected": False,
                    "source_revision": attempt.source_revision,
                    "spec_revision": spec_revision,
                    "classification": None,
                    "retry_decision": "none",
                    "final_outcome": str(result.get("outcome", "succeeded")),
                }
            )
            return result
        raise AssertionError("recovery loop exhausted without result")


def failure_policy_document() -> dict[str, object]:
    return {
        "failed_step": 7,
        "total_steps": 10,
        "policy": "fresh",
        "rationale": (
            "A failed Step-7 verifier attempt is preserved as its own ledger row and evidence "
            "snapshot, then the guest is deleted before a new guest is created. Resume is not "
            "used because a failed generated application may leave unknown processes or state. "
            "Infrastructure failures reuse the same source revision; generated-code or verifier "
            "defects require a new source revision. This keeps retries bounded, auditable, and "
            "separate from the successful learner pause/resume capability."
        ),
        "trace_path": "reports/failure_trace.jsonl",
    }


def write_failure_policy(path: Path) -> None:
    path.write_text(json.dumps(failure_policy_document(), indent=2) + "\n", encoding="utf-8")


def append_failure_trace(path: Path, record: dict[str, object]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
