from __future__ import annotations

import asyncio

import pytest

from src.recovery import (
    FailureClass,
    FreshRetryCoordinator,
    InjectedStep7Failure,
    Step7FaultInjector,
    failure_policy_document,
)


def test_step7_fault_injector_fires_once_only_when_enabled(monkeypatch) -> None:
    monkeypatch.setenv("VULNFORGE_INJECT_STEP7_FAILURE", "1")
    injector = Step7FaultInjector.from_environment()

    with pytest.raises(InjectedStep7Failure):
        injector.before_verifier()
    injector.before_verifier()


def test_step7_fault_injector_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("VULNFORGE_INJECT_STEP7_FAILURE", raising=False)
    Step7FaultInjector.from_environment().before_verifier()


def test_fresh_recovery_uses_new_attempt_and_revision_for_generated_defect(tmp_path) -> None:
    attempts = []
    traces = []

    async def run_attempt(attempt) -> dict[str, object]:
        attempts.append((attempt.retry_index, attempt.source_revision, attempt.run_id, attempt.attempt_id))
        if attempt.retry_index == 0:
            raise InjectedStep7Failure("forced verifier failure")
        return {"sandbox_name": f"sbx-{attempt.retry_index:016x}", "outcome": "succeeded"}

    coordinator = FreshRetryCoordinator(
        batch_id="batch-0123456789ab",
        parent_run_id="run-0123456789ab",
        trace_writer=traces.append,
    )
    result = asyncio.run(
        coordinator.run(
            run_attempt,
            source_revision="source-r1",
            spec_revision="spec-r1",
            classify=lambda _exc: FailureClass.GENERATED_CODE,
        )
    )

    assert result["outcome"] == "succeeded"
    assert attempts[0][:2] == (0, "source-r1")
    assert attempts[1][:2] == (1, "source-r1-rev2")
    assert attempts[0][2] != attempts[1][2]
    assert attempts[0][3] != attempts[1][3]
    assert traces[0]["failed_step"] == 7
    assert traces[0]["retry_decision"] == "fresh"
    assert traces[0]["new_source_revision"] == "source-r1-rev2"
    assert traces[-1]["final_outcome"] == "succeeded"


def test_fresh_recovery_stops_after_two_retries_and_preserves_failures() -> None:
    attempts = []

    async def always_fails(attempt) -> dict[str, object]:
        attempts.append((attempt.retry_index, attempt.source_revision, attempt.run_id, attempt.attempt_id))
        raise RuntimeError("provider unavailable")

    coordinator = FreshRetryCoordinator(
        batch_id="batch-0123456789ab",
        parent_run_id="run-0123456789ab",
        max_retries=2,
    )
    with pytest.raises(RuntimeError, match="provider unavailable"):
        asyncio.run(
            coordinator.run(
                always_fails,
                source_revision="source-r1",
                spec_revision="spec-r1",
                classify=lambda _exc: FailureClass.INFRASTRUCTURE,
            )
        )

    assert [item[:2] for item in attempts] == [
        (0, "source-r1"),
        (1, "source-r1"),
        (2, "source-r1"),
    ]
    assert len({item[2] for item in attempts}) == 3
    assert len({item[3] for item in attempts}) == 3


def test_failure_policy_document_matches_step7_fresh_contract() -> None:
    document = failure_policy_document()
    assert document["failed_step"] == 7
    assert document["total_steps"] == 10
    assert document["policy"] == "fresh"
    assert len(document["rationale"]) >= 200
    assert document["trace_path"] == "reports/failure_trace.jsonl"
