from __future__ import annotations

import os
import subprocess
import sys
from decimal import Decimal

import pytest

from src.celesto_adapter import Guest, PublishedEndpoint, ResumeReadiness
from src.lifecycle import RunLifecycle


class MemoryRepository:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}
        self.events: list[tuple[str, str, str]] = []

    async def sandbox_name_exists(self, sandbox_name: str) -> bool:
        return any(row["sandbox_name"] == sandbox_name for row in self.rows.values())

    async def create_run(self, values: dict[str, object]) -> dict[str, object]:
        row = dict(values)
        self.rows[str(row["run_id"])] = row
        self.events.append((str(row["run_id"]), "", str(row["state"])))
        return row

    async def transition_run(
        self, run_id: str, next_state: str, **updates: object
    ) -> dict[str, object]:
        row = self.rows[run_id]
        previous_state = str(row["state"])
        row.update(updates)
        row["state"] = next_state
        self.events.append((run_id, previous_state, next_state))
        return dict(row)


class FakeAdapter:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def create_guest(
        self,
        template_id: str,
        *,
        sandbox_name: str,
        command_context_factory,
    ) -> Guest:
        self.calls.append("create")
        return Guest(
            "cmp-test",
            sandbox_name,
            object(),
            2.5,
            command_context=command_context_factory(sandbox_name),
            created_monotonic=1.0,
        )

    def publish(self, _guest: Guest, _port: int) -> PublishedEndpoint:
        self.calls.append("publish")
        return PublishedEndpoint(8000, "https://route.celesto.dev/", "published")

    def start_and_wait_ready(self, *_args, **_kwargs) -> ResumeReadiness:
        self.calls.append("start")
        return ResumeReadiness(0, 1.25, 200)

    def stop_guest(self, _guest: Guest) -> float:
        self.calls.append("stop")
        return 0.5

    def resume_and_wait_ready(self, *_args, **_kwargs) -> ResumeReadiness:
        self.calls.append("resume")
        return ResumeReadiness(1.0, 0.75, 200)

    def revoke(self, _guest: Guest, _endpoint: PublishedEndpoint) -> float:
        self.calls.append("revoke")
        return 0.25

    def delete_guest(self, _guest: Guest) -> float:
        self.calls.append("delete")
        return 0.5

    def guest_duration_s(self, _guest: Guest) -> float:
        return 3600


@pytest.mark.anyio
async def test_lifecycle_can_attach_a_guest_to_a_precreated_run() -> None:
    repository = MemoryRepository()
    repository.rows["run-0123456789ab"] = {
        "run_id": "run-0123456789ab",
        "attempt_id": "attempt-0123456789ab",
        "batch_id": "batch-0123456789ab",
        "sandbox_name": "sbx-0123456789abcdef",
        "state": "created",
    }
    lifecycle = RunLifecycle(repository, FakeAdapter())

    attempt = await lifecycle.create_attempt(
        problem_id="ctf-sqli-basic",
        run_id="run-0123456789ab",
        attempt_id="attempt-0123456789ab",
        batch_id="batch-0123456789ab",
        sandbox_name="sbx-0123456789abcdef",
        persist_run=False,
    )

    assert attempt.batch_id == "batch-0123456789ab"
    assert attempt.guest.sandbox_name == "sbx-0123456789abcdef"
    assert list(repository.rows) == ["run-0123456789ab"]


@pytest.mark.anyio
async def test_lifecycle_persists_create_pause_resume_and_cost() -> None:
    repository = MemoryRepository()
    adapter = FakeAdapter()
    lifecycle = RunLifecycle(repository, adapter)

    attempt = await lifecycle.create_attempt(problem_id="ctf-sqli-basic")
    ready = await lifecycle.start_and_publish(
        attempt,
        start_command="python3 /root/app.py",
        expected_marker="m3-ready",
    )
    await lifecycle.pause(attempt)
    resumed = await lifecycle.resume(
        attempt,
        restart_command="python3 /root/app.py",
        expected_marker="m3-ready",
    )
    final = await lifecycle.cleanup(attempt)
    repeated = await lifecycle.cleanup(attempt)

    assert ready.published_status == 200
    assert resumed.published_status == 200
    assert final is not None
    assert repeated is None
    assert final["state"] == "deleted"
    assert final["celesto_cost_usd"] == Decimal("0.015000")
    assert final["celesto_cost_method"] == "computed_from_duration"
    assert final["total_cost_usd"] is None
    assert [event[2] for event in repository.events] == [
        "created",
        "ready",
        "running",
        "ready",
        "running",
        "deleted",
    ]
    assert adapter.calls == [
        "create",
        "publish",
        "start",
        "stop",
        "resume",
        "revoke",
        "delete",
    ]


@pytest.mark.anyio
async def test_failed_sandbox_create_is_recorded_without_fallback() -> None:
    class RefusingAdapter(FakeAdapter):
        def create_guest(self, *_args, **_kwargs) -> Guest:
            self.calls.append("create_network_policy_off_failed")
            raise RuntimeError("network_policy=off refused")

    repository = MemoryRepository()
    lifecycle = RunLifecycle(repository, RefusingAdapter())

    with pytest.raises(RuntimeError, match="network_policy=off"):
        await lifecycle.create_attempt(problem_id="ctf-sqli-basic")

    assert len(repository.rows) == 1
    row = next(iter(repository.rows.values()))
    assert row["state"] == "failed"
    assert row["error_code"] == "sandbox_create_failed"
    assert [event[2] for event in repository.events] == ["created", "failed"]


@pytest.mark.anyio
async def test_failed_created_guest_cost_is_persisted_when_delete_was_confirmed() -> (
    None
):
    class CostedFailureAdapter(FakeAdapter):
        def create_guest(self, *_args, **_kwargs) -> Guest:
            failure = RuntimeError("network policy self-check failed")
            failure.guest_duration_s = 12.0
            raise failure

    repository = MemoryRepository()
    lifecycle = RunLifecycle(repository, CostedFailureAdapter())

    with pytest.raises(RuntimeError, match="network policy"):
        await lifecycle.create_attempt(problem_id="ctf-sqli-basic")

    row = next(iter(repository.rows.values()))
    assert row["state"] == "failed"
    assert row["wall_clock_s"] == 12.0
    assert row["celesto_duration_s"] == 12.0
    assert row["celesto_cost_usd"] == Decimal("0.000050")
    assert row["celesto_cost_method"] == "computed_from_duration"


@pytest.mark.anyio
async def test_stopped_interval_is_excluded_from_celesto_cost() -> None:
    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    class TimedAdapter(FakeAdapter):
        def guest_duration_s(self, _guest: Guest) -> float:
            return clock.now

    clock = Clock()
    repository = MemoryRepository()
    lifecycle = RunLifecycle(repository, TimedAdapter(), monotonic=clock)
    attempt = await lifecycle.create_attempt(problem_id="ctf-sqli-basic")
    await lifecycle.start_and_publish(
        attempt,
        start_command="python3 /root/app.py",
        expected_marker="m3-ready",
    )
    clock.now = 10.0
    await lifecycle.pause(attempt)
    clock.now = 70.0
    await lifecycle.resume(
        attempt,
        restart_command="python3 /root/app.py",
        expected_marker="m3-ready",
    )
    clock.now = 110.0

    final = await lifecycle.cleanup(attempt)

    assert final is not None
    assert final["wall_clock_s"] == 110.0
    assert final["celesto_duration_s"] == 50.0
    assert final["celesto_cost_usd"] == Decimal("0.000208")


@pytest.mark.anyio
async def test_cleanup_retries_unconfirmed_delete_without_claiming_success() -> None:
    class FlakyDeleteAdapter(FakeAdapter):
        def __init__(self) -> None:
            super().__init__()
            self.delete_count = 0

        def delete_guest(self, _guest: Guest) -> float:
            self.delete_count += 1
            self.calls.append("delete")
            if self.delete_count == 1:
                raise RuntimeError("delete not confirmed")
            return 0.5

    repository = MemoryRepository()
    adapter = FlakyDeleteAdapter()
    lifecycle = RunLifecycle(repository, adapter)
    attempt = await lifecycle.create_attempt(problem_id="ctf-sqli-basic")

    first = await lifecycle.cleanup(attempt)
    assert first is not None
    assert first["state"] == "failed"
    assert first["celesto_cost_usd"] is None
    assert attempt.cleaned is False

    second = await lifecycle.cleanup(attempt)

    assert second is not None
    assert second["state"] == "deleted"
    assert attempt.cleaned is True
    assert adapter.delete_count == 2


def test_sigint_runs_revoke_delete_and_terminal_ledger_transition(tmp_path) -> None:
    script = tmp_path / "sigint_probe.py"
    script.write_text(
        """import asyncio, os, signal
from types import SimpleNamespace
from src.lifecycle import LifecycleAttempt, RunLifecycle

class Repo:
    async def transition_run(self, run_id, state, **updates):
        print(f"state={state} error={updates.get('error_code')}")
        return {"state": state}

class Adapter:
    def revoke(self, *_args): print("revoke")
    def delete_guest(self, *_args): print("delete")
    def guest_duration_s(self, *_args): return 2.0

async def main():
    attempt = LifecycleAttempt(
        "run-0123456789ab", "attempt-0123456789ab",
        SimpleNamespace(created_monotonic=1), state="running",
        endpoint=SimpleNamespace(port=8000),
    )
    manager = RunLifecycle(Repo(), Adapter())
    asyncio.get_running_loop().call_later(0.05, os.kill, os.getpid(), signal.SIGINT)
    await manager.wait_for_sigint(attempt)

asyncio.run(main())
"""
    )

    result = subprocess.run(
        [sys.executable, str(script)],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": os.getcwd()},
        timeout=5,
    )

    assert result.returncode == 0, result.stderr
    assert "revoke" in result.stdout
    assert "delete" in result.stdout
    assert "state=deleted error=interrupted" in result.stdout
