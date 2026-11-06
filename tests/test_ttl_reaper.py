from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from src.lab_manager import LabManager, _LabRecord


class FakeRepo:
    def __init__(self, rows: list[dict] | None = None) -> None:
        self.rows = rows or []
        self.transitions: list[tuple[str, str, str | None]] = []
        self.phases: list[tuple[str, str]] = []

    async def list_runs(self) -> list[dict]:
        return self.rows

    async def transition_run(self, run_id, state, *, error_code=None, **_kw):
        self.transitions.append((run_id, state, error_code))
        return {"run_id": run_id, "state": state}

    async def set_run_phase(self, run_id, phase):
        self.phases.append((run_id, phase))
        return {"run_id": run_id, "phase": phase}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_reap_expired_tears_down_old_guests(monkeypatch) -> None:
    monkeypatch.setenv("SANDBOX_TTL_MINUTES", "15")
    manager = LabManager(FakeRepo())
    stopped: list[str] = []

    async def fake_stop(run_id: str):
        stopped.append(run_id)

    monkeypatch.setattr(manager, "stop_lab", fake_stop)

    old = _LabRecord(
        run_id="run-oldoldoldold",
        attempt_id="attempt-oldoldoldold",
        batch_id="batch-oldoldoldold",
        sandbox_name="sbx-oldoldoldold",
        description="old",
        phase="published",
    )
    old.attempt = SimpleNamespace(guest=SimpleNamespace(created_monotonic=time.monotonic() - 16 * 60))
    fresh = _LabRecord(
        run_id="run-freshfreshfr",
        attempt_id="attempt-freshfreshfr",
        batch_id="batch-freshfreshfr",
        sandbox_name="sbx-freshfreshfr",
        description="fresh",
        phase="published",
    )
    fresh.attempt = SimpleNamespace(guest=SimpleNamespace(created_monotonic=time.monotonic()))
    manager._records = {old.run_id: old, fresh.run_id: fresh}

    reaped = await manager.reap_expired()
    assert reaped == ["run-oldoldoldold"]
    assert stopped == ["run-oldoldoldold"]


@pytest.mark.anyio
async def test_reconcile_orphans_fails_non_terminal_rows() -> None:
    repo = FakeRepo(
        rows=[
            {"run_id": "run-running00001", "state": "running"},
            {"run_id": "run-created00001", "state": "created"},
            {"run_id": "run-done000000001", "state": "succeeded"},
            {"run_id": "run-deleted000001", "state": "deleted"},
        ]
    )
    manager = LabManager(repo)
    reconciled = await manager.reconcile_orphans()
    assert set(reconciled) == {"run-running00001", "run-created00001"}
    assert all(state == "failed" for _, state, _ in repo.transitions)
    assert all(err == "orphaned_after_restart" for _, _, err in repo.transitions)
