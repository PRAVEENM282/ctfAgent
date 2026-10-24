"""Live PostgreSQL integration coverage; requires DATABASE_URL."""

from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest
from httpx2 import ASGITransport, AsyncClient

from src.api.main import create_app
from src.ledger.repository import (
    InvalidRunTransition,
    LedgerUnavailable,
    RunRepository,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_run_api_contract_against_postgres() -> None:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        pytest.skip("DATABASE_URL is not set; skipping PostgreSQL integration test")

    run_id = f"run-{uuid4().hex}"
    sandbox_name = f"sbx-{uuid4().hex[:16]}"
    repository = RunRepository(database_url)
    try:
        await repository.check_health()
    except LedgerUnavailable:
        pytest.skip("PostgreSQL at DATABASE_URL is not reachable")

    client = AsyncClient(
        transport=ASGITransport(app=create_app(repository=repository)),
        base_url="http://testserver",
    )
    inserted = False

    try:
        liveness = await client.get("/health")
        assert liveness.status_code == 200
        assert liveness.json() == {"status": "ok"}

        database_health = await client.get("/health/db")
        assert database_health.status_code == 200
        assert database_health.json() == {"status": "ok"}

        runs_response = await client.get("/api/runs")
        assert runs_response.status_code == 200
        assert any(
            row["sandbox_name"] == "sbx-seeddemo1" for row in runs_response.json()
        )

        async with await psycopg.AsyncConnection.connect(database_url) as connection:
            cursor = await connection.execute(
                "SELECT count(*) FROM runs WHERE sandbox_name = %s", ("sbx-seeddemo1",)
            )
            seed_count = (await cursor.fetchone())[0]
        assert seed_count == 1

        body = {
            "run_id": run_id,
            "sandbox_name": sandbox_name,
            "problem_id": "ctf-live-db-contract",
            "state": "created",
            "execution_target": "celesto_sandbox",
        }
        created = await client.post("/api/runs", json=body)
        inserted = created.status_code == 201
        assert created.status_code == 201
        assert created.json()["run_id"] == run_id

        duplicate = await client.post("/api/runs", json=body)
        assert duplicate.status_code == 400
        assert duplicate.json()["error"]["code"] == "duplicate_run_id"

        host_target = await client.post(
            "/api/runs",
            json={**body, "run_id": f"run-{uuid4().hex}", "execution_target": "host"},
        )
        assert host_target.status_code == 400
        assert host_target.json()["error"]["code"] == "invalid_execution_target"

        bad_name = await client.post(
            "/api/runs",
            json={**body, "run_id": f"run-{uuid4().hex}", "sandbox_name": "bad-name"},
        )
        assert bad_name.status_code == 400
        assert bad_name.json()["error"]["code"] == "invalid_sandbox_name"
    finally:
        await client.aclose()
        if inserted:
            async with await psycopg.AsyncConnection.connect(
                database_url
            ) as connection:
                await connection.execute(
                    "DELETE FROM runs WHERE run_id = %s", (run_id,)
                )


@pytest.mark.anyio
async def test_lifecycle_transitions_are_persisted_and_invalid_transitions_recorded() -> (
    None
):
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        pytest.skip("DATABASE_URL is not set; skipping PostgreSQL integration test")

    run_id = f"run-{uuid4().hex}"
    attempt_id = f"attempt-{uuid4().hex[:16]}"
    repository = RunRepository(database_url)
    try:
        await repository.check_health()
    except LedgerUnavailable:
        pytest.skip("PostgreSQL at DATABASE_URL is not reachable")

    created = False
    try:
        await repository.create_run(
            {
                "run_id": run_id,
                "attempt_id": attempt_id,
                "parent_run_id": run_id,
                "batch_id": f"batch-{uuid4().hex[:16]}",
                "sandbox_name": f"sbx-{uuid4().hex[:16]}",
                "problem_id": "ctf-lifecycle-transition-test",
                "state": "created",
                "execution_target": "celesto_sandbox",
            }
        )
        created = True

        ready = await repository.transition_run(run_id, "ready", boot_to_ready_s=1.25)
        assert ready["state"] == "ready"
        assert ready["boot_to_ready_s"] == 1.25

        running = await repository.transition_run(run_id, "running", app_ready_s=0.75)
        assert running["state"] == "running"

        paused = await repository.transition_run(run_id, "ready")
        assert paused["state"] == "ready"

        deleted = await repository.transition_run(
            run_id,
            "deleted",
            celesto_duration_s=30.0,
            celesto_cost_usd="0.000125",
            celesto_cost_method="computed_from_duration",
        )
        assert deleted["celesto_duration_s"] == 30.0
        assert str(deleted["celesto_cost_usd"]) == "0.000125"
        assert deleted["celesto_cost_method"] == "computed_from_duration"

        with pytest.raises(InvalidRunTransition):
            await repository.transition_run(run_id, "running")
        events = await repository.list_run_events(run_id)
        assert [event["to_state"] for event in events] == [
            "created",
            "ready",
            "running",
            "ready",
            "deleted",
            "running",
        ]
        assert events[-1]["event_type"] == "transition_rejected"
    finally:
        if created:
            async with await psycopg.AsyncConnection.connect(
                database_url
            ) as connection:
                await connection.execute(
                    "DELETE FROM runs WHERE run_id = %s", (run_id,)
                )
