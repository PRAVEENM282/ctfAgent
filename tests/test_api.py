from __future__ import annotations

from typing import Any

import pytest
from httpx2 import ASGITransport, AsyncClient

from src.api.main import create_app
from src.ledger.repository import DuplicateRunId, LedgerUnavailable


class MemoryRepository:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, Any]] = {}
        self.healthy = True

    async def check_health(self) -> None:
        if not self.healthy:
            raise LedgerUnavailable

    async def list_runs(self) -> list[dict[str, Any]]:
        return sorted(self.rows.values(), key=lambda row: (row["created_at"], row["run_id"]))

    async def create_run(self, values: dict[str, Any]) -> dict[str, Any]:
        if values["run_id"] in self.rows:
            raise DuplicateRunId
        row = {**values, "created_at": "2026-10-22T00:00:00+00:00"}
        self.rows[row["run_id"]] = row
        return row


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def repository() -> MemoryRepository:
    return MemoryRepository()


@pytest.fixture
async def client(repository: MemoryRepository) -> AsyncClient:
    transport = ASGITransport(app=create_app(repository=repository))
    async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client


def _valid_run(**overrides: str) -> dict[str, str]:
    return {
        "run_id": "run-abc123def456",
        "sandbox_name": "sbx-0123456789abcdef",
        "problem_id": "ctf-sqli-basic",
        "state": "created",
        "execution_target": "celesto_sandbox",
        **overrides,
    }


@pytest.mark.anyio
async def test_health_is_ok_when_ledger_is_available(client: AsyncClient) -> None:
    response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_database_health_is_ok_when_ledger_is_available(client: AsyncClient) -> None:
    response = await client.get("/health/db")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_liveness_health_stays_ok_when_ledger_is_down(
    client: AsyncClient, repository: MemoryRepository
) -> None:
    repository.healthy = False
    response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_database_health_reports_ledger_failure(
    client: AsyncClient, repository: MemoryRepository
) -> None:
    repository.healthy = False
    response = await client.get("/health/db")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ledger_unavailable"


@pytest.mark.anyio
async def test_get_runs_returns_a_json_array(
    client: AsyncClient, repository: MemoryRepository
) -> None:
    repository.rows["run-seed00000001"] = {
        **_valid_run(run_id="run-seed00000001", sandbox_name="sbx-seeddemo1"),
        "state": "deleted",
        "problem_id": "ctf-seed-validation",
        "created_at": "2026-10-21T00:00:00+00:00",
    }

    response = await client.get("/api/runs")

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert response.json()[0]["sandbox_name"] == "sbx-seeddemo1"


@pytest.mark.anyio
async def test_post_run_returns_created_row(client: AsyncClient) -> None:
    response = await client.post("/api/runs", json=_valid_run())

    assert response.status_code == 201
    assert response.json()["run_id"] == "run-abc123def456"
    assert response.json()["execution_target"] == "celesto_sandbox"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("field", "value", "error_code"),
    [
        ("run_id", "bad-id", "invalid_run_id"),
        ("sandbox_name", "bad-name", "invalid_sandbox_name"),
        ("problem_id", "", "invalid_problem_id"),
        ("state", "queued", "invalid_state"),
        ("execution_target", "host", "invalid_execution_target"),
    ],
)
async def test_post_run_returns_stable_400_for_invalid_fields(
    client: AsyncClient, field: str, value: str, error_code: str
) -> None:
    response = await client.post("/api/runs", json=_valid_run(**{field: value}))

    assert response.status_code == 400
    assert response.json()["error"]["code"] == error_code


@pytest.mark.anyio
async def test_duplicate_run_id_returns_stable_400(client: AsyncClient) -> None:
    body = _valid_run()
    assert (await client.post("/api/runs", json=body)).status_code == 201

    response = await client.post("/api/runs", json=body)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "duplicate_run_id"


@pytest.mark.anyio
async def test_reports_route_serves_files_read_only(client: AsyncClient) -> None:
    response = await client.get("/reports/schemas/problem.schema.json")
    write_response = await client.put("/reports/schemas/problem.schema.json", content="{}")

    assert response.status_code == 200
    assert response.json()["type"] == "object"
    assert write_response.status_code == 405
