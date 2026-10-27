from __future__ import annotations

from pathlib import Path

import pytest
from httpx2 import ASGITransport, AsyncClient

from src.api.main import create_app
from src.api.schemas import LabSnapshot
from src.lab_manager import LabConflict, LabExecutionError
from src.ledger.repository import RunNotFound


class FakeLabManager:
    def __init__(self) -> None:
        self.snapshot = LabSnapshot(
            run_id="run-abc123def456",
            state="created",
            phase="queued",
            message="Lab creation queued.",
            can_publish=False,
            can_stop=True,
            cleanup_confirmed=False,
        )
        self.closed = False
        self.description = ""

    async def create_lab(
        self,
        description: str,
        *,
        mode: str = "single",
        vulnerabilities: list[str] | None = None,
    ) -> LabSnapshot:
        self.description = description
        return self.snapshot

    async def get_lab(self, run_id: str) -> LabSnapshot:
        if run_id != self.snapshot.run_id:
            raise RunNotFound(run_id)
        return self.snapshot

    async def publish_lab(self, run_id: str) -> LabSnapshot:
        if run_id != self.snapshot.run_id:
            raise RunNotFound(run_id)
        raise LabConflict("lab is not ready for publication")

    async def stop_lab(self, run_id: str) -> LabSnapshot:
        if run_id != self.snapshot.run_id:
            raise RunNotFound(run_id)
        return self.snapshot.model_copy(
            update={
                "state": "deleted",
                "phase": "cleaned_up",
                "message": "The public route was revoked and the sandbox was deleted.",
                "can_stop": False,
                "cleanup_confirmed": True,
            }
        )

    async def close(self) -> None:
        self.closed = True


class FailingLabManager(FakeLabManager):
    async def create_lab(
        self,
        description: str,
        *,
        mode: str = "single",
        vulnerabilities: list[str] | None = None,
    ) -> LabSnapshot:
        raise LabExecutionError("provider_request_failed")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def client() -> AsyncClient:
    manager = FakeLabManager()
    app = create_app(lab_manager=manager)
    app.state.test_manager = manager
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client


@pytest.mark.anyio
async def test_create_lab_trims_description_and_returns_accepted_snapshot(client: AsyncClient) -> None:
    response = await client.post(
        "/api/labs", json={"description": "  Create a product search lesson.  "}
    )

    assert response.status_code == 202
    assert response.json()["phase"] == "queued"
    assert response.json()["run_id"] == "run-abc123def456"
    assert client._transport.app.state.test_manager.description == "Create a product search lesson."


@pytest.mark.anyio
async def test_create_lab_accepts_a_profile_bundle(client: AsyncClient) -> None:
    response = await client.post(
        "/api/labs",
        json={
            "description": "Create a mixed vulnerability lesson.",
            "mode": "bundle",
            "vulnerabilities": ["sql_injection", "reflected_xss"],
        },
    )

    assert response.status_code == 202
    assert response.json()["phase"] == "queued"


@pytest.mark.anyio
async def test_create_lab_rejects_invalid_profile_selection(client: AsyncClient) -> None:
    response = await client.post(
        "/api/labs",
        json={
            "description": "Create an invalid selection.",
            "mode": "single",
            "vulnerabilities": ["sql_injection", "idor"],
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_vulnerability_selection"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "description",
    ["", "   ", "x" * 2001],
)
async def test_create_lab_rejects_invalid_descriptions(
    client: AsyncClient, description: str
) -> None:
    response = await client.post("/api/labs", json={"description": description})

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_description"


@pytest.mark.anyio
async def test_lab_status_is_safe_and_unknown_runs_are_not_found(client: AsyncClient) -> None:
    response = await client.get("/api/labs/run-abc123def456")
    assert response.status_code == 200
    body = response.json()
    assert "provider_key" not in body
    assert "raw_output" not in body
    assert "flag" not in body

    missing = await client.get("/api/labs/run-missing0000")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "lab_not_found"


@pytest.mark.anyio
async def test_publish_conflict_and_stop_snapshot(client: AsyncClient) -> None:
    conflict = await client.post("/api/labs/run-abc123def456/publish")
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "lab_action_not_available"

    stopped = await client.post("/api/labs/run-abc123def456/stop")
    assert stopped.status_code == 200
    assert stopped.json()["phase"] == "cleaned_up"
    assert stopped.json()["cleanup_confirmed"] is True


@pytest.mark.anyio
async def test_failure_response_has_bounded_message() -> None:
    app = create_app(lab_manager=FailingLabManager())
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/api/labs", json={"description": "Create a search lesson."})

    assert response.status_code == 502
    assert response.json() == {
        "error": {
            "code": "provider_request_failed",
            "message": "The model provider could not complete generation.",
        }
    }


@pytest.mark.anyio
async def test_dashboard_shell_is_served_from_explicit_frontend_directory(tmp_path: Path) -> None:
    frontend = tmp_path / "dist"
    assets = frontend / "assets"
    assets.mkdir(parents=True)
    (frontend / "index.html").write_text("<html><title>VulnForge</title></html>", encoding="utf-8")
    (assets / "app.js").write_text("console.log('dashboard')", encoding="utf-8")
    app = create_app(lab_manager=FakeLabManager(), frontend_dir=frontend)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        shell = await client.get("/")
        asset = await client.get("/assets/app.js")

    assert shell.status_code == 200
    assert "VulnForge" in shell.text
    assert asset.status_code == 200
    assert "dashboard" in asset.text
