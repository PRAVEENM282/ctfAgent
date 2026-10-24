from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx2 import ASGITransport, AsyncClient

from src.agent.provider import (
    OpenAICompatibleClient,
    ProviderHTTPError,
    ProviderResponse,
    ProviderSettings,
)
from src.api.main import create_app
from src.celesto_adapter import Guest, PublishedEndpoint
from src.command_guard import CommandOutcome
from src.lab_manager import LabManager, _error_code
from src.ledger.repository import RunNotFound

SOURCE = """import http.server
import sqlite3

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/search') and 'q' in self.path:
            sqlite3.connect('/root/app.db').execute('SELECT value FROM secrets')
        self.send_response(200)
        self.end_headers()

if __name__ == '__main__':
    http.server.HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
"""


@pytest.mark.parametrize(
    ("status", "provider_code", "expected"),
    [
        (429, "rate_limited", "rate_limited"),
        (400, "http_400", "http_400"),
        (401, "http_401", "http_401"),
        (502, "http_502", "provider_request_failed"),
    ],
)
def test_provider_http_failure_keeps_safe_actionable_category(
    status: int, provider_code: str, expected: str
) -> None:
    assert _error_code(ProviderHTTPError(status, error_code=provider_code)) == expected


class MemoryRepository:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, Any]] = {}
        self.approvals: dict[str, dict[str, Any]] = {}
        self.publications: dict[str, dict[str, Any]] = {}
        self.requests = 0

    async def create_run(self, values: dict[str, Any]) -> dict[str, Any]:
        if values["run_id"] in self.rows:
            raise RuntimeError("duplicate run")
        row = {
            **values,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
        self.rows[values["run_id"]] = row
        return dict(row)

    async def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self.rows.get(run_id)
        return dict(row) if row is not None else None

    async def set_run_phase(self, run_id: str, phase: str) -> dict[str, Any]:
        row = self.rows[run_id]
        row["phase"] = phase
        row["updated_at"] = datetime.now(UTC)
        return dict(row)

    async def transition_run(
        self, run_id: str, next_state: str, **updates: Any
    ) -> dict[str, Any]:
        row = self.rows[run_id]
        row.update(updates)
        row["state"] = next_state
        row["updated_at"] = datetime.now(UTC)
        return dict(row)

    async def preflight_llm_batch(self, **_kwargs: Any) -> dict[str, Any]:
        return {"allowed": True}

    async def create_llm_attempt_budget(
        self, *_args: Any, **_kwargs: Any
    ) -> dict[str, Any]:
        return {"status": "active"}

    async def reserve_llm_request(self, *_args: Any, **_kwargs: Any) -> dict[str, int]:
        self.requests += 1
        return {"request_id": self.requests}

    async def mark_llm_request_sent(self, *_args: Any) -> None:
        return None

    async def record_llm_response(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    async def complete_llm_attempt_budget(self, *_args: Any) -> dict[str, Any]:
        return {"status": "completed"}

    async def create_approval(self, **values: Any) -> dict[str, Any]:
        row = {
            "approval_id": "approval-0123456789abcdef",
            **values,
            "decision": "pending",
            "expires_at": datetime.now(UTC),
            "mode": values.get("mode", "interactive"),
        }
        self.approvals[row["approval_id"]] = row
        return dict(row)

    async def decide_approval(self, approval_id: str, **values: Any) -> dict[str, Any]:
        row = self.approvals[approval_id]
        row.update(values)
        return dict(row)

    async def consume_approval(self, **values: Any):
        from src.approval import ApprovalBinding

        row = next(iter(self.approvals.values()))
        return ApprovalBinding(
            approval_id=row["approval_id"],
            run_id=values["run_id"],
            attempt_id=values["attempt_id"],
            sandbox_name=values["sandbox_name"],
            action="publish_public_lab",
            port=values["port"],
            app_sha256=values["app_sha256"],
            expires_at=datetime.now(UTC).replace(year=datetime.now(UTC).year + 1),
            decision="approved",
            mode="interactive",
        )

    async def record_publication(self, run_id: str, **values: Any) -> dict[str, Any]:
        self.publications[run_id] = {"run_id": run_id, **values}
        return dict(self.publications[run_id])

    async def mark_publication_revoked(
        self, run_id: str, **values: Any
    ) -> dict[str, Any]:
        self.publications[run_id]["revoked"] = True
        self.publications[run_id].update(values)
        return dict(self.publications[run_id])

    async def get_publication(self, run_id: str) -> dict[str, Any] | None:
        row = self.publications.get(run_id)
        return dict(row) if row is not None else None


class FakeClient:
    def __init__(self) -> None:
        self.wrote_source = False

    def chat(self, *, messages, tools, max_tokens):
        assert messages and tools and max_tokens > 0
        if self.wrote_source:
            return ProviderResponse(
                model="test-model",
                message={"role": "assistant", "content": "Challenge source is ready."},
                prompt_tokens=4,
                completion_tokens=3,
                total_tokens=7,
                headers={},
                status_code=200,
            )
        self.wrote_source = True
        return ProviderResponse(
            model="test-model",
            message={
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "write_app",
                            "arguments": json.dumps({"source": SOURCE}),
                        },
                    }
                ],
            },
            prompt_tokens=4,
            completion_tokens=3,
            total_tokens=7,
            headers={},
            status_code=200,
        )


class FakeGuard:
    def __init__(self, adapter: FakeAdapter) -> None:
        self.adapter = adapter

    def execute_control_plane(self, _context, command, **_kwargs):
        if "UNION" in command:
            output = self.adapter.flag
        else:
            output = "ordinary result"
        return CommandOutcome("allow", True, 0, stdout=output)


class FakeAdapter:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.flag = ""

    def create_guest(
        self, template_id, *, sandbox_name, command_context_factory
    ) -> Guest:
        self.calls.append(f"create:{template_id}")
        return Guest(
            "cmp-test",
            sandbox_name,
            object(),
            0.1,
            command_context=command_context_factory(sandbox_name),
            created_monotonic=1.0,
        )

    def agent_command_tool(self, _guest):
        def write(_command, **_kwargs):
            self.calls.append("write")
            return CommandOutcome("allow", True, 0)

        return write

    def upload_trusted_file(self, _guest, path, payload):
        self.calls.append(f"upload:{path}")
        if payload:
            self.flag = json.loads(payload)["flag"]

    def control_plane_command(self, _guest, command, **_kwargs):
        self.calls.append("control")
        return CommandOutcome("allow", True, 0, stdout="200")

    def control_plane_guard(self, _guest):
        return FakeGuard(self)

    def publish(self, _guest, port):
        self.calls.append("publish")
        return PublishedEndpoint(port, "https://opaque.celesto.dev/lab", "published")

    def revoke(self, _guest, _endpoint):
        self.calls.append("revoke")

    def delete_guest(self, _guest):
        self.calls.append("delete")

    def guest_duration_s(self, _guest):
        return 1.0


@pytest.fixture(autouse=True)
def inline_fake_io(monkeypatch):
    async def run_inline(function, /, *args, **kwargs):
        return function(*args, **kwargs)

    # These tests use synchronous fakes; the restricted runner's thread pool
    # can stall at teardown, so exercise orchestration inline without changing
    # production code or claiming to test thread scheduling.
    monkeypatch.setattr(asyncio, "to_thread", run_inline)


async def _wait_for_phase(manager: LabManager, run_id: str, phase: str):
    for _ in range(100):
        snapshot = await manager.get_lab(run_id)
        if snapshot.phase == phase:
            return snapshot
        await asyncio.sleep(0.01)
    raise AssertionError(f"phase did not reach {phase}")


@pytest.mark.anyio
async def test_lab_manager_runs_generation_verification_publication_and_cleanup() -> (
    None
):
    repository = MemoryRepository()
    adapter = FakeAdapter()
    settings = ProviderSettings(
        "bedrock", "https://provider.example/v1", "key", "model"
    )
    manager = LabManager(
        repository,
        adapter_factory=lambda: adapter,
        provider_settings_factory=lambda: settings,
        provider_client_factory=lambda _settings: FakeClient(),
        external_probe=lambda _url: 200,
    )

    queued = await manager.create_lab("Create a small product search page.")
    awaiting = await _wait_for_phase(manager, queued.run_id, "awaiting_publication")

    assert queued.phase == "queued"
    assert awaiting.can_publish is True
    assert "VF{" not in repr(awaiting)
    assert "publish" not in adapter.calls

    published = await manager.publish_lab(queued.run_id)

    assert published.phase == "published"
    assert published.public_url == "https://opaque.celesto.dev/lab"
    assert published.public_access_warning
    assert adapter.calls.count("publish") == 1

    cleaned = await manager.stop_lab(queued.run_id)

    assert cleaned.phase == "cleaned_up"
    assert cleaned.cleanup_confirmed is True
    assert adapter.calls[-2:] == ["revoke", "delete"]

    await manager.close()


@pytest.mark.anyio
async def test_lab_manager_rejects_publish_before_private_verification() -> None:
    repository = MemoryRepository()
    manager = LabManager(
        repository,
        adapter_factory=FakeAdapter,
        provider_settings_factory=lambda: ProviderSettings(
            "bedrock", "https://provider.example/v1", "key", "model"
        ),
        provider_client_factory=lambda _settings: FakeClient(),
    )
    queued = await manager.create_lab("Create a search lesson.")

    with pytest.raises(Exception, match="not ready for publication"):
        await manager.publish_lab(queued.run_id)

    await manager.stop_lab(queued.run_id)
    await manager.close()


@pytest.mark.anyio
async def test_lab_manager_reports_unknown_run_without_database_details() -> None:
    manager = LabManager(MemoryRepository(), adapter_factory=FakeAdapter)

    with pytest.raises(RunNotFound):
        await manager.get_lab("run-unknown0000")


@pytest.mark.anyio
async def test_dashboard_api_completes_mocked_lab_lifecycle_end_to_end() -> None:
    repository = MemoryRepository()
    adapter = FakeAdapter()
    provider_requests = []

    def mocked_provider_transport(url, headers, body, _timeout):
        request = json.loads(body)
        provider_requests.append((url, headers, request))
        if len(provider_requests) == 1:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "write_app",
                            "arguments": json.dumps({"source": SOURCE}),
                        },
                    }
                ],
            }
        else:
            message = {"role": "assistant", "content": "Challenge source is ready."}
        response = {
            "model": "test-model",
            "choices": [{"message": message}],
            "usage": {"prompt_tokens": 4, "completion_tokens": 3, "total_tokens": 7},
        }
        return 200, {"content-type": "application/json"}, json.dumps(response).encode()

    manager = LabManager(
        repository,
        adapter_factory=lambda: adapter,
        provider_settings_factory=lambda: ProviderSettings(
            "openrouter",
            "https://provider.example/v1",
            "server-only-test-key",
            "test-model",
        ),
        provider_client_factory=lambda settings: OpenAICompatibleClient(
            settings.config, transport=mocked_provider_transport
        ),
        external_probe=lambda _url: 200,
    )
    app = create_app(repository=repository, lab_manager=manager)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post(
            "/api/labs", json={"description": "Create a small product search page."}
        )
        assert created.status_code == 202
        run_id = created.json()["run_id"]
        assert created.json()["phase"] == "queued"
        assert created.json().get("public_url") is None

        awaiting = await _wait_for_phase(manager, run_id, "awaiting_publication")
        assert awaiting.can_publish
        status = await client.get(f"/api/labs/{run_id}")
        assert status.status_code == 200
        assert status.json()["phase"] == "awaiting_publication"
        assert status.json().get("public_url") is None
        assert "server-only-test-key" not in status.text
        assert "VF{" not in status.text

        published = await client.post(f"/api/labs/{run_id}/publish")
        assert published.status_code == 200
        assert published.json()["phase"] == "published"
        assert published.json()["public_url"] == "https://opaque.celesto.dev/lab"
        assert published.json()["public_access_warning"]

        stopped = await client.post(f"/api/labs/{run_id}/stop")
        assert stopped.status_code == 200
        assert stopped.json()["phase"] == "cleaned_up"
        assert stopped.json()["cleanup_confirmed"] is True

    assert repository.requests == 2
    assert adapter.calls.count("write") == 1
    assert adapter.calls.count("publish") == 1
    assert len(provider_requests) == 2
    assert provider_requests[0][0] == "https://provider.example/v1/chat/completions"
    assert provider_requests[0][1]["Authorization"] == "Bearer server-only-test-key"
    assert adapter.calls[-2:] == ["revoke", "delete"]
    assert repository.publications[run_id]["revoked"] is True
    await manager.close()
