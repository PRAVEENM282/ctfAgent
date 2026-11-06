from __future__ import annotations

import asyncio
import json

import pytest
from httpx2 import ASGITransport, AsyncClient

from src import config
from src.agent.loop import AgentLoopConfig
from src.agent.provider import ProviderResponse
from src.api.main import create_app
from src.api.schemas import LabSnapshot
from src.challenge import build_variation
from src.generator import ChallengeGenerator


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# ---- config validation --------------------------------------------------------


def test_config_cloud_requires_api_key(monkeypatch) -> None:
    monkeypatch.setenv("CELESTO_PROVIDER", "cloud")
    monkeypatch.setenv("CELESTO_API_KEY", "")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("LLM_MODEL", "qwen2.5-coder:1.5b")
    cfg = config.load_config()
    assert not cfg.valid
    assert any("CELESTO_API_KEY" in err for err in cfg.errors)


def test_config_local_ollama_is_valid(monkeypatch) -> None:
    monkeypatch.setenv("CELESTO_PROVIDER", "local")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("LLM_MODEL", "qwen2.5-coder:1.5b")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434")
    cfg = config.load_config()
    assert cfg.valid, cfg.errors
    assert cfg.celesto_provider == "local"
    assert cfg.llm_provider == "ollama"


def test_config_openai_compatible_requires_base_and_key(monkeypatch) -> None:
    monkeypatch.setenv("CELESTO_PROVIDER", "local")
    monkeypatch.setenv("LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("LLM_BASE_URL", "")
    monkeypatch.setenv("LLM_API_KEY", "")
    monkeypatch.setenv("LLM_MODEL", "")
    cfg = config.load_config()
    assert not cfg.valid
    assert any("LLM_BASE_URL" in err for err in cfg.errors)


def test_config_openai_alias_maps_to_openai_compatible(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    cfg = config.load_config()
    assert cfg.llm_provider == "openai_compatible"


def test_access_code_matches(monkeypatch) -> None:
    monkeypatch.delenv("ACCESS_CODE", raising=False)
    assert config.access_code_matches(None) is True
    monkeypatch.setenv("ACCESS_CODE", "secret-123")
    assert config.access_code_matches("secret-123") is True
    assert config.access_code_matches("wrong") is False
    assert config.access_code_matches(None) is False


# ---- new endpoints ------------------------------------------------------------


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
        self.flag_calls: list[str] = []

    async def create_lab(self, description, *, mode="single", vulnerabilities=None):
        return self.snapshot

    async def get_lab(self, run_id):
        return self.snapshot

    async def publish_lab(self, run_id):
        return self.snapshot.model_copy(update={"phase": "published", "state": "succeeded"})

    async def stop_lab(self, run_id):
        return self.snapshot.model_copy(
            update={"phase": "cleaned_up", "state": "deleted", "cleanup_confirmed": True}
        )

    async def submit_flag(self, run_id, candidate):
        self.flag_calls.append(candidate)
        return {"correct": candidate == "VF{correct}", "solved": candidate == "VF{correct}", "submissions": len(self.flag_calls)}

    async def close(self) -> None:
        return None


async def _client(manager: FakeLabManager) -> AsyncClient:
    app = create_app(lab_manager=manager)
    app.state.test_manager = manager
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://testserver")


@pytest.mark.anyio
async def test_api_config_reports_non_secret_mode(monkeypatch) -> None:
    monkeypatch.setenv("CELESTO_PROVIDER", "local")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("LLM_MODEL", "qwen2.5-coder:1.5b")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434")
    async with await _client(FakeLabManager()) as client:
        response = await client.get("/api/config")
    assert response.status_code == 200
    body = response.json()
    assert body["celesto_provider"] == "local"
    assert body["llm_provider"] == "ollama"
    assert body["llm_model"] == "qwen2.5-coder:1.5b"
    assert body["valid"] is True
    # Secrets are never exposed.
    assert "celesto_api_key" not in body
    assert "llm_api_key" not in body


@pytest.mark.anyio
async def test_api_commands_returns_audit_rows(monkeypatch, tmp_path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "commands.jsonl").write_text(
        json.dumps({"decision": "allow", "execution_target": "celesto_sandbox"}) + "\n"
        + json.dumps({"decision": "block", "execution_target": "celesto_sandbox"}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("VULNFORGE_STATE_DIR", str(tmp_path))
    async with await _client(FakeLabManager()) as client:
        response = await client.get("/api/commands")
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 2
    # Newest first.
    assert rows[0]["decision"] == "block"


@pytest.mark.anyio
async def test_access_code_gate_blocks_and_allows(monkeypatch) -> None:
    monkeypatch.setenv("ACCESS_CODE", "let-me-in")
    async with await _client(FakeLabManager()) as client:
        blocked = await client.post("/api/labs", json={"description": "Build a lab."})
        assert blocked.status_code == 403
        assert blocked.json()["error"]["code"] == "access_code_required"

        allowed = await client.post(
            "/api/labs",
            json={"description": "Build a lab."},
            headers={"X-Access-Code": "let-me-in"},
        )
        assert allowed.status_code == 202


@pytest.mark.anyio
async def test_approve_publish_and_destroy_and_submit_flag_aliases(monkeypatch) -> None:
    monkeypatch.delenv("ACCESS_CODE", raising=False)
    manager = FakeLabManager()
    async with await _client(manager) as client:
        approved = await client.post("/api/labs/run-abc123def456/approve-publish")
        assert approved.status_code == 200
        assert approved.json()["phase"] == "published"

        destroyed = await client.post("/api/labs/run-abc123def456/destroy")
        assert destroyed.status_code == 200
        assert destroyed.json()["phase"] == "cleaned_up"

        flag = await client.post(
            "/api/labs/run-abc123def456/submit-flag", json={"flag": "VF{correct}"}
        )
        assert flag.status_code == 200
        assert flag.json()["correct"] is True
        assert manager.flag_calls == ["VF{correct}"]


# ---- template fallback --------------------------------------------------------


def test_generator_falls_back_to_vetted_template_when_model_cannot_write(monkeypatch) -> None:
    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("src.agent.loop.asyncio.to_thread", inline_to_thread)
    spec = build_variation("fallback-seed", mode="single", vulnerabilities=["sql_injection"])
    writes: list[str] = []

    class Repo:
        def __init__(self) -> None:
            self.index = 0

        async def reserve_llm_request(self, *a, **k):
            self.index += 1
            return {"request_id": self.index}

        async def mark_llm_request_sent(self, *a):
            return None

        async def record_llm_response(self, *a, **k):
            return None

        async def complete_llm_attempt_budget(self, *a):
            return {}

    class NoToolClient:
        def chat(self, *, messages, tools, max_tokens):
            return ProviderResponse(
                model="tiny",
                message={"role": "assistant", "content": "I cannot call tools."},
                prompt_tokens=1,
                completion_tokens=1,
                total_tokens=2,
                headers={},
                status_code=200,
            )

    generator = ChallengeGenerator(
        NoToolClient(),
        Repo(),
        "attempt-0123456789ab",
        lambda source: writes.append(source) or {"ok": True, "bytes": len(source)},
        config=AgentLoopConfig(max_iterations=1, max_tool_calls=1, token_budget=100),
        allow_template_fallback=True,
    )
    result = asyncio.run(generator.generate(spec))
    assert result.llm_fallback_used is True
    assert result.static.passed is True
    assert writes and spec.flag not in writes[0]
