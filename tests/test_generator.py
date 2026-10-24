from __future__ import annotations

import asyncio
import json

from src.agent.loop import AgentLoopConfig
from src.agent.provider import ProviderHTTPError, ProviderResponse
from src.challenge import build_variation
from src.generator import ChallengeGenerationError, ChallengeGenerator

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


class Repo:
    def __init__(self):
        self.index = 0

    async def reserve_llm_request(self, *_args, **_kwargs):
        self.index += 1
        return {"request_id": self.index}

    async def mark_llm_request_sent(self, *_args):
        return None

    async def record_llm_response(self, *_args, **_kwargs):
        return None

    async def complete_llm_attempt_budget(self, *_args):
        return {}


def test_generator_uses_real_tool_call_and_static_checks_before_guest_write(
    monkeypatch,
) -> None:
    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("src.agent.loop.asyncio.to_thread", inline_to_thread)
    spec = build_variation("generator-seed")
    writes = []

    class Client:
        def chat(self, *, messages, tools, max_tokens):
            assert tools[0]["function"]["name"] == "write_app"
            return ProviderResponse(
                model="model",
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

    generator = ChallengeGenerator(
        Client(),
        Repo(),
        "attempt-0123456789ab",
        lambda source: writes.append(source) or {"bytes": len(source)},
        config=AgentLoopConfig(max_iterations=1, max_tool_calls=1, token_budget=100),
    )
    result = asyncio.run(generator.generate(spec))

    assert result.static.passed is True
    assert writes == [SOURCE]
    assert spec.flag not in result.source


def test_generator_retries_a_successful_provider_response_without_tool_call(
    monkeypatch,
) -> None:
    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("src.agent.loop.asyncio.to_thread", inline_to_thread)
    spec = build_variation("generator-retry-seed")
    writes = []
    responses = [
        ProviderResponse(
            model="model",
            message={"role": "assistant", "content": "I will build the app."},
            prompt_tokens=4,
            completion_tokens=3,
            total_tokens=7,
            headers={},
            status_code=200,
        ),
        ProviderResponse(
            model="model",
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
        ),
    ]
    requested_max_tokens = []

    class Client:
        def chat(self, *, messages, tools, max_tokens):
            requested_max_tokens.append(max_tokens)
            return responses[min(len(requested_max_tokens) - 1, len(responses) - 1)]

    generator = ChallengeGenerator(
        Client(),
        Repo(),
        "attempt-0123456789ab",
        lambda source: writes.append(source) or {"bytes": len(source)},
        config=AgentLoopConfig(max_iterations=2, max_tool_calls=2, token_budget=10000),
    )

    result = asyncio.run(generator.generate(spec))

    assert result.static.passed is True
    assert writes == [SOURCE]
    assert requested_max_tokens == [8192, 8192]


def test_generator_failure_is_not_reported_as_provider_outage(monkeypatch) -> None:
    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("src.agent.loop.asyncio.to_thread", inline_to_thread)
    spec = build_variation("generator-no-tool-seed")

    class Client:
        def chat(self, *, messages, tools, max_tokens):
            return ProviderResponse(
                model="model",
                message={"role": "assistant", "content": "I cannot use tools."},
                prompt_tokens=4,
                completion_tokens=3,
                total_tokens=7,
                headers={},
                status_code=200,
            )

    generator = ChallengeGenerator(
        Client(),
        Repo(),
        "attempt-0123456789ab",
        lambda _source: {"bytes": 1},
        config=AgentLoopConfig(max_iterations=1, max_tool_calls=1, token_budget=100),
    )

    try:
        asyncio.run(generator.generate(spec))
    except ChallengeGenerationError as exc:
        assert exc.error_code == "generation_incomplete"
    else:
        raise AssertionError("generation without a write_app tool call must fail")


def test_generator_preserves_provider_http_status_for_dashboard(monkeypatch) -> None:
    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("src.agent.loop.asyncio.to_thread", inline_to_thread)
    spec = build_variation("generator-provider-http-error-seed")

    class Client:
        def chat(self, *, messages, tools, max_tokens):
            raise ProviderHTTPError(403)

    generator = ChallengeGenerator(
        Client(),
        Repo(),
        "attempt-0123456789ab",
        lambda _source: {"bytes": 1},
        config=AgentLoopConfig(
            max_iterations=1,
            max_tool_calls=1,
            token_budget=100,
            max_http_attempts=1,
        ),
    )

    try:
        asyncio.run(generator.generate(spec))
    except ChallengeGenerationError as exc:
        assert exc.error_code == "http_403"
    else:
        raise AssertionError("provider HTTP failures must preserve their status")


def test_generator_does_not_accept_source_when_guarded_write_fails(monkeypatch) -> None:
    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("src.agent.loop.asyncio.to_thread", inline_to_thread)
    spec = build_variation("generator-write-failure-seed")

    class Client:
        def chat(self, *, messages, tools, max_tokens):
            return ProviderResponse(
                model="model",
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

    def fail_write(_source):
        raise RuntimeError("private write failed")

    generator = ChallengeGenerator(
        Client(),
        Repo(),
        "attempt-0123456789ab",
        fail_write,
        config=AgentLoopConfig(max_iterations=1, max_tool_calls=1, token_budget=100),
    )

    try:
        asyncio.run(generator.generate(spec))
    except ChallengeGenerationError as exc:
        assert exc.error_code == "generation_incomplete"
    else:
        raise AssertionError("a failed guarded write must not be reported as generated")
