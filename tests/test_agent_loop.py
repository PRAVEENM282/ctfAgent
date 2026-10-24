from __future__ import annotations

import asyncio
import json

from src.agent.loop import AgentLoop, AgentLoopConfig
from src.agent.provider import (
    ProviderHTTPError,
    ProviderResponse,
    ProviderTransportError,
)
from src.agent.tools import WRITE_APP_TOOL, ToolDispatcher


class FakeRepository:
    def __init__(self) -> None:
        self.reservations = []
        self.sent = []
        self.responses = []
        self.completed = []

    async def reserve_llm_request(self, attempt_id, estimated_tokens, retry_index=0):
        self.reservations.append((attempt_id, estimated_tokens, retry_index))
        return {"request_id": len(self.reservations)}

    async def mark_llm_request_sent(self, request_id):
        self.sent.append(request_id)

    async def record_llm_response(self, request_id, **values):
        self.responses.append((request_id, values))

    async def complete_llm_attempt_budget(self, attempt_id):
        self.completed.append(attempt_id)


def _response(*, tool_calls=None, content=None, prompt=3, completion=2):
    message = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return ProviderResponse(
        model="model",
        message=message,
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=prompt + completion,
        headers={"x-ratelimit-remaining-tokens": "777"},
        status_code=200,
    )


def test_loop_reserves_before_each_post_and_hides_source_in_tool_result(
    monkeypatch,
) -> None:
    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("src.agent.loop.asyncio.to_thread", inline_to_thread)
    repository = FakeRepository()
    calls = []
    source = """import http.server
import sqlite3

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/search") and "q" in self.path:
            sqlite3.connect("/root/app.db").execute("SELECT value FROM secrets")
        self.send_response(200)
        self.end_headers()

# synthetic source without embedded expected value
"""

    class Client:
        def chat(self, *, messages, tools, max_tokens):
            calls.append(messages)
            if len(calls) == 1:
                return _response(
                    tool_calls=[
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "write_app",
                                "arguments": json.dumps({"source": source}),
                            },
                        }
                    ]
                )
            return _response(content="done")

    written = []
    dispatcher = ToolDispatcher(
        lambda app_source: written.append(app_source) or {"bytes": len(app_source)}
    )
    loop = AgentLoop(
        Client(),
        repository,
        dispatcher,
        "attempt-0123456789ab",
        config=AgentLoopConfig(max_iterations=3, max_tool_calls=2, token_budget=100),
        sleep=lambda _seconds: None,
    )

    result = asyncio.run(
        loop.run([{"role": "user", "content": "build the app"}], [WRITE_APP_TOOL])
    )

    assert result.outcome == "stopped"
    assert written == [source]
    assert len(repository.reservations) == 2
    assert repository.reservations[0][2] == 0
    assert all(
        source not in (message.get("content") or "")
        for messages in calls
        for message in messages[1:]
    )
    assert (
        repository.responses[0][1]["headers"]["x-ratelimit-remaining-tokens"] == "777"
    )
    assert repository.completed == ["attempt-0123456789ab"]


def test_loop_retries_only_429_and_reserves_retry(monkeypatch) -> None:
    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("src.agent.loop.asyncio.to_thread", inline_to_thread)
    repository = FakeRepository()
    calls = []

    class Client:
        def chat(self, **_kwargs):
            calls.append(True)
            if len(calls) == 1:
                raise ProviderHTTPError(429, retry_after_s=0, headers={})
            return _response(content="done")

    loop = AgentLoop(
        Client(),
        repository,
        ToolDispatcher(lambda _source: {}),
        "attempt-0123456789ab",
        config=AgentLoopConfig(
            max_iterations=2,
            max_tool_calls=1,
            max_retries=1,
            max_no_tool_retries=0,
            token_budget=100,
        ),
        sleep=lambda _seconds: None,
    )

    result = asyncio.run(
        loop.run([{"role": "user", "content": "build"}], [WRITE_APP_TOOL])
    )

    assert result.outcome == "tool_call_missing"
    assert len(calls) == 2
    assert [item[2] for item in repository.reservations] == [0, 1]
    assert repository.responses[0][1]["http_status"] == 429


def test_loop_retries_transient_provider_503_with_backoff(monkeypatch) -> None:
    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("src.agent.loop.asyncio.to_thread", inline_to_thread)
    repository = FakeRepository()
    calls = []
    waits = []

    class Client:
        def chat(self, **_kwargs):
            calls.append(True)
            if len(calls) == 1:
                raise ProviderHTTPError(503, headers={})
            return _response(
                tool_calls=[
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "write_app",
                            "arguments": json.dumps({"source": "source"}),
                        },
                    }
                ]
            )

    loop = AgentLoop(
        Client(),
        repository,
        ToolDispatcher(lambda source: {"bytes": len(source)}),
        "attempt-0123456789ab",
        config=AgentLoopConfig(
            max_iterations=2,
            max_tool_calls=1,
            max_retries=1,
            token_budget=100,
        ),
        sleep=waits.append,
    )

    result = asyncio.run(
        loop.run([{"role": "user", "content": "build"}], [WRITE_APP_TOOL])
    )

    assert result.outcome == "tool_budget_exhausted"
    assert len(calls) == 3
    assert waits == [1]
    assert [item[2] for item in repository.reservations] == [0, 1, 0]
    assert repository.responses[0][1]["http_status"] == 503


def test_loop_retries_transient_provider_transport_error(monkeypatch) -> None:
    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr("src.agent.loop.asyncio.to_thread", inline_to_thread)
    repository = FakeRepository()
    calls = []
    waits = []

    class Client:
        def chat(self, **_kwargs):
            calls.append(True)
            if len(calls) == 1:
                raise ProviderTransportError("provider transport failed (TimeoutError)")
            return _response(
                tool_calls=[
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "write_app",
                            "arguments": json.dumps({"source": "source"}),
                        },
                    }
                ]
            )

    loop = AgentLoop(
        Client(),
        repository,
        ToolDispatcher(lambda source: {"bytes": len(source)}),
        "attempt-0123456789ab",
        config=AgentLoopConfig(
            max_iterations=2,
            max_tool_calls=1,
            max_retries=1,
            token_budget=100,
        ),
        sleep=waits.append,
    )

    result = asyncio.run(
        loop.run([{"role": "user", "content": "build"}], [WRITE_APP_TOOL])
    )

    assert result.outcome == "tool_budget_exhausted"
    assert len(calls) == 3
    assert waits == [1]
    assert [item[2] for item in repository.reservations] == [0, 1, 0]
