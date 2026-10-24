"""Bounded provider/tool loop with database-backed reservations."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from src.agent.provider import (
    ProviderHTTPError,
    ProviderProtocolError,
    ProviderResponse,
    ProviderTransportError,
)
from src.agent.tools import ToolDispatcher

_RETRYABLE_PROVIDER_STATUSES = {408, 425, 429, 500, 502, 503, 504}
_MAX_PROVIDER_RETRY_DELAY_S = 30


@dataclass(frozen=True)
class AgentLoopConfig:
    max_iterations: int = 20
    max_tool_calls: int = 40
    token_budget: int = 16000
    time_budget_s: float = 600.0
    max_http_attempts: int = 8
    max_retries: int = 2
    request_max_tokens: int = 8192
    max_no_tool_retries: int = 2

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or value < 1
            for value in (
                self.max_iterations,
                self.max_tool_calls,
                self.token_budget,
                self.max_http_attempts,
                self.request_max_tokens,
            )
        ):
            raise ValueError("agent integer budgets must be positive")
        if (
            self.time_budget_s <= 0
            or self.max_retries < 0
            or self.max_no_tool_retries < 0
        ):
            raise ValueError(
                "agent time budget must be positive and retry count non-negative"
            )


@dataclass(frozen=True)
class AgentResult:
    outcome: str
    iterations: int
    tool_calls: int
    token_input: int
    token_output: int
    http_attempts: int
    error: str | None = None


class AgentLoop:
    def __init__(
        self,
        client: Any,
        repository: Any,
        dispatcher: ToolDispatcher,
        attempt_id: str,
        *,
        config: AgentLoopConfig | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        trace: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.client = client
        self.repository = repository
        self.dispatcher = dispatcher
        self.attempt_id = attempt_id
        self.config = config or AgentLoopConfig()
        self.sleep = sleep
        self.clock = clock
        self.trace = trace or (lambda _record: None)

    async def run(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> AgentResult:
        conversation = [dict(message) for message in messages]
        started = self.clock()
        iterations = 0
        tool_calls = 0
        http_attempts = 0
        token_input = 0
        token_output = 0
        retry_index = 0
        no_tool_retries = 0
        write_app_succeeded = False
        error: str | None = None
        outcome = "stopped"
        try:
            while iterations < self.config.max_iterations:
                if self.clock() - started >= self.config.time_budget_s:
                    outcome = "time_budget_exhausted"
                    break
                remaining_tokens = self.config.token_budget - token_input - token_output
                if remaining_tokens <= 0:
                    outcome = "token_budget_exhausted"
                    break
                if http_attempts >= self.config.max_http_attempts:
                    outcome = "http_budget_exhausted"
                    break
                estimated = min(
                    remaining_tokens,
                    max(
                        1,
                        self.config.request_max_tokens + _message_tokens(conversation),
                    ),
                )
                request_id = await self.repository.reserve_llm_request(
                    self.attempt_id, estimated, retry_index=retry_index
                )
                request_key = (
                    request_id.get("request_id")
                    if isinstance(request_id, dict)
                    else request_id
                )
                await self.repository.mark_llm_request_sent(request_key)
                http_attempts += 1
                try:
                    response = await asyncio.to_thread(
                        self.client.chat,
                        messages=conversation,
                        tools=tools,
                        max_tokens=min(
                            self.config.request_max_tokens, remaining_tokens
                        ),
                    )
                except ProviderHTTPError as exc:
                    await self.repository.record_llm_response(
                        request_key,
                        http_status=exc.status_code,
                        headers=exc.headers,
                        input_tokens=0,
                        output_tokens=0,
                        total_tokens=0,
                        error_code=exc.error_code,
                    )
                    self.trace(
                        {
                            "event": "provider_error",
                            "status": exc.status_code,
                            "retry_index": retry_index,
                        }
                    )
                    if (
                        exc.status_code in _RETRYABLE_PROVIDER_STATUSES
                        and retry_index < self.config.max_retries
                        and http_attempts < self.config.max_http_attempts
                    ):
                        delay = exc.retry_after_s or 2**retry_index
                        self.sleep(min(delay, _MAX_PROVIDER_RETRY_DELAY_S))
                        retry_index += 1
                        continue
                    outcome = "provider_error"
                    error = exc.error_code
                    break
                except (ProviderTransportError, ProviderProtocolError) as exc:
                    await self.repository.record_llm_response(
                        request_key,
                        http_status=None,
                        headers={},
                        input_tokens=0,
                        output_tokens=0,
                        total_tokens=0,
                        error_code=type(exc).__name__,
                    )
                    if (
                        isinstance(exc, ProviderTransportError)
                        and retry_index < self.config.max_retries
                        and http_attempts < self.config.max_http_attempts
                    ):
                        self.sleep(min(2**retry_index, _MAX_PROVIDER_RETRY_DELAY_S))
                        retry_index += 1
                        continue
                    outcome = "provider_error"
                    error = type(exc).__name__
                    break
                retry_index = 0
                token_input += response.prompt_tokens
                token_output += response.completion_tokens
                await self.repository.record_llm_response(
                    request_key,
                    http_status=response.status_code,
                    headers=response.headers,
                    input_tokens=response.prompt_tokens,
                    output_tokens=response.completion_tokens,
                    total_tokens=response.total_tokens,
                    response_model=response.model,
                )
                iterations += 1
                conversation.append(_assistant_message(response))
                calls = response.message.get("tool_calls")
                if not isinstance(calls, list) or not calls:
                    if write_app_succeeded:
                        break
                    if no_tool_retries < self.config.max_no_tool_retries:
                        no_tool_retries += 1
                        conversation.append(
                            {
                                "role": "user",
                                "content": (
                                    "No valid app has been written yet. Use the write_app tool now "
                                    "with one complete Python source file that satisfies every "
                                    "fixed route, SQLite, and safety requirement."
                                ),
                            }
                        )
                        continue
                    outcome = "tool_call_missing"
                    break
                for call in calls:
                    if tool_calls >= self.config.max_tool_calls:
                        outcome = "tool_budget_exhausted"
                        break
                    tool_calls += 1
                    result = self.dispatcher.dispatch_call(call)
                    if _is_write_app(call) and result.get("ok") is True:
                        write_app_succeeded = True
                    call_id = (
                        call.get("id", f"call-{tool_calls}")
                        if isinstance(call, dict)
                        else f"call-{tool_calls}"
                    )
                    conversation.append(
                        {
                            "role": "tool",
                            "tool_call_id": str(call_id),
                            "content": json.dumps(
                                result, sort_keys=True, separators=(",", ":")
                            ),
                        }
                    )
                    self.trace(
                        {
                            "event": "tool_call",
                            "tool": "write_app" if _is_write_app(call) else "unknown",
                            "ok": bool(result.get("ok")),
                        }
                    )
                if outcome != "stopped":
                    break
        finally:
            await self.repository.complete_llm_attempt_budget(self.attempt_id)
        return AgentResult(
            outcome,
            iterations,
            tool_calls,
            token_input,
            token_output,
            http_attempts,
            error,
        )


def _assistant_message(response: ProviderResponse) -> dict[str, Any]:
    message = {"role": "assistant", "content": response.message.get("content")}
    if isinstance(response.message.get("tool_calls"), list):
        message["tool_calls"] = response.message["tool_calls"]
    return message


def _message_tokens(messages: list[dict[str, Any]]) -> int:
    return max(
        1, sum(len(str(message.get("content", ""))) for message in messages) // 4
    )


def _is_write_app(call: Any) -> bool:
    return (
        isinstance(call, dict)
        and isinstance(call.get("function"), dict)
        and call["function"].get("name") == "write_app"
    )
