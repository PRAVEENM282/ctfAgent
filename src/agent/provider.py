"""Small OpenAI-compatible client with safe error and header handling."""

from __future__ import annotations

import json
import math
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

Transport = Callable[
    [str, dict[str, str], bytes, float], tuple[int, Mapping[str, str], bytes]
]


@dataclass(frozen=True)
class ProviderConfig:
    base_url: str
    api_key: str
    model: str
    timeout_s: float = 90.0
    max_retry_after_s: float = 30.0
    user_agent: str = "VulnForge/1.0"
    api_key_header: str = "Authorization"
    api_key_prefix: str = "Bearer "


@dataclass(frozen=True)
class ProviderResponse:
    model: str | None
    message: dict[str, Any]
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    headers: dict[str, str]
    status_code: int


class ProviderHTTPError(RuntimeError):
    """A provider HTTP response that was not accepted."""

    def __init__(
        self,
        status_code: int,
        *,
        retry_after_s: float = 0.0,
        headers: Mapping[str, str] | None = None,
        error_code: str | None = None,
    ) -> None:
        self.status_code = int(status_code)
        self.retry_after_s = max(0.0, float(retry_after_s))
        self.headers = _safe_headers(headers or {})
        self.error_code = error_code or f"http_{self.status_code}"
        super().__init__(f"provider HTTP status {self.status_code}")


class ProviderTransportError(RuntimeError):
    """A network failure without provider response content."""


class ProviderProtocolError(RuntimeError):
    """A provider returned a malformed response."""


class ProviderConfigurationError(RuntimeError):
    """Provider environment configuration is missing or unusable."""


@dataclass(frozen=True)
class ProviderSettings:
    provider: str
    base_url: str
    api_key: str
    model: str
    api_key_header: str = "Authorization"
    api_key_prefix: str = "Bearer "
    api_format: str = "openai-chat-completions"
    timeout_s: float = 90.0

    @property
    def config(self) -> ProviderConfig:
        return ProviderConfig(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            timeout_s=self.timeout_s,
            api_key_header=self.api_key_header,
            api_key_prefix=self.api_key_prefix,
        )


class OpenAICompatibleClient:
    def __init__(
        self, config: ProviderConfig, *, transport: Transport | None = None
    ) -> None:
        if (
            not config.base_url.strip()
            or not config.api_key
            or not config.model.strip()
        ):
            raise ValueError("provider base_url, api_key, and model are required")
        if not _valid_header_name(config.api_key_header):
            raise ValueError("provider api_key_header is invalid")
        if any(char in config.api_key for char in "\r\n") or any(
            char in config.api_key_prefix for char in "\r\n"
        ):
            raise ValueError(
                "provider API key authentication contains invalid characters"
            )
        parsed_base = urlsplit(config.base_url)
        if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
            raise ValueError("provider base_url must be an absolute HTTP(S) URL")
        if config.timeout_s <= 0 or config.max_retry_after_s < 0:
            raise ValueError(
                "provider timeouts must be positive and retry cap non-negative"
            )
        self.config = config
        self._transport = transport or _urlopen_transport

    @property
    def endpoint(self) -> str:
        parsed = urlsplit(self.config.base_url)
        path = parsed.path.rstrip("/")
        if not path.endswith("/chat/completions"):
            path = f"{path}/chat/completions"
        return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))

    def chat(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
    ) -> ProviderResponse:
        if (
            isinstance(max_tokens, bool)
            or not isinstance(max_tokens, int)
            or max_tokens < 1
        ):
            raise ValueError("max_tokens must be a positive integer")
        body = json.dumps(
            {
                "model": self.config.model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto" if tools else "none",
                "temperature": 0,
                "max_tokens": max_tokens,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {
            self.config.api_key_header: f"{self.config.api_key_prefix}{self.config.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self.config.user_agent,
        }
        try:
            status_code, response_headers, response_body = self._transport(
                self.endpoint, headers, body, self.config.timeout_s
            )
        except ProviderHTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderTransportError(
                f"provider transport failed ({type(exc).__name__})"
            ) from None

        safe_headers = _safe_headers(response_headers)
        if status_code == 429:
            raise ProviderHTTPError(
                status_code,
                retry_after_s=parse_retry_after(
                    response_headers.get("Retry-After")
                    or response_headers.get("retry-after"),
                    self.config.max_retry_after_s,
                ),
                headers=safe_headers,
                error_code="rate_limited",
            )
        if status_code < 200 or status_code >= 300:
            raise ProviderHTTPError(
                status_code, headers=safe_headers, error_code=f"http_{status_code}"
            )
        try:
            payload = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderProtocolError("provider returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ProviderProtocolError("provider response must be an object")
        choices = payload.get("choices")
        if (
            not isinstance(choices, list)
            or not choices
            or not isinstance(choices[0], dict)
        ):
            raise ProviderProtocolError("provider response omitted choices")
        message = choices[0].get("message")
        if not isinstance(message, dict):
            raise ProviderProtocolError("provider response omitted assistant message")
        usage = payload.get("usage") or {}
        if not isinstance(usage, dict):
            raise ProviderProtocolError("provider usage must be an object")
        prompt = _usage_int(usage, "prompt_tokens", "input_tokens")
        completion = _usage_int(usage, "completion_tokens", "output_tokens")
        total_value = usage.get("total_tokens")
        total = (
            _nonnegative_int(total_value, "total_tokens")
            if total_value is not None
            else prompt + completion
        )
        if total < prompt + completion:
            raise ProviderProtocolError("provider total token usage is inconsistent")
        return ProviderResponse(
            model=payload.get("model")
            if isinstance(payload.get("model"), str)
            else None,
            message=message,
            prompt_tokens=prompt,
            completion_tokens=completion,
            total_tokens=total,
            headers=safe_headers,
            status_code=int(status_code),
        )


class AnthropicMessagesClient(OpenAICompatibleClient):
    """Adapter for Anthropic Messages API, translated to the agent's common shape."""

    @property
    def endpoint(self) -> str:
        parsed = urlsplit(self.config.base_url)
        path = parsed.path.rstrip("/")
        if not path.endswith("/messages"):
            path = f"{path}/messages" if path.endswith("/v1") else f"{path}/v1/messages"
        return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))

    def chat(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
    ) -> ProviderResponse:
        if (
            isinstance(max_tokens, bool)
            or not isinstance(max_tokens, int)
            or max_tokens < 1
        ):
            raise ValueError("max_tokens must be a positive integer")
        system, native_messages = _anthropic_messages(messages)
        body: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": max_tokens,
            "messages": native_messages,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = [_anthropic_tool(tool) for tool in tools]
            body["tool_choice"] = {"type": "auto"}
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {
            self.config.api_key_header: f"{self.config.api_key_prefix}{self.config.api_key}",
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self.config.user_agent,
        }
        try:
            status_code, response_headers, response_body = self._transport(
                self.endpoint, headers, encoded, self.config.timeout_s
            )
        except ProviderHTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderTransportError(
                f"provider transport failed ({type(exc).__name__})"
            ) from None
        safe_headers = _safe_headers(response_headers)
        if status_code == 429:
            raise ProviderHTTPError(
                status_code,
                retry_after_s=parse_retry_after(
                    response_headers.get("Retry-After")
                    or response_headers.get("retry-after"),
                    self.config.max_retry_after_s,
                ),
                headers=safe_headers,
                error_code="rate_limited",
            )
        if status_code < 200 or status_code >= 300:
            raise ProviderHTTPError(status_code, headers=safe_headers)
        try:
            payload = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderProtocolError("provider returned invalid JSON") from exc
        if not isinstance(payload, dict) or not isinstance(
            payload.get("content"), list
        ):
            raise ProviderProtocolError("Anthropic response omitted content blocks")
        text_blocks: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for block in payload["content"]:
            if not isinstance(block, dict):
                raise ProviderProtocolError("Anthropic content block must be an object")
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                text_blocks.append(block["text"])
            elif block.get("type") == "tool_use":
                if not all(isinstance(block.get(key), str) for key in ("id", "name")):
                    raise ProviderProtocolError(
                        "Anthropic tool call omitted id or name"
                    )
                arguments = block.get("input")
                if not isinstance(arguments, dict):
                    raise ProviderProtocolError(
                        "Anthropic tool input must be an object"
                    )
                tool_calls.append(
                    {
                        "id": block["id"],
                        "type": "function",
                        "function": {
                            "name": block["name"],
                            "arguments": json.dumps(arguments, separators=(",", ":")),
                        },
                    }
                )
        usage = payload.get("usage") or {}
        if not isinstance(usage, dict):
            raise ProviderProtocolError("Anthropic usage must be an object")
        prompt = _usage_int(usage, "input_tokens", "prompt_tokens")
        completion = _usage_int(usage, "output_tokens", "completion_tokens")
        message: dict[str, Any] = {
            "role": "assistant",
            "content": "\n".join(text_blocks) or None,
        }
        if tool_calls:
            message["tool_calls"] = tool_calls
        return ProviderResponse(
            model=payload.get("model")
            if isinstance(payload.get("model"), str)
            else None,
            message=message,
            prompt_tokens=prompt,
            completion_tokens=completion,
            total_tokens=prompt + completion,
            headers=safe_headers,
            status_code=int(status_code),
        )


class BedrockConverseClient(OpenAICompatibleClient):
    """Adapter for Amazon Bedrock Converse, including Nova Micro tool calls."""

    @property
    def endpoint(self) -> str:
        parsed = urlsplit(self.config.base_url)
        path = parsed.path.rstrip("/")
        if not path.endswith("/converse"):
            model_id = quote(self.config.model, safe=".:/-")
            path = f"{path}/model/{model_id}/converse"
        return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))

    def chat(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
    ) -> ProviderResponse:
        if (
            isinstance(max_tokens, bool)
            or not isinstance(max_tokens, int)
            or max_tokens < 1
        ):
            raise ValueError("max_tokens must be a positive integer")
        is_nova = "nova" in self.config.model.lower()
        if "nova-micro-v1" in self.config.model.lower():
            max_tokens = min(max_tokens, 5000)
        system, native_messages = _bedrock_messages(messages)
        body: dict[str, Any] = {
            "messages": native_messages,
            "inferenceConfig": {"maxTokens": max_tokens, "temperature": 0.00001},
        }
        if system:
            body["system"] = [{"text": part} for part in system]
        if tools:
            body["toolConfig"] = {
                "tools": [
                    _bedrock_tool(
                        tool,
                        nova_schema=is_nova,
                    )
                    for tool in tools
                ],
                "toolChoice": {"any" if is_nova else "auto": {}},
            }
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {
            self.config.api_key_header: f"{self.config.api_key_prefix}{self.config.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self.config.user_agent,
        }
        try:
            status_code, response_headers, response_body = self._transport(
                self.endpoint, headers, encoded, self.config.timeout_s
            )
        except ProviderHTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderTransportError(
                f"provider transport failed ({type(exc).__name__})"
            ) from None
        safe_headers = _safe_headers(response_headers)
        if status_code == 429:
            raise ProviderHTTPError(
                status_code,
                retry_after_s=parse_retry_after(
                    response_headers.get("Retry-After")
                    or response_headers.get("retry-after"),
                    self.config.max_retry_after_s,
                ),
                headers=safe_headers,
                error_code="rate_limited",
            )
        if status_code < 200 or status_code >= 300:
            raise ProviderHTTPError(status_code, headers=safe_headers)
        try:
            payload = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderProtocolError("provider returned invalid JSON") from exc
        output = payload.get("output") if isinstance(payload, dict) else None
        message = output.get("message") if isinstance(output, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            raise ProviderProtocolError(
                "Bedrock Converse response omitted message content"
            )
        text_blocks: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for block in content:
            if not isinstance(block, dict):
                raise ProviderProtocolError("Bedrock content block must be an object")
            if isinstance(block.get("text"), str):
                text_blocks.append(block["text"])
            elif isinstance(block.get("toolUse"), dict):
                tool_use = block["toolUse"]
                if not all(
                    isinstance(tool_use.get(key), str) for key in ("toolUseId", "name")
                ):
                    raise ProviderProtocolError("Bedrock tool call omitted id or name")
                arguments = tool_use.get("input")
                if not isinstance(arguments, dict):
                    raise ProviderProtocolError("Bedrock tool input must be an object")
                tool_calls.append(
                    {
                        "id": tool_use["toolUseId"],
                        "type": "function",
                        "function": {
                            "name": tool_use["name"],
                            "arguments": json.dumps(arguments, separators=(",", ":")),
                        },
                    }
                )
        usage = payload.get("usage") or {}
        if not isinstance(usage, dict):
            raise ProviderProtocolError("Bedrock usage must be an object")
        prompt = _usage_int(usage, "inputTokens", "input_tokens")
        completion = _usage_int(usage, "outputTokens", "output_tokens")
        common_message: dict[str, Any] = {
            "role": "assistant",
            "content": "\n".join(text_blocks) or None,
        }
        if tool_calls:
            common_message["tool_calls"] = tool_calls
        return ProviderResponse(
            model=self.config.model,
            message=common_message,
            prompt_tokens=prompt,
            completion_tokens=completion,
            total_tokens=prompt + completion,
            headers=safe_headers,
            status_code=int(status_code),
        )


def provider_client_from_settings(settings: ProviderSettings) -> OpenAICompatibleClient:
    if settings.api_format.lower() in {"anthropic", "anthropic-messages", "messages"}:
        return AnthropicMessagesClient(settings.config)
    if settings.api_format.lower() in {"bedrock-converse", "converse"}:
        return BedrockConverseClient(settings.config)
    if settings.api_format.lower() not in {
        "openai",
        "openai-compatible",
        "openai-chat-completions",
        "chat-completions",
    }:
        raise ProviderConfigurationError("provider API format is unsupported")
    return OpenAICompatibleClient(settings.config)


def _anthropic_tool(tool: dict[str, Any]) -> dict[str, Any]:
    function = tool.get("function") if isinstance(tool, dict) else None
    if not isinstance(function, dict) or not isinstance(function.get("name"), str):
        raise ProviderProtocolError("tool definition is invalid")
    schema = function.get("parameters")
    if not isinstance(schema, dict):
        raise ProviderProtocolError("tool input schema is invalid")
    result: dict[str, Any] = {
        "name": function["name"],
        "input_schema": schema,
    }
    if isinstance(function.get("description"), str):
        result["description"] = function["description"]
    return result


def _bedrock_tool(tool: dict[str, Any], *, nova_schema: bool = False) -> dict[str, Any]:
    function = tool.get("function") if isinstance(tool, dict) else None
    if not isinstance(function, dict) or not isinstance(function.get("name"), str):
        raise ProviderProtocolError("tool definition is invalid")
    schema = function.get("parameters")
    if not isinstance(schema, dict):
        raise ProviderProtocolError("tool input schema is invalid")
    if nova_schema:
        schema = {
            key: value
            for key, value in schema.items()
            if key in {"type", "properties", "required"}
        }
        schema = _strip_nova_constraints(schema)
    spec: dict[str, Any] = {"name": function["name"], "inputSchema": {"json": schema}}
    if isinstance(function.get("description"), str):
        spec["description"] = function["description"]
    return {"toolSpec": spec}


def _strip_nova_constraints(value: Any) -> Any:
    """Remove JSON Schema keywords unsupported by Nova tool definitions."""
    if isinstance(value, list):
        return [_strip_nova_constraints(item) for item in value]
    if not isinstance(value, dict):
        return value
    unsupported = {"additionalProperties", "minLength", "maxLength"}
    return {
        key: _strip_nova_constraints(item)
        for key, item in value.items()
        if key not in unsupported
    }


def _bedrock_messages(
    messages: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, Any]]]:
    system: list[str] = []
    output: list[dict[str, Any]] = []
    for message in messages:
        role = message.get("role")
        content = message.get("content")
        if role == "system":
            if isinstance(content, str):
                system.append(content)
            continue
        if role == "tool":
            status = "success"
            try:
                result = json.loads(content) if isinstance(content, str) else {}
                if isinstance(result, dict) and result.get("ok") is False:
                    status = "error"
            except json.JSONDecodeError:
                pass
            _append_bedrock_message(
                output,
                "user",
                {
                    "toolResult": {
                        "toolUseId": str(message.get("tool_call_id", "")),
                        "content": [{"text": str(content or "")}],
                        "status": status,
                    }
                },
            )
            continue
        if role not in {"user", "assistant"}:
            raise ProviderProtocolError("conversation contains an unsupported role")
        blocks: list[dict[str, Any]] = []
        if isinstance(content, str) and content:
            blocks.append({"text": content})
        calls = message.get("tool_calls")
        if role == "assistant" and isinstance(calls, list):
            for call in calls:
                if not isinstance(call, dict) or not isinstance(
                    call.get("function"), dict
                ):
                    raise ProviderProtocolError("assistant tool call is invalid")
                function = call["function"]
                try:
                    arguments = json.loads(function.get("arguments", "{}"))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ProviderProtocolError(
                        "assistant tool arguments are invalid"
                    ) from exc
                if not isinstance(arguments, dict):
                    raise ProviderProtocolError(
                        "assistant tool arguments must be an object"
                    )
                blocks.append(
                    {
                        "toolUse": {
                            "toolUseId": str(call.get("id", "")),
                            "name": str(function.get("name", "")),
                            "input": arguments,
                        }
                    }
                )
        if not blocks:
            blocks.append({"text": ""})
        _append_bedrock_message(output, role, *blocks)
    return system, output


def _append_bedrock_message(
    messages: list[dict[str, Any]], role: str, *blocks: dict[str, Any]
) -> None:
    if messages and messages[-1]["role"] == role:
        messages[-1]["content"].extend(blocks)
    else:
        messages.append({"role": role, "content": list(blocks)})


def _anthropic_messages(
    messages: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    system_parts: list[str] = []
    output: list[dict[str, Any]] = []
    for message in messages:
        role = message.get("role")
        content = message.get("content")
        if role == "system":
            if isinstance(content, str):
                system_parts.append(content)
            continue
        if role == "tool":
            result = {
                "type": "tool_result",
                "tool_use_id": str(message.get("tool_call_id", "")),
                "content": str(content or ""),
            }
            _append_anthropic_message(output, "user", result)
            continue
        if role not in {"user", "assistant"}:
            raise ProviderProtocolError("conversation contains an unsupported role")
        blocks: list[dict[str, Any]] = []
        if isinstance(content, str) and content:
            blocks.append({"type": "text", "text": content})
        calls = message.get("tool_calls")
        if role == "assistant" and isinstance(calls, list):
            for call in calls:
                if not isinstance(call, dict) or not isinstance(
                    call.get("function"), dict
                ):
                    raise ProviderProtocolError("assistant tool call is invalid")
                function = call["function"]
                try:
                    arguments = json.loads(function.get("arguments", "{}"))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ProviderProtocolError(
                        "assistant tool arguments are invalid"
                    ) from exc
                if not isinstance(arguments, dict):
                    raise ProviderProtocolError(
                        "assistant tool arguments must be an object"
                    )
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": str(call.get("id", "")),
                        "name": str(function.get("name", "")),
                        "input": arguments,
                    }
                )
        if not blocks:
            blocks.append({"type": "text", "text": ""})
        _append_anthropic_message(output, role, *blocks)
    return "\n\n".join(system_parts), output


def _append_anthropic_message(
    messages: list[dict[str, Any]], role: str, *blocks: dict[str, Any]
) -> None:
    if messages and messages[-1]["role"] == role:
        messages[-1]["content"].extend(blocks)
    else:
        messages.append({"role": role, "content": list(blocks)})


def provider_config_from_environment() -> ProviderSettings:
    configured_provider = os.getenv("LLM_PROVIDER", "").strip()
    has_bedrock_alias = any(
        _first_configured_environment_value(name)
        for name in ("BEDROCK_BASE_URL", "BEDROCK_API_KEY", "BEDROCK_MODEL")
    )
    provider = configured_provider or ("bedrock" if has_bedrock_alias else "openai")
    base_url = _first_configured_environment_value("LLM_BASE_URL")
    api_key = _first_configured_environment_value("LLM_API_KEY")
    model = _first_configured_environment_value("LLM_MODEL")
    if provider.lower() == "bedrock":
        base_url = base_url or _first_configured_environment_value("BEDROCK_BASE_URL")
        api_key = api_key or _first_configured_environment_value("BEDROCK_API_KEY")
        model = model or _first_configured_environment_value("BEDROCK_MODEL")
    api_format = os.getenv("LLM_API_FORMAT", "").strip().lower()
    if not api_format:
        if provider.lower() == "anthropic":
            api_format = "anthropic-messages"
        elif provider.lower() == "bedrock" and model.lower().endswith(
            "nova-micro-v1:0"
        ):
            api_format = "bedrock-converse"
        else:
            api_format = "openai-compatible"
    if provider.lower() == "anthropic":
        base_url = base_url or "https://api.anthropic.com/v1"
    if not base_url or not api_key or not model:
        raise ProviderConfigurationError("provider configuration is incomplete")
    default_header, default_prefix = {
        "azure": ("api-key", ""),
        "anthropic": ("x-api-key", ""),
    }.get(provider.lower(), ("Authorization", "Bearer "))
    header = os.getenv("LLM_API_KEY_HEADER", default_header).strip() or default_header
    configured_prefix = os.getenv("LLM_API_KEY_PREFIX")
    prefix = (
        ""
        if configured_prefix is not None and configured_prefix.strip().lower() == "none"
        else configured_prefix or default_prefix
    )
    if not _valid_header_name(header):
        raise ProviderConfigurationError("provider API key header is invalid")
    if any(char in prefix for char in "\r\n"):
        raise ProviderConfigurationError("provider API key prefix is invalid")
    try:
        timeout_s = float(os.getenv("LLM_TIMEOUT_SECONDS", "90"))
    except ValueError as exc:
        raise ProviderConfigurationError(
            "provider timeout must be a positive number of seconds"
        ) from exc
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise ProviderConfigurationError(
            "provider timeout must be a positive number of seconds"
        )
    return ProviderSettings(
        provider, base_url, api_key, model, header, prefix, api_format, timeout_s
    )


def _valid_header_name(value: str) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", value) is not None
        and value.lower() not in {"accept", "content-type", "host", "user-agent"}
    )


def _first_configured_environment_value(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value and not value.startswith("replace-"):
            return value
    return ""


def _urlopen_transport(
    url: str, headers: dict[str, str], body: bytes, timeout: float
) -> tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as exc:
        # Read and discard the body. Provider bodies may contain secrets or private reasoning.
        try:
            exc.read()
        except OSError:
            pass
        return int(exc.code), dict(exc.headers.items()), b""


def _safe_headers(headers: Mapping[str, str]) -> dict[str, str]:
    allowed = {"content-type", "retry-after"}
    safe: dict[str, str] = {}
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered in allowed or lowered.startswith("x-ratelimit-"):
            safe[lowered] = str(value)[:200]
    return safe


def parse_retry_after(value: str | None, maximum: float) -> float:
    if not value:
        return 0.0
    try:
        seconds = float(value.strip())
    except (TypeError, ValueError):
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            seconds = (parsed - datetime.now(UTC)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return 0.0
    if not math.isfinite(seconds):
        return 0.0
    return max(0.0, min(float(maximum), seconds))


def _usage_int(usage: Mapping[str, Any], *names: str) -> int:
    for name in names:
        if name in usage:
            return _nonnegative_int(usage[name], name)
    raise ProviderProtocolError(f"provider response omitted {names[0]}")


def _nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProviderProtocolError(f"provider {name} must be a non-negative integer")
    return value
