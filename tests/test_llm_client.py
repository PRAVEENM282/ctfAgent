from __future__ import annotations

import json

import pytest

from src.agent.provider import (
    AnthropicMessagesClient,
    BedrockConverseClient,
    OpenAICompatibleClient,
    ProviderConfig,
    ProviderConfigurationError,
    ProviderHTTPError,
    ProviderSettings,
    parse_retry_after,
    provider_client_from_settings,
    provider_config_from_environment,
)


def test_provider_client_builds_chat_request_and_parses_usage_and_headers() -> None:
    seen = {}

    def transport(url, headers, body, timeout):
        seen.update(url=url, headers=headers, body=json.loads(body), timeout=timeout)
        return (
            200,
            {
                "content-type": "application/json",
                "x-ratelimit-remaining-requests": "999",
                "x-ratelimit-remaining-tokens": "1234",
                "authorization": "should-not-be-kept",
            },
            json.dumps(
                {
                    "id": "chatcmpl-1",
                    "model": "openai/gpt-oss-120b",
                    "choices": [
                        {"index": 0, "message": {"role": "assistant", "content": "OK"}}
                    ],
                    "usage": {
                        "prompt_tokens": 4,
                        "completion_tokens": 2,
                        "total_tokens": 6,
                    },
                }
            ).encode(),
        )

    client = OpenAICompatibleClient(
        ProviderConfig(
            base_url="https://api.example/v1",
            api_key="secret-key",
            model="openai/gpt-oss-120b",
            timeout_s=7,
        ),
        transport=transport,
    )
    response = client.chat(
        messages=[{"role": "user", "content": "hello"}],
        tools=[],
        max_tokens=16,
    )

    assert seen["url"] == "https://api.example/v1/chat/completions"
    assert seen["headers"]["Authorization"] == "Bearer secret-key"
    assert seen["body"]["model"] == "openai/gpt-oss-120b"
    assert response.prompt_tokens == 4
    assert response.completion_tokens == 2
    assert response.total_tokens == 6
    assert response.headers == {
        "content-type": "application/json",
        "x-ratelimit-remaining-requests": "999",
        "x-ratelimit-remaining-tokens": "1234",
    }


def test_anthropic_messages_adapter_maps_tools_history_and_response() -> None:
    seen = {}

    def transport(url, headers, body, timeout):
        seen.update(url=url, headers=headers, body=json.loads(body))
        return (
            200,
            {},
            json.dumps(
                {
                    "model": "claude-test",
                    "content": [
                        {"type": "text", "text": "Writing app."},
                        {
                            "type": "tool_use",
                            "id": "tool-1",
                            "name": "write_app",
                            "input": {"source": "print('ok')"},
                        },
                    ],
                    "usage": {"input_tokens": 18, "output_tokens": 7},
                }
            ).encode(),
        )

    client = AnthropicMessagesClient(
        ProviderConfig(
            "https://api.anthropic.com/v1",
            "anthropic-key",
            "claude-test",
            api_key_header="x-api-key",
            api_key_prefix="",
        ),
        transport=transport,
    )
    response = client.chat(
        messages=[
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "build it"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "previous-tool",
                        "type": "function",
                        "function": {"name": "write_app", "arguments": "{}"},
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "previous-tool",
                "content": '{"ok":true}',
            },
        ],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "write_app",
                    "description": "write source",
                    "parameters": {
                        "type": "object",
                        "properties": {"source": {"type": "string"}},
                    },
                },
            }
        ],
        max_tokens=8000,
    )

    assert seen["url"] == "https://api.anthropic.com/v1/messages"
    assert seen["headers"]["x-api-key"] == "anthropic-key"
    assert seen["headers"]["anthropic-version"]
    assert seen["body"]["system"] == "system prompt"
    assert seen["body"]["max_tokens"] == 8000
    assert seen["body"]["tools"][0]["input_schema"]["type"] == "object"
    assert seen["body"]["messages"][1]["content"][0]["type"] == "tool_use"
    assert seen["body"]["messages"][2]["content"][0]["tool_use_id"] == "previous-tool"
    assert response.message["tool_calls"][0]["function"]["name"] == "write_app"
    assert response.prompt_tokens == 18
    assert response.completion_tokens == 7


def test_bedrock_converse_adapter_maps_tools_history_and_response() -> None:
    seen = {}

    def transport(url, headers, body, timeout):
        seen.update(url=url, headers=headers, body=json.loads(body))
        return (
            200,
            {},
            json.dumps(
                {
                    "output": {
                        "message": {
                            "role": "assistant",
                            "content": [
                                {"text": "Writing app."},
                                {
                                    "toolUse": {
                                        "toolUseId": "tool-2",
                                        "name": "write_app",
                                        "input": {"source": "print('ok')"},
                                    }
                                },
                            ],
                        }
                    },
                    "usage": {"inputTokens": 12, "outputTokens": 5},
                }
            ).encode(),
        )

    client = BedrockConverseClient(
        ProviderConfig(
            "https://bedrock-runtime.us-east-1.amazonaws.com",
            "bedrock-key",
            "amazon.nova-micro-v1:0",
        ),
        transport=transport,
    )
    response = client.chat(
        messages=[
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "build it"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "previous-tool",
                        "type": "function",
                        "function": {"name": "write_app", "arguments": "{}"},
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "previous-tool",
                "content": '{"ok":true}',
            },
        ],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "write_app",
                    "description": "write source",
                    "parameters": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "source": {
                                "type": "string",
                                "minLength": 100,
                                "maxLength": 6000,
                                "description": "Generated source",
                            }
                        },
                        "required": ["source"],
                    },
                },
            }
        ],
        max_tokens=8000,
    )

    assert seen["url"] == (
        "https://bedrock-runtime.us-east-1.amazonaws.com/"
        "model/amazon.nova-micro-v1:0/converse"
    )
    assert seen["headers"]["Authorization"] == "Bearer bedrock-key"
    assert seen["body"]["system"] == [{"text": "system prompt"}]
    assert seen["body"]["inferenceConfig"]["maxTokens"] == 5000
    assert seen["body"]["toolConfig"]["toolChoice"] == {"any": {}}
    schema = seen["body"]["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]
    assert schema == {
        "type": "object",
        "properties": {
            "source": {
                "type": "string",
                "description": "Generated source",
            }
        },
        "required": ["source"],
    }
    assert (
        seen["body"]["messages"][1]["content"][0]["toolUse"]["toolUseId"]
        == "previous-tool"
    )
    assert (
        seen["body"]["messages"][2]["content"][0]["toolResult"]["toolUseId"]
        == "previous-tool"
    )
    assert response.message["tool_calls"][0]["function"]["name"] == "write_app"
    assert response.prompt_tokens == 12
    assert response.completion_tokens == 5


def test_provider_client_supports_azure_api_key_header_and_openai_v1_endpoint() -> None:
    seen = {}

    def transport(url, headers, body, timeout):
        seen.update(url=url, headers=headers)
        return (
            200,
            {},
            json.dumps(
                {
                    "choices": [{"message": {"role": "assistant", "content": "OK"}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                }
            ).encode(),
        )

    client = OpenAICompatibleClient(
        ProviderConfig(
            base_url="https://resource.openai.azure.com/openai/v1/",
            api_key="azure-test-key",
            model="my-deployment",
            api_key_header="api-key",
            api_key_prefix="",
        ),
        transport=transport,
    )

    client.chat(messages=[{"role": "user", "content": "hello"}], tools=[], max_tokens=8)

    assert seen["url"] == "https://resource.openai.azure.com/openai/v1/chat/completions"
    assert seen["headers"]["api-key"] == "azure-test-key"
    assert "Authorization" not in seen["headers"]


def test_provider_client_raises_bounded_retry_after_for_429() -> None:
    def transport(_url, _headers, _body, _timeout):
        return 429, {"Retry-After": "999"}, b'{"error":{"message":"slow down"}}'

    client = OpenAICompatibleClient(
        ProviderConfig(
            base_url="https://api.example/v1",
            api_key="secret-key",
            model="model",
            max_retry_after_s=12,
        ),
        transport=transport,
    )

    with pytest.raises(ProviderHTTPError) as caught:
        client.chat(messages=[], tools=[], max_tokens=8)

    assert caught.value.status_code == 429
    assert caught.value.retry_after_s == 12
    assert "slow down" not in str(caught.value)


def test_parse_retry_after_rejects_unbounded_or_invalid_values() -> None:
    assert parse_retry_after("4", 10) == 4
    assert parse_retry_after("999", 10) == 10
    assert parse_retry_after("invalid", 10) == 0


def test_provider_config_from_environment_supports_bedrock_aliases(monkeypatch) -> None:
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("BEDROCK_BASE_URL", "https://bedrock.example/v1")
    monkeypatch.setenv("BEDROCK_API_KEY", "test-key")
    monkeypatch.setenv("BEDROCK_MODEL", "bedrock-model")

    settings = provider_config_from_environment()

    assert settings.provider == "bedrock"
    assert settings.model == "bedrock-model"
    assert settings.config.base_url == "https://bedrock.example/v1"
    assert settings.config.api_key == "test-key"


def test_provider_config_from_environment_supports_generic_auth_settings(
    monkeypatch,
) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "azure")
    monkeypatch.setenv("LLM_BASE_URL", "https://resource.openai.azure.com/openai/v1")
    monkeypatch.setenv("LLM_API_KEY", "azure-test-key")
    monkeypatch.setenv("LLM_MODEL", "my-deployment")
    monkeypatch.setenv("LLM_API_KEY_HEADER", "api-key")
    monkeypatch.setenv("LLM_API_KEY_PREFIX", "")

    settings = provider_config_from_environment()

    assert settings.provider == "azure"
    assert settings.model == "my-deployment"
    assert settings.config.api_key_header == "api-key"
    assert settings.config.api_key_prefix == ""


def test_provider_config_supports_local_ollama_without_a_remote_key(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("LLM_MODEL", "small-local-model")
    monkeypatch.delenv("LLM_API_KEY_HEADER", raising=False)
    monkeypatch.delenv("LLM_API_KEY_PREFIX", raising=False)

    settings = provider_config_from_environment()

    assert settings.base_url == "http://host.docker.internal:11434/v1"
    assert settings.api_key == "ollama"
    assert settings.model == "small-local-model"


def test_provider_config_defaults_to_openai_and_bearer_auth(monkeypatch) -> None:
    for name in (
        "LLM_PROVIDER",
        "LLM_BASE_URL",
        "LLM_API_KEY",
        "LLM_MODEL",
        "LLM_API_KEY_HEADER",
        "LLM_API_KEY_PREFIX",
        "BEDROCK_BASE_URL",
        "BEDROCK_API_KEY",
        "BEDROCK_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LLM_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "model")

    settings = provider_config_from_environment()

    assert settings.provider == "openai"
    assert settings.config.api_key_header == "Authorization"
    assert settings.config.api_key_prefix == "Bearer "


def test_provider_config_reads_request_timeout_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv(
        "LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/"
    )
    monkeypatch.setenv("LLM_API_KEY", "gemini-test-key")
    monkeypatch.setenv("LLM_MODEL", "gemini-test-model")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "600")

    settings = provider_config_from_environment()

    assert settings.config.timeout_s == 600


def test_provider_config_uses_azure_api_key_defaults(monkeypatch) -> None:
    for name in ("LLM_API_KEY_HEADER", "LLM_API_KEY_PREFIX"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "azure")
    monkeypatch.setenv("LLM_BASE_URL", "https://resource.openai.azure.com/openai/v1")
    monkeypatch.setenv("LLM_API_KEY", "azure-test-key")
    monkeypatch.setenv("LLM_MODEL", "deployment-name")

    settings = provider_config_from_environment()

    assert settings.config.api_key_header == "api-key"
    assert settings.config.api_key_prefix == ""


def test_provider_config_selects_native_anthropic_defaults(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("LLM_API_FORMAT", raising=False)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.setenv("LLM_API_KEY", "anthropic-test-key")
    monkeypatch.setenv("LLM_MODEL", "claude-model")
    monkeypatch.delenv("LLM_API_KEY_HEADER", raising=False)
    monkeypatch.delenv("LLM_API_KEY_PREFIX", raising=False)

    settings = provider_config_from_environment()

    assert settings.api_format == "anthropic-messages"
    assert settings.base_url == "https://api.anthropic.com/v1"
    assert settings.api_key_header == "x-api-key"
    assert settings.api_key_prefix == ""
    assert isinstance(provider_client_from_settings(settings), AnthropicMessagesClient)


def test_bedrock_nova_micro_selects_converse_with_user_base_url(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv(
        "LLM_BASE_URL", "https://bedrock-runtime.us-east-1.amazonaws.com"
    )
    monkeypatch.setenv("LLM_API_KEY", "bedrock-test-key")
    monkeypatch.setenv("LLM_MODEL", "amazon.nova-micro-v1:0")
    monkeypatch.delenv("LLM_API_FORMAT", raising=False)

    settings = provider_config_from_environment()

    assert settings.api_format == "bedrock-converse"
    client = provider_client_from_settings(settings)
    assert isinstance(client, BedrockConverseClient)
    assert client.endpoint.endswith("/model/amazon.nova-micro-v1:0/converse")


def test_api_format_can_select_native_anthropic_for_custom_gateway(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "custom-gateway")
    monkeypatch.setenv("LLM_API_FORMAT", "anthropic-messages")
    monkeypatch.setenv("LLM_BASE_URL", "https://gateway.example/anthropic/v1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "claude-deployment")

    settings = provider_config_from_environment()

    assert settings.provider == "custom-gateway"
    assert isinstance(provider_client_from_settings(settings), AnthropicMessagesClient)


@pytest.mark.parametrize(
    ("provider", "base_url", "expected_url", "header", "prefix"),
    [
        (
            "openai",
            "https://api.openai.com/v1",
            "https://api.openai.com/v1/chat/completions",
            "Authorization",
            "Bearer ",
        ),
        (
            "gemini",
            "https://generativelanguage.googleapis.com/v1beta/openai/",
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            "Authorization",
            "Bearer ",
        ),
        (
            "openrouter",
            "https://openrouter.ai/api/v1",
            "https://openrouter.ai/api/v1/chat/completions",
            "Authorization",
            "Bearer ",
        ),
        (
            "groq",
            "https://api.groq.com/openai/v1",
            "https://api.groq.com/openai/v1/chat/completions",
            "Authorization",
            "Bearer ",
        ),
        (
            "bedrock",
            "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1",
            "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1/chat/completions",
            "Authorization",
            "Bearer ",
        ),
        (
            "azure",
            "https://resource.openai.azure.com/openai/v1",
            "https://resource.openai.azure.com/openai/v1/chat/completions",
            "api-key",
            "",
        ),
    ],
)
def test_named_provider_endpoints_use_common_chat_completion_contract(
    provider, base_url, expected_url, header, prefix
) -> None:
    seen = {}

    def transport(url, headers, body, timeout):
        seen.update(url=url, headers=headers)
        return (
            200,
            {},
            json.dumps(
                {
                    "choices": [{"message": {"role": "assistant", "content": "OK"}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                }
            ).encode(),
        )

    settings = ProviderSettings(
        provider,
        base_url,
        "test-key",
        "test-model-or-deployment",
        header,
        prefix,
    )
    OpenAICompatibleClient(settings.config, transport=transport).chat(
        messages=[{"role": "user", "content": "hello"}], tools=[], max_tokens=8
    )

    assert seen["url"] == expected_url
    assert seen["headers"][header] == f"{prefix}test-key"


def test_provider_config_from_environment_rejects_missing_values(monkeypatch) -> None:
    for name in (
        "LLM_BASE_URL",
        "LLM_API_KEY",
        "LLM_MODEL",
        "BEDROCK_BASE_URL",
        "BEDROCK_API_KEY",
        "BEDROCK_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(
        ProviderConfigurationError, match="provider configuration is incomplete"
    ):
        provider_config_from_environment()
