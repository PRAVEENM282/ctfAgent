from __future__ import annotations

import json

from src.agent.test_client import TEST_SOURCE, DeterministicTestClient
from src.agent.tools import WRITE_APP_TOOL
from src.challenge import build_variation, static_check


def test_deterministic_client_emits_one_write_app_call_without_provider_usage() -> None:
    response = DeterministicTestClient().chat(
        messages=[], tools=[WRITE_APP_TOOL], max_tokens=128
    )

    call = response.message["tool_calls"][0]
    assert call["function"]["name"] == "write_app"
    assert response.total_tokens == 0
    payload = json.loads(call["function"]["arguments"])
    assert payload == {"source": TEST_SOURCE}


def test_deterministic_source_passes_the_challenge_static_checks() -> None:
    result = static_check(TEST_SOURCE, build_variation("test-client-seed"))

    assert result.passed is True
    assert result.flag_in_source is False
