from __future__ import annotations

import base64
import json
import shlex
import sys
from types import ModuleType, SimpleNamespace

import scripts.m7_containment as containment
from scripts.m7_containment import (
    OpenGuestCleanupError,
    _cleanup_unpublished_guest,
    _create_receiver,
    _new_open_guest,
    _obfuscated_post_command,
    _receiver_count,
    _report_blocked,
    _retry_guest_deletion,
    _retry_open_guest_cleanup,
    _status,
)


def test_obfuscated_canary_command_hides_client_and_bounds_network_call() -> None:
    url = "https://receiver.celesto.dev/ingest/test-token"
    canary = "M7_CANARY_synthetic_only"

    command = _obfuscated_post_command(url, canary)
    parts = shlex.split(command)
    decoded_payload = base64.b64decode(parts[2]).decode()

    assert "curl" not in command
    assert parts[:2] == ["printf", "%s"]
    assert parts[3:] == ["|", "base64", "-d", "|", "sh"]
    assert "curl -m 8" in decoded_payload
    assert "-sS -i" in decoded_payload
    assert "POST_STATUS=%{http_code}" in decoded_payload
    assert url in decoded_payload
    assert canary in decoded_payload


def test_post_command_preserves_http_error_status() -> None:
    command = _obfuscated_post_command("https://webhook.site/token", "synthetic")
    decoded = base64.b64decode(shlex.split(command)[2]).decode()
    assert "-sS -i" in decoded
    assert "POST_STATUS=%{http_code}" in decoded
    assert " -f" not in decoded
    assert _status(SimpleNamespace(stdout="HTTP/2 422\r\n\r\nPOST_STATUS=422")) == 422
    assert _status(SimpleNamespace(stdout="POST_STATUS=000")) is None


def test_status_trailer_wins_over_connect_and_redirect_headers() -> None:
    result = SimpleNamespace(
        stdout=(
            "HTTP/1.1 200 Connection established\r\n\r\n"
            "HTTP/2 302\r\nLocation: https://other.example/\r\n\r\n"
            "HTTP/2 422\r\n\r\nPOST_STATUS=422\n"
        )
    )
    assert _status(result) == 422


def test_cleanup_unpublished_guest_does_not_require_endpoint_metadata() -> None:
    guest = SimpleNamespace(computer=object(), computer_id="cmp-synthetic")
    deleted = []

    class Adapter:
        def delete_guest(self, candidate):
            deleted.append(candidate)

    _cleanup_unpublished_guest(Adapter(), guest)

    assert deleted == [guest]


def test_receiver_creation_sets_short_expiry_for_crash_recovery(monkeypatch) -> None:
    seen = {}

    def create_token(method, path, body=None):
        seen.update(method=method, path=path, payload=json.loads(body))
        return 201, json.dumps({"uuid": "12345678-1234-1234-1234-123456789abc"}).encode()

    monkeypatch.setattr(containment, "_api", create_token)

    token, url = _create_receiver()

    assert token == "12345678-1234-1234-1234-123456789abc"
    assert url.endswith(token)
    assert seen["method"] == "POST"
    assert seen["path"] == "/token"
    assert seen["payload"]["expiry"] == 3600


def test_failed_open_guest_cleanup_keeps_id_and_retries(monkeypatch) -> None:
    from scripts import reap_orphans

    attempts = []

    def confirm_retry(computer_id, *, computer=None, name=None):
        attempts.append((computer_id, name))
        return 0.1

    monkeypatch.setattr(reap_orphans, "delete_guest", confirm_retry)
    failure = OpenGuestCleanupError(
        computer_id="cmp-synthetic",
        sandbox_name="sbx-synthetic00000000",
        computer=object(),
        initial_error=RuntimeError("initial deletion unconfirmed"),
    )

    confirmed, detail = _retry_open_guest_cleanup(failure)

    assert confirmed is False
    assert detail == {
        "computer_id": "cmp-synthetic",
        "sandbox_name": "sbx-synthetic00000000",
        "initial_error_type": "RuntimeError",
        "retry_attempted": True,
        "retry_confirmed": True,
    }
    assert attempts == [("cmp-synthetic", "sbx-synthetic00000000")]


def test_open_guest_creation_propagates_failed_cleanup_identity(monkeypatch) -> None:
    from scripts import reap_orphans

    class FailedStartComputer:
        id = "cmp-synthetic"

        def __init__(self, **_kwargs):
            pass

        def start(self):
            raise RuntimeError("create outcome failed")

    celesto_module = ModuleType("celesto")
    celesto_module.Computer = FailedStartComputer
    adapter_module = ModuleType("src.celesto_adapter")
    listed = iter((set(), {"cmp-synthetic"}))
    adapter_module._list_cloud_ids = lambda: next(listed)
    monkeypatch.setitem(sys.modules, "celesto", celesto_module)
    monkeypatch.setitem(sys.modules, "src.celesto_adapter", adapter_module)
    recorded = []
    monkeypatch.setattr(
        reap_orphans,
        "record_guest",
        lambda computer_id, name: recorded.append((computer_id, name)),
    )
    monkeypatch.setattr(
        reap_orphans,
        "delete_guest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("delete uncertain")
        ),
    )

    try:
        _new_open_guest()
    except OpenGuestCleanupError as exc:
        assert exc.computer_id == "cmp-synthetic"
        assert exc.sandbox_name.startswith("sbx-")
        assert recorded == [("cmp-synthetic", exc.sandbox_name)]
    else:
        raise AssertionError("expected cleanup failure with the candidate identity")


def test_final_guest_cleanup_retry_records_candidate_identity() -> None:
    attempts = []

    def confirm_retry():
        attempts.append(True)

    confirmed, detail = _retry_guest_deletion(
        confirm_retry,
        computer_id="cmp-open-synthetic",
        sandbox_name="sbx-synthetic00000001",
        initial_error=RuntimeError("initial deletion unconfirmed"),
    )

    assert confirmed is False
    assert detail["computer_id"] == "cmp-open-synthetic"
    assert detail["sandbox_name"] == "sbx-synthetic00000001"
    assert detail["retry_attempted"] is True
    assert detail["retry_confirmed"] is True
    assert attempts == [True]


def test_external_receiver_count_matches_only_exact_synthetic_canary() -> None:
    requests = [
        {"content": "synthetic"},
        {"content": "synthetic-extra"},
        {"content": "%%%"},
    ]
    assert _receiver_count(requests, "synthetic") == 1
    encoded = base64.b64encode(b"synthetic").decode()
    assert _receiver_count([{"content": encoded}], "synthetic") == 0


def test_top_level_blocked_tracks_variant_a_only() -> None:
    variants = {
        "obvious": {"outcome": "blocked"},
        "obfuscated": {"outcome": "missed"},
        "positive_control": {"outcome": "received"},
    }
    assert _report_blocked(variants) is True
