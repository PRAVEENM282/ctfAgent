from __future__ import annotations

from collections.abc import Iterator

import pytest

from scripts import reap_orphans


def test_retry_transient_retries_read_and_connect_errors_with_bounded_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses: Iterator[object] = iter(
        [RuntimeError("ReadTimeout"), RuntimeError("ConnectError"), "ready"]
    )
    sleeps: list[float] = []
    calls = 0

    def operation() -> object:
        nonlocal calls
        calls += 1
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(reap_orphans.time, "sleep", sleeps.append)

    result = reap_orphans._retry_transient("test operation", operation)

    assert result == "ready"
    assert calls == 3
    assert sleeps == [1, 2]


def test_retry_transient_does_not_retry_non_transient_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []
    calls = 0

    def operation() -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("validation_error")

    monkeypatch.setattr(reap_orphans.time, "sleep", sleeps.append)

    with pytest.raises(RuntimeError, match="validation_error"):
        reap_orphans._retry_transient("test operation", operation)

    assert calls == 1
    assert sleeps == []


def test_confirm_deleted_polls_until_direct_lookup_reports_absent(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    states = iter([True, True, False])
    polls: list[str] = []

    def exists(computer_id: str) -> bool:
        polls.append(computer_id)
        return next(states)

    monkeypatch.setattr(reap_orphans, "_computer_exists", exists)
    monkeypatch.setattr(reap_orphans.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(reap_orphans, "forget_guest", lambda _computer_id: None)

    duration = reap_orphans.confirm_deleted("cmp_test", started_at=0.0)

    output = capsys.readouterr().out
    assert duration >= 0
    assert polls == ["cmp_test", "cmp_test", "cmp_test"]
    assert "DELETE_CONFIRMED computer_id=cmp_test" in output
    assert "polls=3" in output
