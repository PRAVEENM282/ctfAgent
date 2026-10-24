from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from src.command_guard import (
    AgentCommandTool,
    CommandAuditUnavailable,
    CommandContext,
    CommandGuard,
)


def _context() -> CommandContext:
    return CommandContext(
        run_id="run-0123456789ab",
        parent_run_id=None,
        batch_id="batch-0123456789ab",
        attempt_id="attempt-0123456789ab",
        sandbox_name="sbx-0123456789abcdef",
    )


def test_blocked_command_is_audited_and_never_dispatched(tmp_path) -> None:
    calls: list[str] = []
    audit_path = tmp_path / "commands.jsonl"
    guard = CommandGuard(
        lambda command, **_kwargs: calls.append(command), audit_path=audit_path
    )

    outcome = guard.execute(_context(), "curl https://example.com/collect")

    assert calls == []
    assert outcome.dispatched is False
    assert outcome.decision == "block"
    row = json.loads(audit_path.read_text().splitlines()[0])
    assert row["execution_target"] == "celesto_sandbox"
    assert row["decision"] == "block"
    assert row["dispatched"] is False
    assert row["block_reason"]
    assert row["sandbox_name"] == "sbx-0123456789abcdef"


def test_allowed_command_is_audited_and_flag_output_is_redacted(tmp_path) -> None:
    flag = "VF{" + "a" * 32 + "}"
    audit_path = tmp_path / "commands.jsonl"
    guard = CommandGuard(
        lambda _command, **_kwargs: SimpleNamespace(
            stdout=flag + "\n", stderr="", exit_code=0
        ),
        audit_path=audit_path,
    )

    outcome = guard.execute(_context(), "python3 /root/app.py")

    assert outcome.dispatched is True
    assert outcome.stdout == "[REDACTED_FLAG]\n"
    raw_audit = audit_path.read_text()
    assert flag not in raw_audit
    row = json.loads(raw_audit.splitlines()[0])
    assert row["decision"] == "allow"
    assert row["exit_code"] == 0
    assert row["duration_ms"] >= 0


def test_control_plane_gets_raw_output_without_logging_it(tmp_path) -> None:
    flag = "VF{" + "b" * 32 + "}"
    command = "python3 -c 'urllib.request.urlopen(\"http://127.0.0.1:8000/')'"
    calls: list[str] = []
    audit_path = tmp_path / "commands.jsonl"
    guard = CommandGuard(
        lambda value, **_kwargs: (
            calls.append(value)
            or SimpleNamespace(stdout=flag + "\n", stderr="", exit_code=0)
        ),
        audit_path=audit_path,
    )

    outcome = guard.execute_control_plane(_context(), command)

    assert calls == [command]
    assert outcome.stdout == flag + "\n"
    audit_text = audit_path.read_text()
    assert flag not in audit_text
    row = json.loads(audit_text.splitlines()[0])
    assert row["origin"] == "control_plane"
    assert row["result_summary"] == {
        "stdout_bytes": len((flag + "\n").encode()),
        "stderr_bytes": 0,
    }


def test_agent_external_client_is_blocked_but_control_plane_local_probe_is_allowed(
    tmp_path,
) -> None:
    calls: list[str] = []
    guard = CommandGuard(
        lambda command, **_kwargs: (
            calls.append(command)
            or SimpleNamespace(stdout="ok", stderr="", exit_code=0)
        ),
        audit_path=tmp_path / "commands.jsonl",
    )

    blocked = guard.execute(_context(), "curl https://example.com/collect")
    allowed = guard.execute_control_plane(
        _context(), "python3 -c 'urllib.request.urlopen(\"http://127.0.0.1:8000/')'"
    )

    assert blocked.dispatched is False
    assert allowed.dispatched is True
    assert calls == ["python3 -c 'urllib.request.urlopen(\"http://127.0.0.1:8000/')'"]
    rows = [
        json.loads(line)
        for line in (tmp_path / "commands.jsonl").read_text().splitlines()
    ]
    identity_fields = {
        "run_id",
        "parent_run_id",
        "batch_id",
        "attempt_id",
        "sandbox_name",
        "execution_target",
    }
    assert [row["origin"] for row in rows] == ["agent", "control_plane"]
    assert [row["decision"] for row in rows] == ["block", "allow"]
    assert set(rows[0]) >= identity_fields
    assert set(rows[1]) >= identity_fields
    assert all(rows[0][field] == rows[1][field] for field in identity_fields)


def test_agent_tool_cannot_choose_control_plane_origin(tmp_path) -> None:
    guard = CommandGuard(
        lambda command, **_kwargs: SimpleNamespace(stdout="ok", stderr="", exit_code=0),
        audit_path=tmp_path / "commands.jsonl",
    )
    tool = AgentCommandTool(guard, _context())

    outcome = tool("python3 /root/app.py")

    assert outcome.dispatched is True
    row = json.loads((tmp_path / "commands.jsonl").read_text().splitlines()[0])
    assert row["origin"] == "agent"


def test_command_is_not_dispatched_when_audit_storage_is_unavailable(tmp_path) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_text("blocked")
    calls: list[str] = []
    guard = CommandGuard(
        lambda command, **_kwargs: calls.append(command),
        audit_path=parent / "commands.jsonl",
    )

    with pytest.raises(CommandAuditUnavailable):
        guard.execute(_context(), "python3 /root/app.py")

    assert calls == []
