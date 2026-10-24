"""Single guarded dispatch path with redacted JSONL command auditing."""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

_RUN_ID = re.compile(r"^run-[a-z0-9]{12,32}$")
_ATTEMPT_ID = re.compile(r"^attempt-[a-z0-9]{12,32}$")
_SANDBOX_NAME = re.compile(r"^sbx-[a-z0-9]{16}$")
_FLAG = re.compile(r"VF\{[0-9a-fA-F]{32}\}")
_CREDENTIAL = re.compile(r"(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s;,]+")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_DENY = (
    (
        re.compile(r"(?i)\b(curl|wget|nc|ncat|netcat|socat|ssh|scp|ftp)\b"),
        "network client",
    ),
    (re.compile(r"(?i)/dev/tcp|docker\.sock"), "direct network or container socket"),
    (
        re.compile(r"(?i)\b(sudo|su|mount|umount|mkfs|reboot|shutdown)\b"),
        "privileged operation",
    ),
    (re.compile(r"(?i)\brm\s+-[^\s]*r[^\s]*f\b"), "recursive force delete"),
)
_AUDIT_LOCK = threading.Lock()


@dataclass(frozen=True)
class CommandContext:
    run_id: str
    parent_run_id: str | None
    batch_id: str | None
    attempt_id: str
    sandbox_name: str


@dataclass(frozen=True)
class CommandOutcome:
    decision: str
    dispatched: bool
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    block_reason: str | None = None
    duration_ms: int = 0


class CommandDispatchError(RuntimeError):
    """Safe error returned to callers without echoing guest output or secrets."""


class CommandAuditUnavailable(RuntimeError):
    """Raised before dispatch when the command audit cannot be opened."""


class CommandGuard:
    """Validate, dispatch, and audit every command requested by the agent."""

    def __init__(
        self,
        dispatcher: Callable[..., Any],
        *,
        audit_path: Path = Path("logs/commands.jsonl"),
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._dispatcher = dispatcher
        self._audit_path = audit_path
        self._monotonic = monotonic

    def execute(
        self,
        context: CommandContext,
        command: str,
        *,
        cwd: str = "/root",
        timeout: int = 30,
        purpose: str = "",
    ) -> CommandOutcome:
        """Execute an agent command with denylist enforcement and redacted output."""
        return self._execute(
            context,
            command,
            origin="agent",
            cwd=cwd,
            timeout=timeout,
            purpose=purpose,
        )

    def execute_control_plane(
        self,
        context: CommandContext,
        command: str,
        *,
        cwd: str = "/root",
        timeout: int = 30,
        purpose: str = "",
    ) -> CommandOutcome:
        """Execute trusted verifier/runtime work and return raw output only to its caller."""
        return self._execute(
            context,
            command,
            origin="control_plane",
            cwd=cwd,
            timeout=timeout,
            purpose=purpose,
        )

    def _execute(
        self,
        context: CommandContext,
        command: str,
        *,
        origin: str,
        cwd: str,
        timeout: int,
        purpose: str,
    ) -> CommandOutcome:
        started = self._monotonic()
        reason = self._block_reason(context, command, cwd, timeout, origin)
        summary = _redact(command[:500]) if isinstance(command, str) else "<invalid>"
        common = {
            "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            **asdict(context),
            "execution_target": "celesto_sandbox",
            "origin": origin,
            "command": summary,
            "command_summary": summary,
            "purpose": _redact(str(purpose)[:200]),
        }
        common["timestamp"] = common["ts"]
        if reason:
            elapsed = round((self._monotonic() - started) * 1000)
            self._write_audit(
                {
                    **common,
                    "decision": "block",
                    "dispatched": False,
                    "block_reason": reason,
                    "exit_code": None,
                    "duration_ms": elapsed,
                    "result_summary": "not dispatched",
                }
            )
            return CommandOutcome(
                "block", False, None, block_reason=reason, duration_ms=elapsed
            )

        try:
            audit_descriptor = self._open_audit()
        except OSError:
            raise CommandAuditUnavailable(
                "command audit storage is unavailable"
            ) from None
        try:
            try:
                result = self._dispatcher(command, cwd=cwd, timeout=timeout)
            except Exception as exc:  # noqa: BLE001 - write a safe audit record for every dispatch error.
                elapsed = round((self._monotonic() - started) * 1000)
                self._write_audit(
                    {
                        **common,
                        "decision": "allow",
                        "dispatched": True,
                        "block_reason": None,
                        "exit_code": None,
                        "duration_ms": elapsed,
                        "result_summary": f"dispatch_error={type(exc).__name__}",
                    },
                    descriptor=audit_descriptor,
                )
                raise CommandDispatchError(
                    f"guest command dispatch failed ({type(exc).__name__})"
                ) from None

            elapsed = round((self._monotonic() - started) * 1000)
            raw_stdout = str(result.stdout)
            raw_stderr = str(result.stderr)
            if origin == "control_plane":
                stdout = raw_stdout[:10000]
                stderr = raw_stderr[:2000]
            else:
                stdout = _redact(raw_stdout)[:10000]
                stderr = _redact(raw_stderr)[:2000]
            exit_code = int(result.exit_code)
            self._write_audit(
                {
                    **common,
                    "decision": "allow",
                    "dispatched": True,
                    "block_reason": None,
                    "exit_code": exit_code,
                    "duration_ms": elapsed,
                    "result_summary": {
                        "stdout_bytes": len(str(result.stdout).encode()),
                        "stderr_bytes": len(str(result.stderr).encode()),
                    },
                },
                descriptor=audit_descriptor,
            )
            return CommandOutcome(
                "allow", True, exit_code, stdout, stderr, duration_ms=elapsed
            )
        finally:
            os.close(audit_descriptor)

    @staticmethod
    def _block_reason(
        context: CommandContext, command: str, cwd: str, timeout: int, origin: str
    ) -> str | None:
        if origin not in {"agent", "control_plane"}:
            return "origin must be agent or control_plane"
        if not _RUN_ID.fullmatch(context.run_id):
            return "invalid run_id"
        if not _ATTEMPT_ID.fullmatch(context.attempt_id):
            return "invalid attempt_id"
        if not _SANDBOX_NAME.fullmatch(context.sandbox_name):
            return "invalid sandbox_name"
        if context.parent_run_id and not _RUN_ID.fullmatch(context.parent_run_id):
            return "invalid parent_run_id"
        if context.batch_id and not re.fullmatch(
            r"batch-[a-z0-9]{12,32}", context.batch_id
        ):
            return "invalid batch_id"
        if not isinstance(command, str) or not command.strip() or len(command) > 10000:
            return "command must contain 1 to 10000 characters"
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int)
            or not 1 <= timeout <= 300
        ):
            return "timeout must be an integer from 1 to 300 seconds"
        path = PurePosixPath(cwd) if isinstance(cwd, str) else PurePosixPath("/")
        if path != PurePosixPath("/root"):
            return "working directory must be /root"
        if origin == "agent":
            for pattern, reason in _DENY:
                if pattern.search(command):
                    return f"blocked {reason}"
        return None

    def _open_audit(self) -> int:
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            self._audit_path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        return descriptor

    def _write_audit(
        self, record: dict[str, Any], *, descriptor: int | None = None
    ) -> None:
        data = (
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        owned_descriptor = descriptor is None
        if descriptor is None:
            descriptor = self._open_audit()
        with _AUDIT_LOCK:
            try:
                os.write(descriptor, data)
            finally:
                if owned_descriptor:
                    os.close(descriptor)


def _redact(value: str) -> str:
    value = _FLAG.sub("[REDACTED_FLAG]", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    return _CREDENTIAL.sub(r"\1=[REDACTED]", value)


class AgentCommandTool:
    """Expose only agent-originated guarded dispatch as an LLM tool callable."""

    def __init__(self, guard: CommandGuard, context: CommandContext) -> None:
        self._guard = guard
        self._context = context

    def __call__(
        self,
        command: str,
        *,
        cwd: str = "/root",
        timeout: int = 30,
        purpose: str = "",
    ) -> CommandOutcome:
        return self._guard.execute(
            self._context,
            command,
            cwd=cwd,
            timeout=timeout,
            purpose=purpose,
        )
