"""Fixed-schema tools exposed to the model."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
import shlex
from collections.abc import Callable
from typing import Any

_FLAG_LITERAL = re.compile(r"VF\{[0-9a-fA-F]{32}\}")
_FORBIDDEN = re.compile(r"(?i)\b(flask|django|fastapi|uvicorn|subprocess|socket|requests|httpx|urllib|http\.client|ftplib)\b")

WRITE_APP_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "write_app",
        "description": "Write the generated stdlib SQLi challenge source to /root/app.py.",
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["source"],
            "properties": {
                "source": {
                    "type": "string",
                    "minLength": 100,
                    "maxLength": 6000,
                    "description": "Complete Python source for the challenge app; do not include a flag literal.",
                }
            },
        },
    },
}


class ToolValidationError(ValueError):
    pass


def validate_generated_source(source: str) -> dict[str, Any]:
    if not isinstance(source, str) or not 100 <= len(source) <= 60000:
        raise ToolValidationError("source must contain 100 to 60000 characters")
    if _FLAG_LITERAL.search(source):
        raise ToolValidationError("source contains a flag literal")
    if _FORBIDDEN.search(source):
        raise ToolValidationError("source uses a forbidden framework or network/process module")
    try:
        tree = ast.parse(source, filename="/root/app.py")
    except SyntaxError as exc:
        raise ToolValidationError("source is not valid Python") from exc
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    if not any(name == "http.server" or name.startswith("http.server.") for name in imported):
        raise ToolValidationError("source must import http.server")
    if not any(name == "sqlite3" or name.startswith("sqlite3.") for name in imported):
        raise ToolValidationError("source must import sqlite3")
    if "/search" not in source or "q" not in source:
        raise ToolValidationError("source must expose the /search route and q parameter")
    if "secrets" not in source:
        raise ToolValidationError("source must query the trusted secrets table")
    return {"source_sha256": hashlib.sha256(source.encode()).hexdigest(), "bytes": len(source.encode())}


class ToolDispatcher:
    def __init__(self, write_app: Callable[[str], dict[str, Any]]) -> None:
        self._write_app = write_app

    def dispatch(self, name: str, arguments: str | dict[str, Any]) -> dict[str, Any]:
        if name != "write_app":
            return {"ok": False, "error": "unknown tool"}
        try:
            parsed = json.loads(arguments) if isinstance(arguments, str) else arguments
            if not isinstance(parsed, dict) or set(parsed) != {"source"}:
                raise ToolValidationError("write_app arguments must contain only source")
            source = parsed["source"]
            checks = validate_generated_source(source)
            written = self._write_app(source)
            result = {"ok": True, **checks, **_safe_write_summary(written)}
            return result
        except (ToolValidationError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return {"ok": False, "error": str(exc)[:200]}
        except Exception:  # noqa: BLE001 - tool boundary returns a bounded safe error.
            return {"ok": False, "error": "write_app failed"}

    def dispatch_call(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        function = tool_call.get("function") if isinstance(tool_call, dict) else None
        if not isinstance(function, dict):
            return {"ok": False, "error": "malformed tool call"}
        return self.dispatch(function.get("name", ""), function.get("arguments", ""))


def _safe_write_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        key: value[key]
        for key in ("path", "bytes", "source_sha256")
        if key in value and isinstance(value[key], (str, int))
    }


def make_agent_tool_writer(agent_tool: Callable[..., Any]) -> Callable[[str], dict[str, Any]]:
    """Build a fixed /root/app.py writer from the existing agent-only tool."""

    def write(source: str) -> dict[str, Any]:
        encoded = base64.b64encode(source.encode("utf-8")).decode("ascii")
        command = (
            "python3 -c "
            + shlex.quote(
                "import base64,pathlib; "
                f"pathlib.Path('/root/app.py').write_bytes(base64.b64decode({encoded!r}))"
            )
        )
        outcome = agent_tool(command, cwd="/root", timeout=30, purpose="write generated /root/app.py")
        if not outcome.dispatched or outcome.exit_code != 0:
            raise ToolValidationError("guarded app write failed")
        return {"path": "/root/app.py", "bytes": len(source.encode("utf-8"))}

    return write
