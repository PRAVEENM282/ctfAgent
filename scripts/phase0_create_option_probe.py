"""Probe one Celesto cloud create option per process, with cleanup."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import traceback
from typing import Any

try:
    from scripts.reap_orphans import delete_guest, reap_orphans, record_guest
except ModuleNotFoundError as exc:
    if exc.name != "scripts":
        raise
    from reap_orphans import delete_guest, reap_orphans, record_guest


def _redact(value: str) -> str:
    for name in ("CELESTO_API_KEY", "LLM_API_KEY"):
        secret = os.environ.get(name)
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


def _error_details(exc: Exception) -> str:
    message = _redact(repr(exc))
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        context: dict[str, Any] = {
            "status_code": status_code,
            "code": getattr(exc, "code", None),
            "operation": getattr(exc, "operation", None),
            "validation_errors": getattr(exc, "validation_errors", ()),
            "side_effects": getattr(exc, "side_effects", None),
        }
        message += " provider_context=" + json.dumps(context, sort_keys=True)
    return message


def run_case(case: str) -> int:
    from celesto import Computer

    reap_orphans()
    kwargs: dict[str, Any] = {"provider": "cloud"}
    if case == "lifetime-only":
        kwargs["lifetime"] = "persistent"
    elif case == "volume-only":
        kwargs["external_volume_enabled"] = True
    else:
        raise ValueError(f"unsupported create case: {case}")

    print(f"CREATE_CASE {case} kwargs={json.dumps(kwargs, sort_keys=True)}")
    computer = Computer(**kwargs)
    logical_name = f"sbx-{secrets.token_hex(8)}"
    computer_id: str | None = None
    primary_error: Exception | None = None
    cleanup_error: Exception | None = None
    try:
        computer.start()
        computer_id = computer.id
        if not computer_id:
            raise RuntimeError("cloud create returned without a computer ID")
        record_guest(computer_id, logical_name)
        print(
            f"CREATE_ACCEPTED case={case} logical_name={logical_name} computer_id={computer_id}"
        )
    except Exception as exc:  # noqa: BLE001 - cleanup must run after every create attempt.
        primary_error = exc
        if computer.id:
            computer_id = computer.id
            try:
                record_guest(computer_id, logical_name)
            except Exception as registry_error:  # noqa: BLE001 - retain the create failure.
                cleanup_error = registry_error
        print(f"CREATE_REJECTED case={case} error={_error_details(exc)}")
    finally:
        if computer_id:
            try:
                delete_guest(computer_id, computer=computer, name=logical_name)
            except Exception as exc:  # noqa: BLE001 - report cleanup failure explicitly.
                cleanup_error = cleanup_error or exc
        else:
            computer.close()

    if primary_error and cleanup_error:
        print(f"CLEANUP_FAILURE case={case} error={_error_details(cleanup_error)}")
        return 1
    if cleanup_error:
        print(f"CLEANUP_FAILURE case={case} error={_error_details(cleanup_error)}")
        return 1
    if primary_error:
        frames = traceback.extract_tb(primary_error.__traceback__)
        last = frames[-1] if frames else None
        location = f"{last.filename}:{last.lineno}" if last else "unavailable"
        print(f"FAIL case={case} last_frame={location}")
        return 1
    print(f"PASS create-and-delete case={case}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--case", choices=("lifetime-only", "volume-only"), required=True
    )
    return run_case(parser.parse_args().case)


if __name__ == "__main__":
    raise SystemExit(main())
