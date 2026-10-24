"""Run the sequential, account-backed Celesto compatibility probe."""

from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import secrets
import sys
import traceback
from importlib import metadata
from typing import Any

try:
    from scripts.reap_orphans import delete_guest, reap_orphans, record_guest
except ModuleNotFoundError as exc:
    if exc.name != "scripts":
        raise
    from reap_orphans import delete_guest, reap_orphans, record_guest

os.environ.setdefault("CELESTO_NO_TELEMETRY", "1")

_CURRENT_STEP = "argument_validation"


def _redact(value: str) -> str:
    for key_name in ("CELESTO_API_KEY", "LLM_API_KEY"):
        secret = os.environ.get(key_name)
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


def _format_error(exc: Exception) -> str:
    message = _redact(repr(exc))
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        safe_context = {
            "status_code": status_code,
            "code": getattr(exc, "code", None),
            "operation": getattr(exc, "operation", None),
            "validation_errors": getattr(exc, "validation_errors", ()),
            "side_effects": getattr(exc, "side_effects", None),
        }
        message += " provider_context=" + json.dumps(safe_context, sort_keys=True)
    return message


def _signature_survey(computer_class: type[Any]) -> None:
    print(f"CELESTO_SDK_VERSION {metadata.version('celesto')}")
    for member in (
        computer_class,
        computer_class.get,
        computer_class.start,
        computer_class.run,
        computer_class.stop,
        computer_class.resume,
        computer_class.publish_port,
        computer_class.published_ports,
        computer_class.unpublish_port,
        computer_class.delete,
    ):
        print(f"SDK_SIGNATURE {member.__qualname__}{inspect.signature(member)}")


def _run_guarded(computer: Any, step: str, command: str, timeout: int = 30) -> Any:
    """Allow only the fixed, harmless operations used by the phase 0 probe."""
    allowed = {
        "sdk_echo": "echo hi",
        "guest_identity": 'whoami && printf \'\\nHOME=%s\\n\' "$HOME"',
        "python_and_pip": "python3 --version && python3 -m pip --version",
        "flask_install": "python3 -m pip install --disable-pip-version-check flask",
        "read_sentinel": "cat /home/ohm/phase0_sentinel",
    }
    if step == "write_sentinel":
        allowed_command = re.fullmatch(
            r"mkdir -p /home/ohm && printf '%s' '[0-9a-f]{32}' > /home/ohm/phase0_sentinel",
            command,
        )
    else:
        allowed_command = command == allowed.get(step)
    if not allowed_command or computer.provider != "cloud":
        raise ValueError(f"phase 0 command guard rejected step={step!r} or execution target")
    print(
        "COMMAND_LOG "
        + json.dumps(
            {
                "execution_target": "celesto_sandbox",
                "step": step,
                "command": command,
                "dispatched": True,
            },
            sort_keys=True,
        )
    )
    result = computer.run(command, timeout=timeout)
    if result.exit_code != 0:
        raise RuntimeError(
            f"guarded command step={step} returned exit_code={result.exit_code}; "
            f"stderr={_redact(result.stderr)!r}"
        )
    print(f"GUEST_COMMAND_RESULT step={step} exit_code=0")
    return result


def _echo_smoke() -> None:
    from celesto import Computer

    _signature_survey(Computer)
    computer = Computer(provider="cloud")
    logical_name = f"sbx-{secrets.token_hex(8)}"
    computer_id: str | None = None
    primary_error: Exception | None = None
    cleanup_error: Exception | None = None
    try:
        computer.start()
        computer_id = computer.id
        if not computer_id:
            raise RuntimeError("Celesto started a cloud computer without returning an id")
        record_guest(computer_id, logical_name)
        print(f"COMPUTER_CREATED logical_name={logical_name} computer_id={computer_id}")
        result = _run_guarded(computer, "sdk_echo", "echo hi")
        if result.stdout.strip() != "hi":
            raise RuntimeError("guarded echo returned unexpected output")
        print("ECHO_RESULT stdout=hi exit_code=0")
    except Exception as exc:  # noqa: BLE001 - cleanup must run for every SDK/runtime failure.
        primary_error = exc
        if computer.id:
            computer_id = computer.id
            try:
                record_guest(computer_id, logical_name)
            except Exception as registry_error:  # noqa: BLE001 - preserve the primary probe failure.
                cleanup_error = registry_error
    finally:
        if computer_id:
            try:
                delete_guest(computer_id, computer=computer, name=logical_name)
            except Exception as exc:  # noqa: BLE001 - retain cleanup failure for the final report.
                cleanup_error = cleanup_error or exc
        else:
            computer.close()

    if primary_error and cleanup_error:
        raise ExceptionGroup("echo probe and cleanup both failed", [primary_error, cleanup_error])
    if primary_error:
        raise primary_error
    if cleanup_error:
        raise cleanup_error
    print("PASS sdk_echo_and_delete")


def _persistence_probe() -> None:
    global _CURRENT_STEP
    from celesto import Computer

    _CURRENT_STEP = "persistence_probe"
    reap_orphans()
    computer = Computer(
        provider="cloud",
        lifetime="persistent",
        external_volume_enabled=True,
    )
    logical_name = f"sbx-{secrets.token_hex(8)}"
    computer_id: str | None = None
    primary_error: Exception | None = None
    cleanup_error: Exception | None = None
    try:
        computer.start()
        computer_id = computer.id
        if not computer_id:
            raise RuntimeError("Celesto started a persistent computer without returning an id")
        record_guest(computer_id, logical_name)
        print(
            f"PERSISTENT_COMPUTER_CREATED logical_name={logical_name} "
            f"computer_id={computer_id} storage_option=external_volume_enabled"
        )

        _CURRENT_STEP = "guest_identity"
        identity = _run_guarded(
            computer,
            "guest_identity",
            'whoami && printf \'\\nHOME=%s\\n\' "$HOME"',
        )
        identity_lines = identity.stdout.strip().splitlines()
        print(
            f"GUEST_IDENTITY user={identity_lines[0] if identity_lines else 'unknown'} "
            f"home={identity_lines[-1].removeprefix('HOME=') if len(identity_lines) > 1 else 'unknown'}"
        )

        sentinel = secrets.token_hex(16)
        write_command = (
            f"mkdir -p /home/ohm && printf '%s' '{sentinel}' "
            "> /home/ohm/phase0_sentinel"
        )
        _CURRENT_STEP = "write_sentinel"
        _run_guarded(computer, "write_sentinel", write_command)
        original_id = computer.id

        _CURRENT_STEP = "stop_persistent_computer"
        computer.stop()
        print(f"PERSISTENCE_STOP computer_id={original_id}")
        _CURRENT_STEP = "resume_persistent_computer"
        computer.resume()
        same_id = computer.id == original_id
        _CURRENT_STEP = "read_sentinel_after_resume"
        sentinel_result = _run_guarded(
            computer,
            "read_sentinel",
            "cat /home/ohm/phase0_sentinel",
        )
        sentinel_matches = sentinel_result.stdout.strip() == sentinel
        print(
            f"PERSISTENCE_RESULT same_computer_id={str(same_id).lower()} "
            f"sentinel_survived={str(sentinel_matches).lower()}"
        )
        if not same_id or not sentinel_matches:
            raise RuntimeError("persistence gate failed: guest identity or /home/ohm sentinel changed")

        _CURRENT_STEP = "python_pip_probe"
        versions = _run_guarded(
            computer,
            "python_and_pip",
            "python3 --version && python3 -m pip --version",
        )
        version_lines = versions.stdout.strip().splitlines()
        if len(version_lines) < 2:
            raise RuntimeError("guest Python/pip probe did not return both versions")
        print(f"GUEST_PYTHON {version_lines[0]}")
        print(f"GUEST_PIP {version_lines[1]}")

        _CURRENT_STEP = "install_flask"
        _run_guarded(
            computer,
            "flask_install",
            "python3 -m pip install --disable-pip-version-check flask",
            timeout=300,
        )
        print("GUEST_FLASK_INSTALL pass")
    except Exception as exc:  # noqa: BLE001 - retain all failures while preserving cleanup.
        primary_error = exc
        if computer.id:
            computer_id = computer.id
            try:
                record_guest(computer_id, logical_name)
            except Exception as registry_error:  # noqa: BLE001 - preserve the primary probe failure.
                cleanup_error = registry_error
    finally:
        if computer_id:
            try:
                delete_guest(computer_id, computer=computer, name=logical_name)
            except Exception as exc:  # noqa: BLE001 - retain cleanup failure for the final report.
                cleanup_error = cleanup_error or exc
        else:
            computer.close()

    if primary_error and cleanup_error:
        raise ExceptionGroup("persistence probe and cleanup both failed", [primary_error, cleanup_error])
    if primary_error:
        raise primary_error
    if cleanup_error:
        raise cleanup_error
    print("PASS persistence_and_guest_python_pip_flask")


def _main() -> int:
    global _CURRENT_STEP
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-inflight", type=int, default=1)
    args = parser.parse_args()
    if args.max_inflight != 1:
        print("FAIL step=argument_validation error=ValueError('phase 0 is sequential only')")
        return 2

    try:
        _CURRENT_STEP = "reap_orphans"
        reap_orphans()
        _CURRENT_STEP = "sdk_echo_and_delete"
        _echo_smoke()
        _persistence_probe()
        return 0
    except Exception as exc:  # noqa: BLE001 - emit required redacted failure diagnostics.
        frames = traceback.extract_tb(exc.__traceback__)
        frame = frames[-1] if frames else None
        location = f"{frame.filename}:{frame.lineno}" if frame else "unavailable"
        print(
            f"FAIL step={_CURRENT_STEP} error={_format_error(exc)} last_frame={location}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
