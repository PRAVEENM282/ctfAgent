"""Measure Python, pip, and root-disk size for one Celesto cloud template."""

from __future__ import annotations

import json
import os
import secrets
import time
import traceback
from typing import Any

try:
    from scripts.reap_orphans import delete_guest, reap_orphans, record_guest
except ModuleNotFoundError as exc:
    if exc.name != "scripts":
        raise
    from reap_orphans import delete_guest, reap_orphans, record_guest


_RUNTIME_INVENTORY = (
    "for tool in python3 python pip pip3; do "
    'if path="$(command -v "$tool" 2>/dev/null)"; then '
    'printf "%s=%s\\n" "$tool" "$path"; '
    'else printf "%s=unavailable\\n" "$tool"; fi; done; '
    "if command -v python3 >/dev/null 2>&1; then python3 --version; "
    'python3 -m pip --version 2>&1 || printf "PIP_RESULT unavailable\\n"; '
    "python3 -c \"import sqlite3; print('SQLITE_VERSION='+sqlite3.sqlite_version)\"; "
    'else printf "PYTHON3_RESULT unavailable\\n"; fi; '
    'printf "ROOT_DISK_BYTES="; df -B1 --output=size / | tail -n1; '
    'printf "CPU_COUNT="; nproc; awk \'/MemTotal/ {print "MEMORY_KB=" $2}\' /proc/meminfo'
)


def _redact(value: str) -> str:
    for name in ("CELESTO_API_KEY", "LLM_API_KEY"):
        secret = os.environ.get(name)
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


def _guarded_inventory(computer: Any) -> str:
    if computer.provider != "cloud":
        raise ValueError("template probe requires a Celesto cloud computer")
    print(
        "COMMAND_LOG "
        + json.dumps(
            {
                "execution_target": "celesto_sandbox",
                "step": "template_runtime_inventory",
                "command": _RUNTIME_INVENTORY,
                "dispatched": True,
            },
            sort_keys=True,
        )
    )
    result = computer.run(_RUNTIME_INVENTORY, timeout=30)
    if result.exit_code != 0:
        raise RuntimeError(
            f"template runtime inventory failed exit_code={result.exit_code}; "
            f"stderr={_redact(result.stderr[:500])!r}"
        )
    print("GUEST_RUNTIME_INVENTORY " + result.stdout.strip().replace("\n", ","))
    return result.stdout


def run(template_id: str, *, smallest_shape: bool = False) -> int:
    from celesto import Computer

    reap_orphans()
    size_options: dict[str, Any] = {}
    if smallest_shape:
        size_options = {
            "image": "ubuntu-desktop-24.04",
            "vcpus": 1,
            "ram_mb": 512,
            "disk_size_mb": 7168,
        }
    computer = Computer(
        provider="cloud",
        lifetime="ephemeral",
        template_id=template_id,
        **size_options,
    )
    logical_name = f"sbx-{secrets.token_hex(8)}"
    computer_id: str | None = None
    primary_error: Exception | None = None
    cleanup_error: Exception | None = None
    try:
        boot_started = time.monotonic()
        computer.start()
        boot_to_ready_s = time.monotonic() - boot_started
        computer_id = computer.id
        if not computer_id:
            raise RuntimeError("template create returned without a computer ID")
        record_guest(computer_id, logical_name)
        print(
            f"TEMPLATE_COMPUTER_CREATED template_id={template_id} "
            f"logical_name={logical_name} computer_id={computer_id} "
            f"boot_to_ready_s={boot_to_ready_s:.3f} "
            f"requested_shape={json.dumps(size_options, sort_keys=True)}"
        )
        inventory = _guarded_inventory(computer)
        values = dict(
            line.split("=", 1) for line in inventory.splitlines() if "=" in line
        )
        print(
            f"TEMPLATE_RUNTIME_RESULT template_id={template_id} "
            f"python3={values.get('python3', 'unknown')} "
            f"python_version={next((line for line in inventory.splitlines() if line.startswith('Python ')), 'unavailable')} "
            f"pip={next((line for line in inventory.splitlines() if line.startswith('pip ')), 'unavailable')} "
            f"sqlite3={next((line for line in inventory.splitlines() if line.startswith('SQLITE_VERSION=')), 'unavailable')} "
            f"root_disk_bytes={values.get('ROOT_DISK_BYTES', 'unknown')} "
            f"cpu_count={values.get('CPU_COUNT', 'unknown')} "
            f"memory_kb={values.get('MEMORY_KB', 'unknown')}"
        )
    except Exception as exc:  # noqa: BLE001 - retain runtime failure and still delete the guest.
        primary_error = exc
        if computer.id:
            computer_id = computer.id
            try:
                record_guest(computer_id, logical_name)
            except Exception as registry_error:  # noqa: BLE001 - preserve the primary failure.
                cleanup_error = registry_error
        frames = traceback.extract_tb(exc.__traceback__)
        last = frames[-1] if frames else None
        location = f"{last.filename}:{last.lineno}" if last else "unavailable"
        print(
            f"FAIL step=template_runtime error={_redact(repr(exc))} "
            f"last_frame={location}"
        )
    finally:
        if computer_id:
            try:
                delete_guest(computer_id, computer=computer, name=logical_name)
            except Exception as exc:  # noqa: BLE001 - report incomplete cleanup evidence.
                cleanup_error = cleanup_error or exc
        else:
            computer.close()

    if cleanup_error:
        print(f"CLEANUP_FAILURE error={_redact(repr(cleanup_error))}")
        return 1
    if primary_error:
        return 1
    print(f"PASS template_runtime_probe template_id={template_id}")
    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--template", choices=("scratch", "coding-agent"), required=True
    )
    parser.add_argument("--smallest-shape", action="store_true")
    options = parser.parse_args()
    raise SystemExit(run(options.template, smallest_shape=options.smallest_shape))
