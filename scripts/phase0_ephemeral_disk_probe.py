"""Check which guest paths survive stop/resume on one ephemeral computer."""

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


_INVENTORY = (
    'for path in /root /tmp /home/ohm; do if [ -d "$path" ]; then '
    'printf "%s=present\\n" "$path"; else printf "%s=absent\\n" "$path"; fi; done; '
    'id -u; printf "HOME=%s\\n" "$HOME"'
)
_READ = (
    "printf 'root='; cat /root/.phase0_disk_sentinel; "
    "printf '\\ntmp='; cat /tmp/.phase0_disk_sentinel; "
    "printf '\\nhome_ohm='; if [ -d /home/ohm ]; then "
    "if [ -f /home/ohm/.phase0_disk_sentinel ]; then "
    "cat /home/ohm/.phase0_disk_sentinel; else printf 'missing'; fi; "
    "else printf 'directory_absent'; fi; printf '\\n'"
)


def _redact(value: str) -> str:
    for name in ("CELESTO_API_KEY", "LLM_API_KEY"):
        secret = os.environ.get(name)
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


def _guarded_run(
    computer: Any, step: str, command: str, allowed: dict[str, str]
) -> Any:
    if command != allowed.get(step) or computer.provider != "cloud":
        raise ValueError(
            f"guest command guard rejected step={step!r} or execution target"
        )
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
    result = computer.run(command, timeout=30)
    if result.exit_code != 0:
        raise RuntimeError(
            f"guest command step={step} exit_code={result.exit_code}; "
            f"stderr={_redact(result.stderr[:500])!r}"
        )
    print(f"GUEST_COMMAND_RESULT step={step} exit_code=0")
    return result


def run() -> int:
    from celesto import Computer

    reap_orphans()
    computer = Computer(provider="cloud", lifetime="ephemeral")
    logical_name = f"sbx-{secrets.token_hex(8)}"
    computer_id: str | None = None
    primary_error: Exception | None = None
    cleanup_error: Exception | None = None
    try:
        boot_started = time.monotonic()
        computer.start()
        boot_seconds = time.monotonic() - boot_started
        computer_id = computer.id
        if not computer_id:
            raise RuntimeError("ephemeral cloud create returned without a computer ID")
        record_guest(computer_id, logical_name)
        print(
            f"EPHEMERAL_COMPUTER_CREATED logical_name={logical_name} "
            f"computer_id={computer_id} boot_to_ready_s={boot_seconds:.3f}"
        )

        inventory = _guarded_run(
            computer, "path_inventory", _INVENTORY, {"path_inventory": _INVENTORY}
        )
        available = set(inventory.stdout.splitlines())
        home_exists = "/home/ohm=present" in available
        uid = next(
            (line for line in inventory.stdout.splitlines() if line.isdigit()),
            "unknown",
        )
        home = next(
            (
                line.removeprefix("HOME=")
                for line in inventory.stdout.splitlines()
                if line.startswith("HOME=")
            ),
            "unknown",
        )
        print(
            f"GUEST_IDENTITY uid={uid} home={home} "
            f"home_ohm_exists={str(home_exists).lower()}"
        )

        sentinels = {
            "root": secrets.token_hex(16),
            "tmp": secrets.token_hex(16),
            "home_ohm": secrets.token_hex(16),
        }
        write_command = (
            f"printf '%s' '{sentinels['root']}' > /root/.phase0_disk_sentinel; "
            f"printf '%s' '{sentinels['tmp']}' > /tmp/.phase0_disk_sentinel; "
            + (
                f"printf '%s' '{sentinels['home_ohm']}' > /home/ohm/.phase0_disk_sentinel"
                if home_exists
                else "true"
            )
        )
        _guarded_run(
            computer,
            "write_sentinels",
            write_command,
            {"write_sentinels": write_command},
        )
        computer_id_before = computer.id
        computer.stop()
        print(f"EPHEMERAL_STOP_RESULT ok=true computer_id={computer_id_before}")
        computer.resume()
        same_id = computer.id == computer_id_before
        print(f"EPHEMERAL_RESUME_RESULT ok=true same_id={str(same_id).lower()}")

        after = _guarded_run(
            computer, "read_sentinels", _READ, {"read_sentinels": _READ}
        )
        lines = dict(
            line.split("=", 1)
            for line in after.stdout.strip().splitlines()
            if "=" in line
        )
        survived = {
            path: lines.get(path) == sentinel
            for path, sentinel in sentinels.items()
            if path != "home_ohm" or home_exists
        }
        for path, found in survived.items():
            print(f"SENTINEL_RESULT path={path} survived={str(found).lower()}")
        if not home_exists:
            print(
                "SENTINEL_RESULT path=home_ohm survived=not_tested directory_absent=true"
            )
        if not same_id or not all(survived.values()):
            raise RuntimeError(
                "ephemeral stop/resume changed guest ID or lost a sentinel"
            )
    except Exception as exc:  # noqa: BLE001 - cleanup must run after provider failures.
        primary_error = exc
        if computer.id:
            computer_id = computer.id
            try:
                record_guest(computer_id, logical_name)
            except Exception as registry_error:  # noqa: BLE001 - retain the primary failure.
                cleanup_error = registry_error
        frames = traceback.extract_tb(exc.__traceback__)
        last = frames[-1] if frames else None
        location = f"{last.filename}:{last.lineno}" if last else "unavailable"
        print(
            f"FAIL step=ephemeral_disk error={_redact(repr(exc))} last_frame={location}"
        )
    finally:
        if computer_id:
            try:
                delete_guest(computer_id, computer=computer, name=logical_name)
            except Exception as exc:  # noqa: BLE001 - preserve incomplete cleanup evidence.
                cleanup_error = cleanup_error or exc
        else:
            computer.close()

    if cleanup_error:
        print(f"CLEANUP_FAILURE error={_redact(repr(cleanup_error))}")
        return 1
    if primary_error:
        return 1
    print("PASS ephemeral_disk_stop_resume_probe")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
