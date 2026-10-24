"""Delete stale Celesto computers previously recorded by this project."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any

DEFAULT_LIMIT = 100
MANAGED_NAME = re.compile(r"^sbx-[0-9a-f]{16}$")
TRANSIENT_ATTEMPTS = 3
TRANSIENT_BACKOFF_SECONDS = (1, 2)
DELETE_POLL_SECONDS = 3
DELETE_TIMEOUT_SECONDS = 180


def _state_path() -> Path:
    return (
        Path(os.environ.get("VULNFORGE_STATE_DIR", "/var/lib/vulnforge"))
        / "celesto_guests.json"
    )


def _cli() -> str:
    sibling = Path(sys.executable).with_name("celesto")
    return str(sibling) if sibling.is_file() else (shutil.which("celesto") or "celesto")


def _redact(value: str) -> str:
    for key_name in ("CELESTO_API_KEY", "LLM_API_KEY"):
        secret = os.environ.get(key_name)
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


def _transient_error_kind(error: BaseException | str) -> str | None:
    message = repr(error) if isinstance(error, BaseException) else error
    for kind in ("ReadTimeout", "ConnectError"):
        if kind in message:
            return kind
    return None


def _retry_transient(step: str, operation: Any) -> Any:
    """Retry only provider-declared read/connect failures with bounded backoff."""
    for attempt in range(1, TRANSIENT_ATTEMPTS + 1):
        try:
            return operation()
        except Exception as exc:
            error_kind = _transient_error_kind(exc)
            if error_kind is None or attempt == TRANSIENT_ATTEMPTS:
                raise
            delay = TRANSIENT_BACKOFF_SECONDS[attempt - 1]
            print(
                f"TRANSIENT_RETRY step={step} attempt={attempt} "
                f"error={error_kind} delay_s={delay}"
            )
            time.sleep(delay)
    raise AssertionError("bounded retry loop exhausted without returning or raising")


def _run_cli_once(args: list[str], step: str) -> dict[str, Any]:
    command = [_cli(), *args]
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=180
        )
    except Exception as exc:
        raise RuntimeError(f"{step}: {exc!r}") from exc

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        detail = _redact(result.stderr or result.stdout)
        raise RuntimeError(
            f"{step}: invalid JSON response; exit={result.returncode}; {detail}"
        ) from exc

    if result.returncode != 0 or payload.get("ok") is not True:
        error = payload.get("error") or {}
        raise RuntimeError(
            f"{step}: exit={result.returncode}; code={error.get('code')!r}; "
            f"message={_redact(str(error.get('message', '')))!r}"
        )
    return payload


def _run_cli(args: list[str], step: str) -> dict[str, Any]:
    return _retry_transient(step, lambda: _run_cli_once(args, step))


def _load_registry(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise TypeError("managed guest registry must be a JSON object")
    registry: dict[str, dict[str, str]] = {}
    for computer_id, record in data.items():
        if not isinstance(computer_id, str) or not isinstance(record, dict):
            raise TypeError("managed guest registry has an invalid entry")
        name = record.get("name")
        if not isinstance(name, str) or not MANAGED_NAME.fullmatch(name):
            raise ValueError(
                f"managed guest registry has an invalid project name for {computer_id}"
            )
        registry[computer_id] = {"name": name}
    return registry


def record_guest(computer_id: str, name: str) -> None:
    """Persist a provider ID as project-owned immediately after creation."""
    if not computer_id or not MANAGED_NAME.fullmatch(name):
        raise ValueError("computer_id and a generated sbx-<16 hex> name are required")
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    registry = _load_registry(path)
    registry[computer_id] = {"name": name}
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def forget_guest(computer_id: str) -> None:
    """Remove a project-owned guest only after provider deletion is confirmed."""
    path = _state_path()
    registry = _load_registry(path)
    if computer_id in registry:
        del registry[computer_id]
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n")
        temporary.replace(path)


def _computer_exists_once(computer_id: str) -> bool:
    """Check one managed ID directly, avoiding ambiguous list pagination."""
    from celesto import Computer, VMNotFoundError

    try:
        computer = Computer.get(computer_id, provider="cloud")
    except VMNotFoundError:
        return False
    try:
        return computer.id == computer_id
    finally:
        computer.close()


def _computer_exists(computer_id: str) -> bool:
    return _retry_transient(
        f"lookup computer {computer_id}",
        lambda: _computer_exists_once(computer_id),
    )


def confirm_deleted(
    computer_id: str,
    *,
    started_at: float | None = None,
    timeout_seconds: float = DELETE_TIMEOUT_SECONDS,
) -> float:
    """Poll direct lookups until Celesto raises VMNotFoundError for this ID."""
    started_at = time.monotonic() if started_at is None else started_at
    deadline = time.monotonic() + timeout_seconds
    polls = 0
    while True:
        polls += 1
        try:
            if not _computer_exists(computer_id):
                duration = time.monotonic() - started_at
                forget_guest(computer_id)
                print(
                    f"DELETE_CONFIRMED computer_id={computer_id} "
                    f"duration_s={duration:.3f} polls={polls}"
                )
                return duration
        except Exception as exc:
            if _transient_error_kind(exc) is None:
                raise
            print(
                f"DELETE_POLL_RETRY computer_id={computer_id} "
                f"error={_transient_error_kind(exc)}"
            )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"timed out after {timeout_seconds:g}s waiting for VMNotFoundError "
                f"for managed computer {computer_id}; polls={polls}"
            )
        time.sleep(min(DELETE_POLL_SECONDS, remaining))


def delete_guest(
    computer_id: str, *, computer: Any | None = None, name: str | None = None
) -> float:
    """Delete one managed guest, then poll until its ID is independently absent."""
    started_at = time.monotonic()
    delete_error: Exception | None = None
    if computer is not None:
        try:
            computer.delete()
        except Exception as exc:  # noqa: BLE001 - deletion outcome may be ambiguous.
            delete_error = exc
            print(
                f"DELETE_REQUEST_UNCERTAIN computer_id={computer_id} "
                f"error={_redact(repr(exc))}"
            )
    if computer is None or delete_error is not None:
        try:
            _run_cli(
                ["computer", "delete", computer_id, "--cloud", "--json"],
                f"delete managed computer {computer_id}",
            )
        except Exception as exc:  # noqa: BLE001 - independent lookup decides whether retry worked.
            delete_error = delete_error or exc
            print(
                f"DELETE_REQUEST_RETRY_UNCERTAIN computer_id={computer_id} "
                f"error={_redact(repr(exc))}"
            )
    try:
        duration = confirm_deleted(computer_id, started_at=started_at)
    except Exception as confirm_error:
        if delete_error is not None:
            raise RuntimeError(
                f"delete request failed ({delete_error!r}) and absence confirmation failed "
                f"({confirm_error!r}) for {computer_id}"
            ) from confirm_error
        raise
    finally:
        if computer is not None:
            try:
                computer.close()
            except Exception as exc:  # noqa: BLE001 - client close must not hide delete evidence.
                print(
                    f"CLIENT_CLOSE_WARNING computer_id={computer_id} "
                    f"error={_redact(repr(exc))}"
                )
    label = f" name={name}" if name else ""
    print(f"DELETE_LIFECYCLE_COMPLETE computer_id={computer_id}{label}")
    return duration


def reap_orphans(*, dry_run: bool = False) -> list[str]:
    """Delete recorded project guests and refuse to touch untracked account guests."""
    list_payload = _run_cli(
        ["computer", "list", "--cloud", "--json", "--limit", str(DEFAULT_LIMIT)],
        "list cloud computers",
    )
    data = list_payload.get("data") or {}
    computers = data.get("computers")
    if not isinstance(computers, list):
        raise TypeError("cloud inventory response omitted data.computers")
    requested_limit = data.get("limit", DEFAULT_LIMIT)
    if not isinstance(requested_limit, int) or requested_limit < 1:
        raise TypeError("cloud inventory response omitted a valid limit")
    if len(computers) >= requested_limit:
        raise RuntimeError(
            f"cloud inventory reached the request limit; returned={len(computers)} "
            f"requested_limit={requested_limit}"
        )
    if data.get("possibly_truncated"):
        print(
            "INVENTORY_WARNING sdk_possibly_truncated=true "
            f"returned={len(computers)} requested_limit={requested_limit}"
        )
    live_ids = {
        item.get("computer_id")
        for item in computers
        if isinstance(item, dict) and isinstance(item.get("computer_id"), str)
    }
    path = _state_path()
    registry = _load_registry(path)
    for item in computers:
        if (
            isinstance(item, dict)
            and isinstance(item.get("computer_id"), str)
            and item.get("computer_id") in registry
        ):
            print(
                f"TRACKED_INVENTORY computer_id={item['computer_id']} "
                f"status={item.get('status', 'unknown')}"
            )
    untracked = sorted(live_ids - registry.keys())
    if untracked:
        for computer_id in untracked:
            print(f"UNTRACKED {computer_id}")
        raise RuntimeError(
            "untracked cloud computers found; refusing to delete resources not owned here"
        )

    # The SDK's list flag can be true for an empty page. Check every tracked ID
    # directly before deciding it is absent or needs cleanup.
    orphans = set(live_ids & registry.keys())
    for computer_id in sorted(registry.keys() - live_ids):
        if _computer_exists(computer_id):
            orphans.add(computer_id)
        else:
            print(f"ALREADY_ABSENT {computer_id}")
            if not dry_run:
                registry.pop(computer_id)
                temporary = path.with_suffix(".tmp")
                temporary.write_text(
                    json.dumps(registry, indent=2, sort_keys=True) + "\n"
                )
                temporary.replace(path)

    for computer_id in sorted(orphans):
        name = registry[computer_id]["name"]
        if dry_run:
            print(f"WOULD_DELETE {name} ({computer_id})")
            continue
        delete_guest(computer_id, name=name)
        registry.pop(computer_id, None)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n")
        temporary.replace(path)
    if not orphans:
        print("CLEAN: no recorded orphaned cloud computers")
    return orphans


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true", help="list managed computers without deleting"
    )
    args = parser.parse_args()
    step = "reap_orphans"
    try:
        reap_orphans(dry_run=args.dry_run)
        return 0
    except Exception as exc:  # noqa: BLE001 - report every failure with a redacted traceback location.
        frames = traceback.extract_tb(exc.__traceback__)
        frame = frames[-1] if frames else None
        location = f"{frame.filename}:{frame.lineno}" if frame else "unavailable"
        print(
            f"FAIL step={step} error={_redact(repr(exc))} last_frame={location}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
