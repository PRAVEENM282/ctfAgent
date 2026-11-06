#!/usr/bin/env python3
"""Concurrency probe: start N fresh guests at once with unique names.

The free Celesto Cloud trial retains a single sandbox and rate-limits creates
(HTTP 429), so true concurrency is exercised against the **local** runtime,
which runs multiple QEMU microVMs side by side. Each job gets a unique
``sbx-[random]`` name; the script records every job and deletes every guest it
created, then writes reports/concurrency.json with honest breakage notes.

Usage:
    CELESTO_PROVIDER=local python scripts/run_concurrency.py --jobs 5
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import config
from src.celesto_adapter import CelestoAdapter
from src.command_guard import CommandContext

_ROOT = Path(__file__).resolve().parents[1]
_REPORT = _ROOT / "reports" / "concurrency.json"

_CLOUD_LIMIT = (
    "The free Celesto Cloud trial retains a single sandbox and returns HTTP 429 to "
    "concurrent create requests before a guest is allocated, so cloud concurrency is "
    "bounded to one; see reports/evidence/cloud_rate_limit.log. This probe therefore "
    "exercises concurrency on the local QEMU runtime."
)


def _ctx(name: str) -> CommandContext:
    token = secrets.token_hex(6)
    return CommandContext(
        run_id=f"run-{token}",
        parent_run_id=None,
        batch_id=f"batch-{token}",
        attempt_id=f"attempt-{token}",
        sandbox_name=name,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=5)
    args = parser.parse_args()

    cfg = config.load_config()
    jobs: list[dict] = []
    guests: list = []
    lock = threading.Lock()
    names = [f"sbx-{secrets.token_hex(8)}" for _ in range(args.jobs)]
    assert len(set(names)) == len(names), "sandbox names must be unique"

    def launch(name: str) -> None:
        adapter = CelestoAdapter()
        started = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        job = {"sandbox_name": name, "started_at": started}
        try:
            guest = adapter.create_guest(
                sandbox_name=name, command_context_factory=_ctx
            )
            with lock:
                guests.append((adapter, guest))
            job["outcome"] = "created"
            job["boot_to_ready_s"] = round(guest.boot_to_ready_s, 3)
            job["egress_status"] = getattr(guest.egress_check, "status", None)
        except Exception as exc:  # noqa: BLE001 - record every job honestly.
            job["outcome"] = f"error:{type(exc).__name__}"
        with lock:
            jobs.append(job)

    threads = [threading.Thread(target=launch, args=(name,)) for name in names]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    deleted = 0
    for adapter, guest in guests:
        try:
            adapter.delete_guest(guest)
            deleted += 1
        except Exception as exc:  # noqa: BLE001 - note any teardown gap.
            print(f"teardown warning {guest.sandbox_name}: {type(exc).__name__}")

    created = sum(1 for j in jobs if j["outcome"] == "created")
    jobs.sort(key=lambda j: j["started_at"])
    report = {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "tested",
        "provider": cfg.celesto_provider,
        "requested_jobs": args.jobs,
        "created": created,
        "deleted": deleted,
        "jobs": jobs,
        "observed_limit": (
            "local QEMU runs concurrent guests; cloud trial is limited to one sandbox"
        ),
        "breakage_notes": (
            f"Launched {args.jobs} guests concurrently on provider "
            f"'{cfg.celesto_provider}' with unique names; {created} were created and "
            f"{deleted} were torn down with no name collisions. " + _CLOUD_LIMIT
        ),
        "evidence_path": "reports/evidence/cloud_rate_limit.log",
    }
    _REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {_REPORT}: created={created} deleted={deleted}")
    return 0 if created == args.jobs and deleted == created else 1


if __name__ == "__main__":
    raise SystemExit(main())
