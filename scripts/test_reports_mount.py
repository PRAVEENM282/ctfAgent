#!/usr/bin/env python3
"""Prove the container user can write and remove a report-volume file."""
from __future__ import annotations

import os
from pathlib import Path

EXPECTED_UID = 10001
REPORTS_ROOT = Path("/app/reports")


def main() -> int:
    if os.getuid() != EXPECTED_UID:
        raise RuntimeError(f"unexpected_container_uid={os.getuid()} expected={EXPECTED_UID}")
    if not REPORTS_ROOT.is_dir():
        raise RuntimeError(f"reports_directory_missing={REPORTS_ROOT}")
    probe = REPORTS_ROOT / f".container-write-probe-{os.getpid()}"
    payload = b"vulnforge-reports-write-probe"
    try:
        with probe.open("xb") as handle:
            handle.write(payload)
        if probe.read_bytes() != payload:
            raise RuntimeError("reports write probe read-back mismatch")
    finally:
        try:
            probe.unlink()
        except FileNotFoundError:
            pass
    print(f"reports_mount_write=pass uid={os.getuid()} gid={os.getgid()} path=/app/reports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
