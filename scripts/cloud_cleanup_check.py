#!/usr/bin/env python3
"""Report the observed Cloud inventory count without printing IDs or credentials."""
from __future__ import annotations

import sys

from scripts.reap_orphans import DEFAULT_LIMIT, _run_cli


def main() -> int:
    payload = _run_cli(
        ["computer", "list", "--cloud", "--json", "--limit", str(DEFAULT_LIMIT)],
        "final cloud inventory",
    )
    data = payload.get("data") or {}
    computers = data.get("computers")
    if not isinstance(computers, list):
        print("cloud_guest_count=unknown reason=inventory_missing", file=sys.stderr)
        return 2
    count = len(computers)
    print(f"cloud_guest_count={count}")
    if data.get("possibly_truncated"):
        print("cloud_guest_inventory_warning=possibly_truncated")
    return 0 if count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
