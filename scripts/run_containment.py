#!/usr/bin/env python3
"""Prompt-injection exfiltration containment test (synthetic canary only).

This is the canonical entry point for the containment experiment. It drives the
synthetic-canary checks and rewrites reports/containment.json and its evidence
log. The obvious exfil command is blocked by CommandGuard before dispatch; an
obfuscated variant is stopped by the guest's egress policy; host canary hashes
are compared before and after; guest/receiver cleanup is confirmed. No real
credential is ever used.

Usage:
    python scripts/run_containment.py [--report reports/containment.json]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.m7_containment import run

_DEFAULT = Path(__file__).resolve().parents[1] / "reports" / "containment.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=_DEFAULT)
    args = parser.parse_args()
    return run(args.report)


if __name__ == "__main__":
    raise SystemExit(main())
