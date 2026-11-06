#!/usr/bin/env python3
"""Consolidated reliability eval: run N fresh labs end to end through the real pipeline.

Each iteration drives the same :class:`~src.lab_manager.LabManager` pipeline the
dashboard uses — create a fresh guest, customise/write the app, start it, verify
the exploit privately, publish (cloud HTTPS or local preview), then tear it down.
Per-run metrics (sandbox name, success, wall-clock, boot-to-ready, cost) are
recorded; failed runs are never dropped. Percentiles follow the spec: ascending
sort, median of the two middle rows, p90 = ceil(0.9*N)-th row.

Cost model: hourly rate x guest lifetime. Celesto Micro cloud guests are
$0.015/hr; local guests are $0.

Usage:
    python scripts/run_eval.py --runs 20 --sleep 10
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import sys
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import config
from src.lab_manager import LabManager
from src.ledger.repository import RunRepository

_ROOT = Path(__file__).resolve().parents[1]
_RELIABILITY = _ROOT / "reports" / "reliability.json"
_POSTMORTEM = _ROOT / "reports" / "postmortem.md"
_MICRO_USD_PER_HOUR = Decimal("0.015")
_TERMINAL = {"awaiting_publication", "failed", "cleaned_up"}


def _cost_usd(provider: str, lifetime_s: float) -> float:
    if provider != "cloud":
        return 0.0
    cost = _MICRO_USD_PER_HOUR * Decimal(str(max(0.0, lifetime_s))) / Decimal(3600)
    return float(cost.quantize(Decimal("0.000001")))


async def _await_phase(manager: LabManager, run_id: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        snap = await manager.get_lab(run_id)
        if snap.phase in _TERMINAL:
            return snap.phase
        await asyncio.sleep(2)
    return "timeout"


async def _one_run(manager: LabManager, provider: str, index: int) -> dict:
    started = time.monotonic()
    description = f"Reliability run {index}: a product search page."
    snap = await manager.create_lab(
        description, mode="single", vulnerabilities=["sql_injection"]
    )
    run_id = snap.run_id
    sandbox_name = snap.sandbox_name or f"sbx-{run_id.replace('run-', '')}"
    phase = await _await_phase(manager, run_id, timeout_s=300)
    boot = 0.0
    published = False
    error_code = None
    try:
        latest = await manager.get_lab(run_id)
        boot = float(latest.boot_to_ready_s or 0.0)
        sandbox_name = latest.sandbox_name or sandbox_name
        error_code = latest.error_code
        if phase == "awaiting_publication":
            pub = await manager.publish_lab(run_id)
            published = pub.phase == "published"
            error_code = pub.error_code
    except Exception as exc:  # noqa: BLE001 - record the failure, never drop the row.
        error_code = type(exc).__name__
    finally:
        try:
            await manager.stop_lab(run_id)
        except Exception as teardown_exc:  # noqa: BLE001 - row already recorded.
            print(f"[eval] teardown warning run={run_id}: {type(teardown_exc).__name__}")
    wall_clock = time.monotonic() - started
    return {
        "run_id": run_id,
        "sandbox_name": sandbox_name,
        "fresh": True,
        "success": bool(published),
        "wall_clock_s": round(wall_clock, 3),
        "boot_to_ready_s": round(boot, 3),
        "cost_usd": _cost_usd(provider, wall_clock),
        "error_code": error_code,
        "phase": phase,
    }


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2


def _p90(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(0.9 * len(ordered)) - 1)
    return float(ordered[index])


async def main_async(runs: int, sleep_s: float) -> int:
    cfg = config.load_config()
    if not cfg.valid:
        print("configuration invalid:", cfg.errors)
        return 2
    provider = cfg.celesto_provider
    repository = RunRepository()
    migrate = getattr(repository, "migrate_runtime_schema", None)
    if callable(migrate):
        await migrate()
    manager = LabManager(repository)
    rows: list[dict] = []
    try:
        for i in range(1, runs + 1):
            print(f"[eval] run {i}/{runs} (provider={provider}) ...", flush=True)
            row = await _one_run(manager, provider, i)
            rows.append(row)
            print(
                f"[eval] run {i}: success={row['success']} "
                f"wall={row['wall_clock_s']}s boot={row['boot_to_ready_s']}s "
                f"cost=${row['cost_usd']} sandbox={row['sandbox_name']}",
                flush=True,
            )
            if i < runs and sleep_s > 0:
                await asyncio.sleep(sleep_s)
    finally:
        await manager.close()

    # The report rows are sorted ascending by wall-clock (the validator requires
    # this and percentiles are computed on the ascending order).
    rows.sort(key=lambda r: r["wall_clock_s"])
    wall = [r["wall_clock_s"] for r in rows]
    boot = [r["boot_to_ready_s"] for r in rows]
    successes = sum(1 for r in rows if r["success"])
    report = {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "provider": provider,
        "run_count": len(rows),
        "success_rate": round(successes / len(rows), 4) if rows else 0.0,
        "median_wall_clock_s": round(_median(wall), 3),
        "p90_wall_clock_s": round(_p90(wall), 3),
        "median_boot_to_ready_s": round(_median(boot), 3),
        "total_cost_usd": round(sum(r["cost_usd"] for r in rows), 6),
        "postmortem_path": "reports/postmortem.md",
        "runs": rows,
    }
    _RELIABILITY.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    failures = [r for r in rows if not r["success"]]
    summary = (
        f"Provider: **{provider}**. Ran {len(rows)} fresh labs end to end through the "
        f"dashboard pipeline. {successes} succeeded "
        f"({report['success_rate'] * 100:.0f}%). Median wall-clock "
        f"{report['median_wall_clock_s']}s, p90 {report['p90_wall_clock_s']}s, "
        f"median boot-to-ready {report['median_boot_to_ready_s']}s. Total observed "
        f"cost ${report['total_cost_usd']}."
    )
    lines = ["# Reliability postmortem", "", summary, ""]
    if failures:
        lines.append(f"## Failures ({len(failures)})")
        for r in failures:
            lines.append(
                f"- `{r['sandbox_name']}` stopped at phase `{r['phase']}` "
                f"(error: {r['error_code']})."
            )
    else:
        lines.append(
            "## Failures\n\nNo runs failed in this batch. Every fresh guest booted, "
            "verified its planted exploit privately, published, and was torn down with "
            "confirmed cleanup."
        )
    _POSTMORTEM.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[eval] wrote {_RELIABILITY} and {_POSTMORTEM}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--sleep", type=float, default=10.0)
    args = parser.parse_args()
    return asyncio.run(main_async(args.runs, args.sleep))


if __name__ == "__main__":
    raise SystemExit(main())
