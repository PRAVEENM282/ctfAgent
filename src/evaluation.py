"""Pure reliability calculations; never synthesize missing run evidence."""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any


def summarize_runs(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    runs = [dict(row) for row in rows]
    if not runs:
        raise ValueError("at least one real run is required")
    for row in runs:
        for field in ("wall_clock_s", "boot_to_ready_s", "cost_usd"):
            row[field] = float(row[field])
    validate_variation_seeds(
        [str(row["variation_seed"]) for row in runs if "variation_seed" in row]
    ) if any("variation_seed" in row for row in runs) else None
    ordered = sorted(runs, key=lambda row: float(row["wall_clock_s"]))
    wall = [float(row["wall_clock_s"]) for row in ordered]
    boot = [float(row["boot_to_ready_s"]) for row in ordered]
    costs = [float(row["cost_usd"]) for row in ordered]
    return {
        "run_count": len(ordered),
        "runs": ordered,
        "success_rate": sum(bool(row["success"]) for row in ordered) / len(ordered),
        "median_wall_clock_s": _median(wall),
        "p90_wall_clock_s": _percentile_rank(wall, 0.9),
        "median_boot_to_ready_s": _median(boot),
        "total_cost_usd": sum(costs),
        "postmortem_path": "reports/postmortem.md",
    }


def validate_variation_seeds(seeds: list[str]) -> None:
    if len(seeds) != len(set(seeds)):
        raise ValueError("variation seeds must be unique")


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _percentile_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(1, math.ceil(percentile * len(ordered))) - 1]
