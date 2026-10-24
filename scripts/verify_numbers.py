#!/usr/bin/env python3
"""Recompute report metrics from PostgreSQL ledger rows and raw evidence."""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
from pathlib import Path
from statistics import median

import psycopg


def p90(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[math.ceil(0.9 * len(ordered)) - 1]


async def collect(database_url: str) -> dict[str, object]:
    async with await psycopg.AsyncConnection.connect(database_url, row_factory=psycopg.rows.dict_row) as connection:
        cursor = await connection.execute(
            """
            SELECT run_id, sandbox_name, state, wall_clock_s,
                   boot_to_ready_s, celesto_duration_s,
                   celesto_cost_usd, llm_cost_usd, total_cost_usd,
                   token_input, token_output
            FROM runs
            WHERE sandbox_name <> 'sbx-seeddemo1'
            ORDER BY created_at, run_id
            """
        )
        rows = [dict(row) for row in await cursor.fetchall()]
    measured = [row for row in rows if row.get("wall_clock_s") is not None and row.get("boot_to_ready_s") is not None]
    wall = [float(row["wall_clock_s"]) for row in measured]
    boot = [float(row["boot_to_ready_s"]) for row in measured]
    success = [row.get("state") == "succeeded" for row in measured]
    costs = [float(row["total_cost_usd"]) for row in measured if row.get("total_cost_usd") is not None]
    result = {
        "ledger_rows": len(rows),
        "measured_rows": len(measured),
        "success_count": sum(success),
        "success_rate": sum(success) / len(success) if success else None,
        "median_wall_clock_s": median(wall) if wall else None,
        "p90_wall_clock_s": p90(wall) if wall else None,
        "median_boot_to_ready_s": median(boot) if boot else None,
        "total_cost_usd": sum(costs) if costs else None,
        "token_input": sum(int(row.get("token_input") or 0) for row in measured),
        "token_output": sum(int(row.get("token_output") or 0) for row in measured),
        "null_cost_rows_excluded": sum(row.get("total_cost_usd") is None for row in rows),
        "rate_sources": {
            "celesto": "computed_from_duration at brief rate $0.015/hr; not provider billing",
            "llm": "computed_from_tokens at configured free-model rate 0",
        },
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.database_url:
        print("BLOCKED-USER DATABASE_URL is not configured; no ledger-derived numbers claimed")
        return 2
    try:
        result = asyncio.run(collect(args.database_url))
    except Exception as exc:  # noqa: BLE001 - report unavailable runtime safely.
        print(f"BLOCKED-USER ledger read failed error_type={type(exc).__name__}")
        return 2
    text = "# Numbers provenance\n\n```json\n" + json.dumps(result, indent=2, default=str) + "\n```\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
