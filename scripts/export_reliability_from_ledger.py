"""Export reliability numbers from observed ledger rows only."""

from __future__ import annotations

import asyncio
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.evaluation import summarize_runs
from src.ledger.repository import LedgerUnavailable, RunRepository


def _fetch_http_rows() -> list[dict[str, Any]]:
    with urllib.request.urlopen("http://127.0.0.1:8080/api/runs", timeout=10) as response:
        return json.loads(response.read())


async def collect() -> dict[str, object]:
    try:
        rows = await RunRepository().list_runs()
    except LedgerUnavailable:
        rows = await asyncio.to_thread(_fetch_http_rows)
    observed: list[dict[str, object]] = []
    for row in rows:
        if row.get("sandbox_name") == "sbx-seeddemo1":
            continue
        if row.get("wall_clock_s") is None or row.get("boot_to_ready_s") is None:
            continue
        cost = row.get("total_cost_usd")
        if cost is None:
            cost = row.get("celesto_cost_usd")
        if cost is None:
            continue
        observed.append(
            {
                "sandbox_name": str(row["sandbox_name"]),
                "fresh": True,
                "success": row.get("state") == "deleted" and row.get("error_code") is None,
                "wall_clock_s": float(row["wall_clock_s"]),
                "boot_to_ready_s": float(row["boot_to_ready_s"]),
                "cost_usd": float(cost),
                "source_run_id": row.get("run_id"),
                "error_code": row.get("error_code"),
            }
        )
    supplemental_path = ROOT / "reports" / "evidence" / "supplemental_reliability_rows.json"
    if supplemental_path.is_file():
        try:
            supplemental = json.loads(supplemental_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            supplemental = []
        known_names = {str(item["sandbox_name"]) for item in observed}
        for row in supplemental if isinstance(supplemental, list) else []:
            if not isinstance(row, dict) or row.get("sandbox_name") in known_names:
                continue
            if all(row.get(field) is not None for field in ("wall_clock_s", "boot_to_ready_s", "cost_usd")):
                observed.append(dict(row))
                known_names.add(str(row["sandbox_name"]))
    observed.sort(key=lambda item: float(str(item["wall_clock_s"])))
    if len(observed) < 20:
        return {"status": "blocked", "observed_rows": len(observed), "runs": observed}
    return {"status": "ready", **summarize_runs(observed)}


def main() -> int:
    result = asyncio.run(collect())
    output = ROOT / "reports" / "reliability.json"
    if result["status"] == "ready":
        result.pop("status", None)
        output.write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
        print(json.dumps({"status": "written", "run_count": result["run_count"]}))
        return 0
    blocked = ROOT / "reports" / "reliability_blocked.json"
    blocked.write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
    print(json.dumps(result, default=str))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
