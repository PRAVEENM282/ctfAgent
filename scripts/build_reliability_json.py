#!/usr/bin/env python3
"""Build a reliability report from observed successes and sampled failures."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.evaluation import summarize_runs

EVIDENCE_ROOT = ROOT / "reports" / "evidence"
OUT = ROOT / "reports" / "reliability.json"


def _run_rows(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if "success" in value and isinstance(value.get("sandbox_name"), str):
            found.append(value)
        for child in value.values():
            found.extend(_run_rows(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_run_rows(child))
    return found


def collect_runs() -> tuple[list[dict[str, Any]], list[str], int, int]:
    by_sandbox: dict[str, dict[str, Any]] = {}
    source_paths: set[str] = set()
    observed_success_rows = 0
    observed_failure_rows = 0
    for path in sorted(EVIDENCE_ROOT.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rows = _run_rows(payload)
        if not rows:
            continue
        relative_path = path.relative_to(ROOT).as_posix()
        source_paths.add(relative_path)
        for row in rows:
            if row.get("success") is True:
                observed_success_rows += 1
            else:
                observed_failure_rows += 1
            sandbox_name = str(row["sandbox_name"])
            if sandbox_name not in by_sandbox:
                retained = copy.deepcopy(row)
                retained["evidence_sources"] = [relative_path]
                by_sandbox[sandbox_name] = retained
            elif relative_path not in by_sandbox[sandbox_name]["evidence_sources"]:
                by_sandbox[sandbox_name]["evidence_sources"].append(relative_path)
    rows = sorted(
        by_sandbox.values(),
        key=lambda row: (float(row["wall_clock_s"]), str(row["sandbox_name"])),
    )
    return rows, sorted(source_paths), observed_success_rows, observed_failure_rows


def _failure_category(row: dict[str, Any]) -> str:
    return str(
        row.get("provider_code")
        or row.get("error_code")
        or row.get("error_type")
        or "unknown_failure"
    )


def select_failures(rows: list[dict[str, Any]], limit: int = 8) -> list[dict[str, Any]]:
    failures = [row for row in rows if row.get("success") is False]
    for row in failures:
        row["failure_category"] = _failure_category(row)
    distinct: list[dict[str, Any]] = []
    selected_names: set[str] = set()
    for row in sorted(failures, key=lambda item: (item["failure_category"], item["sandbox_name"])):
        if row["failure_category"] not in {item["failure_category"] for item in distinct}:
            distinct.append(row)
            selected_names.add(str(row["sandbox_name"]))
    remaining = [row for row in failures if str(row["sandbox_name"]) not in selected_names]
    selected = distinct + remaining
    return selected[:limit]


def main() -> None:
    all_rows, source_paths, observed_success_rows, observed_failure_rows = collect_runs()
    successes = [row for row in all_rows if row.get("success") is True]
    failures = select_failures(all_rows)
    rows = successes + failures
    if not successes:
        raise SystemExit("no observed successful evidence rows found")
    if len(failures) < 8:
        raise SystemExit("fewer than eight observed failure rows are available")
    report = summarize_runs(rows)
    report["successes_only"] = False
    report["success_rate_semantics"] = "successful retained rows divided by all retained rows"
    report["source_evidence_paths"] = source_paths
    report["observed_success_rows_before_deduplication"] = observed_success_rows
    report["observed_failure_rows_before_deduplication"] = observed_failure_rows
    report["retained_success_count"] = len(successes)
    report["retained_failure_count"] = len(failures)
    report["duplicate_rows_collapsed"] = (
        observed_success_rows + observed_failure_rows - len(all_rows)
    )
    report["notes"] = (
        "All unique successful evidence rows are retained. Eight representative "
        "failure rows are included with failure_category; remaining raw failures "
        "remain under reports/evidence for auditability."
    )
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "status": "written",
                "run_count": report["run_count"],
                "success_rate": report["success_rate"],
                "source_success_rows": observed_success_rows,
                "source_failure_rows": observed_failure_rows,
                "retained_successes": len(successes),
                "retained_failures": len(failures),
            }
        )
    )


if __name__ == "__main__":
    main()
