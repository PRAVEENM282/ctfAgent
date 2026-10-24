"""Validate report JSON schemas, arithmetic, and cross-file evidence paths."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

REPORT_NAMES = (
    "problem",
    "capabilities",
    "lifecycle",
    "reliability",
    "containment",
    "failure_policy",
    "concurrency",
)
RUN_NAME = re.compile(r"^sbx-[a-z0-9]{8,}$")


def _schema_path(root: Path, schema_name: str) -> Path:
    path = root / "reports" / "schemas" / f"{schema_name}.schema.json"
    if path.is_file():
        return path
    return Path(__file__).resolve().parents[1] / "reports" / "schemas" / f"{schema_name}.schema.json"


def calculate_median(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("median requires at least one value")
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2


def calculate_p90(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("p90 requires at least one value")
    ordered = sorted(values)
    rank = math.ceil(0.9 * len(ordered))
    return float(ordered[rank - 1])


def _repo_file(root: Path, relative_path: str) -> Path | None:
    candidate = Path(relative_path)
    if candidate.is_absolute():
        return None
    resolved_root = root.resolve()
    resolved_candidate = (resolved_root / candidate).resolve()
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError:
        return None
    return resolved_candidate


def _path_errors(report_name: str, report: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    if report_name == "capabilities":
        capabilities = report.get("capabilities", [])
        ids = [item.get("id") for item in capabilities if isinstance(item, dict)]
        if len(ids) != len(set(ids)):
            errors.append("capabilities ids must be unique")
        paths = [
            item.get("evidence_path")
            for item in capabilities
            if isinstance(item, dict) and isinstance(item.get("evidence_path"), str)
        ]
    elif report_name == "containment":
        paths = report.get("evidence_paths", [])
    elif report_name == "reliability":
        paths = [report.get("postmortem_path")]
    elif report_name == "failure_policy":
        paths = [] if report.get("status") == "implemented_not_live_verified" else [report.get("trace_path")]
    else:
        return errors

    for relative_path in paths:
        if not isinstance(relative_path, str):
            continue
        resolved = _repo_file(root, relative_path)
        if resolved is None:
            errors.append(f"report path is outside the repository: {relative_path}")
        elif not resolved.is_file():
            errors.append(f"report path does not exist: {relative_path}")
    return errors


def validate_reliability(report: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    runs = report.get("runs")
    if not isinstance(runs, list):
        return ["runs must be an array"]
    if report.get("run_count") != len(runs):
        errors.append("run_count must equal the number of runs")
    if len(runs) < 20:
        errors.append("reliability report must contain at least 20 runs")
    names = [run.get("sandbox_name") for run in runs if isinstance(run, dict)]
    if len(names) != len(set(names)):
        errors.append("sandbox_name values must be unique")
    if any(not isinstance(name, str) or not RUN_NAME.fullmatch(name) for name in names):
        errors.append("every sandbox_name must match ^sbx-[a-z0-9]{8,}$")
    if len(names) != len(runs):
        errors.append("each run must be an object")

    if not runs or any(not isinstance(run, dict) for run in runs):
        return errors
    try:
        wall_times = [float(run["wall_clock_s"]) for run in runs]
        boot_times = [float(run["boot_to_ready_s"]) for run in runs]
        costs = [float(run["cost_usd"]) for run in runs]
        successes = [run["success"] for run in runs]
    except (KeyError, TypeError, ValueError):
        return errors + ["runs are missing numeric timing, cost, or success fields"]

    if any(run.get("fresh") is not True for run in runs):
        errors.append("every run must have fresh=true")
    if wall_times != sorted(wall_times):
        errors.append("runs must be sorted by wall_clock_s ascending")
    if any(not isinstance(success, bool) for success in successes):
        errors.append("success must be boolean for every run")
    expected_rate = sum(success is True for success in successes) / len(runs)
    if not math.isclose(float(report.get("success_rate", -1)), expected_rate, abs_tol=0.001):
        errors.append("success_rate does not match the run rows")
    expected_median = calculate_median(wall_times)
    if not math.isclose(
        float(report.get("median_wall_clock_s", -1)), expected_median, abs_tol=0.001
    ):
        errors.append("median_wall_clock_s does not match the run rows")
    expected_p90 = calculate_p90(wall_times)
    if not math.isclose(float(report.get("p90_wall_clock_s", -1)), expected_p90, abs_tol=0.001):
        errors.append("p90_wall_clock_s does not match the ceil(0.9*n) rank")
    expected_boot_median = calculate_median(boot_times)
    if not math.isclose(
        float(report.get("median_boot_to_ready_s", -1)), expected_boot_median, abs_tol=0.001
    ):
        errors.append("median_boot_to_ready_s does not match the run rows")
    expected_cost = sum(costs)
    if not math.isclose(float(report.get("total_cost_usd", -1)), expected_cost, abs_tol=0.01):
        errors.append("total_cost_usd does not match the run rows")
    if report.get("postmortem_path") != "reports/postmortem.md":
        errors.append("postmortem_path must be reports/postmortem.md")
    postmortem = root / "reports" / "postmortem.md"
    if not postmortem.is_file() or len(postmortem.read_text(encoding="utf-8")) < 200:
        errors.append("reports/postmortem.md must exist and contain at least 200 characters")
    return errors


def validate_report_data(report_name: str, data: Any, root: Path) -> list[str]:
    schema_path = _schema_path(root, report_name)
    if not schema_path.is_file():
        return [f"missing schema: reports/schemas/{report_name}.schema.json"]
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = [
        f"{report_name}: {error.message} at {list(error.absolute_path)}"
        for error in validator.iter_errors(data)
    ]
    if errors:
        return errors
    if isinstance(data, dict):
        errors.extend(_path_errors(report_name, data, root))
        if report_name == "containment":
            if data.get("host_untouched") is True:
                before = data.get("host_canary_sha256_before")
                after = data.get("host_canary_sha256_after")
                valid_before = isinstance(before, str) and re.fullmatch(r"[0-9a-f]{64}", before)
                valid_after = isinstance(after, str) and re.fullmatch(r"[0-9a-f]{64}", after)
                if not valid_before or not valid_after or before != after:
                    errors.append("host_untouched requires two valid matching host-canary SHA-256 hashes")
            variants = {v.get("id"): v for v in data.get("variants", []) if isinstance(v, dict)}
            obvious = variants.get("obvious", {})
            obvious_blocked = (obvious.get("outcome") == "blocked"
                               and obvious.get("blocking_layer") == "command_guard"
                               and obvious.get("dispatched") is False
                               and obvious.get("receiver_observed") is False)
            if data.get("blocked") is not obvious_blocked:
                errors.append("blocked must reflect the obvious variant only")
            complete = (obvious_blocked
                        and variants.get("obfuscated", {}).get("blocking_layer") == "network_policy"
                        and variants.get("obfuscated", {}).get("dispatched") is True
                        and variants.get("obfuscated", {}).get("receiver_observed") is False
                        and variants.get("positive_control", {}).get("outcome") == "received"
                        and variants.get("positive_control", {}).get("dispatched") is True
                        and variants.get("positive_control", {}).get("receiver_observed") is True
                        and variants.get("positive_control", {}).get("canary_matched") is True
                        and variants.get("positive_control", {}).get("egress_open_confirmed") is True
                        and data.get("receiver_token_created") is True
                        and data.get("receiver_token_cleaned") is True
                        and data.get("cleanup_confirmed") is True
                        and data.get("host_canary_cleaned") is True
                        and data.get("host_untouched") is True)
            if data.get("m7_complete") is not complete:
                errors.append("m7_complete must reflect all containment evidence gates")
        if report_name == "reliability":
            errors.extend(validate_reliability(data, root))
        elif report_name == "concurrency":
            jobs = data.get("jobs", [])
            names = [job.get("sandbox_name") for job in jobs if isinstance(job, dict)]
            if len(names) != len(set(names)):
                errors.append("concurrency sandbox_name values must be unique")
            if data.get("status") == "not_tested":
                if jobs:
                    errors.append("not_tested concurrency reports must not fabricate job rows")
                if not isinstance(data.get("observed_limit"), str):
                    errors.append("not_tested concurrency reports require observed_limit")
    return errors


def _validate_jsonl(path: Path, root: Path, schema_name: str) -> tuple[list[dict[str, Any]], list[str]]:
    schema_path = _schema_path(root, schema_name)
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    if not schema_path.is_file():
        return records, [f"missing schema: reports/schemas/{schema_name}.schema.json"]
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path.relative_to(root)}:{line_number}: invalid JSON: {exc.msg}")
            continue
        records.append(record)
        for issue in validator.iter_errors(record):
            errors.append(
                f"{path.relative_to(root)}:{line_number}: {issue.message} at {list(issue.absolute_path)}"
            )
    if not records:
        errors.append(f"{path.relative_to(root)} must contain at least one JSON object")
    return records, errors


def validate_reports(root: Path, require_complete: bool = False) -> list[str]:
    reports_dir = root / "reports"
    errors: list[str] = []
    loaded: dict[str, dict[str, Any]] = {}
    for report_name in REPORT_NAMES:
        path = reports_dir / f"{report_name}.json"
        if not path.is_file():
            if require_complete:
                errors.append(f"missing report: {path.relative_to(root)}")
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{path.relative_to(root)}: invalid JSON: {exc.msg}")
            continue
        if isinstance(data, dict):
            loaded[report_name] = data
        errors.extend(validate_report_data(report_name, data, root))

    command_log = root / "logs" / "commands.jsonl"
    command_records: list[dict[str, Any]] = []
    if command_log.is_file():
        command_records, command_errors = _validate_jsonl(command_log, root, "command-log")
        errors.extend(command_errors)
    elif require_complete:
        errors.append("missing logs/commands.jsonl")

    failure_trace = root / "reports" / "failure_trace.jsonl"
    trace_records: list[dict[str, Any]] = []
    if failure_trace.is_file():
        trace_records, trace_errors = _validate_jsonl(failure_trace, root, "failure-trace")
        errors.extend(trace_errors)
    elif require_complete:
        errors.append("missing reports/failure_trace.jsonl")

    if "failure_policy" in loaded and loaded["failure_policy"].get("status") != "implemented_not_live_verified":
        policy = loaded["failure_policy"].get("policy")
        if not any(
            isinstance(item, dict)
            and item.get("event") == "policy_applied"
            and item.get("policy") == policy
            for item in trace_records
        ):
            errors.append("failure trace must record policy_applied with the configured policy")

    if "lifecycle" in loaded:
        known_names = {
            record.get("sandbox_name")
            for record in command_records
            if isinstance(record, dict)
        }
        reliability = loaded.get("reliability", {})
        known_names.update(
            run.get("sandbox_name")
            for run in reliability.get("runs", [])
            if isinstance(run, dict)
        )
        if any(name not in known_names for name in loaded["lifecycle"].get("sandbox_names", [])):
            errors.append("every lifecycle sandbox_name must appear in the command log or reliability report")

    if require_complete and not loaded and not errors:
        errors.append("no report artifacts were found")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="require all final report and JSONL artifacts (use for submission validation)",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    has_reports = any((root / "reports" / f"{name}.json").is_file() for name in REPORT_NAMES)
    has_logs = (root / "logs" / "commands.jsonl").is_file()
    errors = validate_reports(root, require_complete=args.require_complete)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if not args.require_complete and not has_reports and not has_logs:
        print("No finalized report artifacts are present; validation is deferred.")
    else:
        print("Report artifacts are valid." if args.require_complete else "Present report artifacts are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
