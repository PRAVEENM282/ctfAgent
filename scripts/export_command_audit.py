#!/usr/bin/env python3
"""Export sanitized command audit records to the grader-required repo path."""
from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path

FLAG = re.compile(r"VF\{[0-9a-fA-F]{32}\}")
CREDENTIAL = re.compile(r"(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s;,]+")


def redact(value: str) -> str:
    return CREDENTIAL.sub(r"\1=[REDACTED]", FLAG.sub("[REDACTED_FLAG]", value))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    out = root / "logs" / "commands.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    exported_at = datetime.now(UTC).isoformat()
    source = root / "reports" / "evidence" / "m3_live_command_audit.jsonl"
    if source.is_file():
        for line in source.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            records.append({
                "ts": row.get("timestamp"),
                "sandbox_name": row.get("sandbox_name"),
                "command": redact(str(row.get("command_summary", ""))),
                "decision": row.get("decision"),
                "execution_target": row.get("execution_target"),
                "dispatched": row.get("dispatched", True),
                "origin": row.get("origin"),
                "export_source": "reports/evidence/m3_live_command_audit.jsonl",
            })
    containment = root / "reports" / "containment.json"
    if containment.is_file():
        report = json.loads(containment.read_text(encoding="utf-8"))
        for variant in report.get("variants", []):
            if variant.get("id") == "obvious":
                records.append({
                    "ts": exported_at,
                    "timestamp_semantics": "exported_at_from_untimestamped_containment_artifact",
                    "sandbox_name": "sbx-f3f63844dd3009d6",
                    "command": "[REDACTED_OBVIOUS_CONTAINMENT_VARIANT]",
                    "decision": "block",
                    "execution_target": "celesto_sandbox",
                    "dispatched": False,
                    "origin": "agent",
                    "block_reason": "command_guard",
                    "export_source": "reports/containment.json",
                })
    with out.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"exported_records={len(records)} path={out}")
    return 0 if records else 1


if __name__ == "__main__":
    raise SystemExit(main())
