#!/usr/bin/env python3
"""Check that runtime environment variables are documented with safe placeholders."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ENV_PATTERNS = (
    re.compile(r"os\.environ\.get\(\s*['\"]([A-Z][A-Z0-9_]+)['\"]"),
    re.compile(r"os\.environ\[['\"]([A-Z][A-Z0-9_]+)['\"]\]"),
    re.compile(r"os\.getenv\(\s*['\"]([A-Z][A-Z0-9_]+)['\"]"),
)
SECRET_KEYS = {"CELESTO_API_KEY", "LLM_API_KEY", "OPERATOR_TOKEN"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    example = root / ".env.example"
    values: dict[str, str] = {}
    for line in example.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    found: set[str] = set()
    for path in list((root / "src").rglob("*.py")) + list((root / "scripts").rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in ENV_PATTERNS:
            found.update(pattern.findall(text))
    missing = sorted(found - values.keys())
    unsafe = sorted(key for key in found & SECRET_KEYS if values.get(key, "") and values[key] not in {"replace-me", "replace-with-a-token"})
    print(f"env_vars_found={len(found)}")
    print("missing=" + ",".join(missing))
    print("unsafe_secret_placeholders=" + ",".join(unsafe))
    if missing or unsafe:
        return 1
    print("env_example=complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
