"""Scan workspace source files for likely committed credentials."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", ".pytest_cache", ".ruff_cache"}
SECRET_PATTERNS = (
    re.compile(r"\bcel_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def scan_workspace(root: Path = ROOT) -> list[str]:
    findings: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.name.startswith(".env") and path.name != ".env.example":
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if any(pattern.search(content) for pattern in SECRET_PATTERNS):
            findings.append(path.relative_to(root).as_posix())
    return findings


def main() -> int:
    findings = scan_workspace()
    if findings:
        print("Potential credentials found in:", file=sys.stderr)
        for name in findings:
            print(f"- {name}", file=sys.stderr)
        return 1
    print("Secret scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
