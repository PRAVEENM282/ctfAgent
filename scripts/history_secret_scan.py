#!/usr/bin/env python3
"""Scan every reachable Git revision for credential-shaped content without printing it."""
from __future__ import annotations

import re
import subprocess
import sys

PATTERNS = (
    ("celesto_key", re.compile(rb"\bcel_[A-Za-z0-9_-]{20,}\b")),
    ("openai_key", re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("private_key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "credential_assignment",
        re.compile(
            rb"(?i)\b(?:CELESTO_API_KEY|LLM_API_KEY|OPERATOR_TOKEN|"
            rb"API[_-]?KEY|ACCESS[_-]?TOKEN|APPROVAL[_-]?TOKEN|PASSWORD|SECRET)"
            rb"\s*[:=]\s*(?!replace-me|replace-with|<REDACTED>|\[REDACTED\]|"
            rb"unknown|none|null|example)[A-Za-z0-9._~+/-]{16,}"
        ),
    ),
    (
        "bearer_token",
        re.compile(rb"(?i)\bBearer\s+(?!\[REDACTED\])[A-Za-z0-9._~+/-]{16,}"),
    ),
)
SECRET_PATH = re.compile(r"(?:^|/)\.env(?:$|\.(?!example$))|\.(?:pem|key|p12|pfx|token)$")


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], stderr=subprocess.STDOUT)


def main() -> int:
    commits = git("rev-list", "--all", "--reflog").decode().splitlines()
    findings: list[tuple[str, str, str]] = []
    tracked_secret_paths: set[str] = set()
    for commit in commits:
        paths = git("ls-tree", "-r", "--name-only", commit).decode().splitlines()
        for path in paths:
            if SECRET_PATH.search(path):
                tracked_secret_paths.add(path)
            try:
                content = git("show", f"{commit}:{path}")
            except subprocess.CalledProcessError:
                continue
            if b"\x00" in content:
                continue
            for label, pattern in PATTERNS:
                if pattern.search(content):
                    findings.append((commit, path, label))
    if tracked_secret_paths:
        for path in sorted(tracked_secret_paths):
            print(f"tracked_sensitive_path={path}", file=sys.stderr)
    if findings:
        for commit, path, label in findings:
            print(f"history_secret_finding commit={commit} path={path} kind={label}", file=sys.stderr)
        return 1
    print(
        f"history_secret_scan=passed commits={len(commits)} tracked_sensitive_paths={len(tracked_secret_paths)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
