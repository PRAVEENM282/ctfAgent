from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from src.agent.test_client import TEST_SOURCE
from src.challenge import build_variation, static_check
from src.verification import build_benign_path, verify_private_target


def test_deterministic_bundle_source_passes_all_private_profile_checks(tmp_path: Path) -> None:
    spec = build_variation("profile-source-smoke", mode="bundle")
    database_path = tmp_path / "app.db"
    fixture_root = tmp_path / "vulnforge_files"
    (fixture_root / "public").mkdir(parents=True)
    (fixture_root / "public" / "README.txt").write_text("synthetic public file\n", encoding="utf-8")
    (fixture_root / "secret.txt").write_text(
        spec.marker_for("path_traversal"), encoding="utf-8"
    )
    with sqlite3.connect(database_path) as database:
        database.execute("CREATE TABLE secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        database.execute("INSERT INTO secrets VALUES (?, ?)", ("flag", spec.flag))
        database.execute("CREATE TABLE records (id TEXT PRIMARY KEY, name TEXT, email TEXT)")
        database.executemany(
            "INSERT INTO records VALUES (?, ?, ?)",
            [(record["id"], record["name"], record["email"]) for record in spec.records],
        )
        database.execute(
            "CREATE TABLE profiles (id INTEGER PRIMARY KEY, username TEXT, email TEXT, secret TEXT)"
        )
        database.executemany(
            "INSERT INTO profiles VALUES (?, ?, ?, ?)",
            [
                (1, "learner-one", "one@example.invalid", "synthetic-public-profile"),
                (2, "learner-two", "two@example.invalid", spec.marker_for("idor")),
            ],
        )

    port = 18765
    source = (
        TEST_SOURCE.replace("/root/app.db", str(database_path))
        .replace("/root/vulnforge_files", str(fixture_root))
        .replace("('0.0.0.0', 8000)", f"('127.0.0.1', {port})")
    )
    assert static_check(source, spec).passed is True
    process = subprocess.Popen([sys.executable, "-c", source], env=os.environ.copy())
    try:
        for _ in range(30):
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}{build_benign_path(spec)}", timeout=1
                ).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("deterministic profile app did not become ready")

        result = verify_private_target(
            spec,
            lambda path: urllib.request.urlopen(
                f"http://127.0.0.1:{port}{path}", timeout=2
            ).read(),
            source=source,
        )
    finally:
        process.terminate()
        process.wait(timeout=5)

    assert result.passed is True
    assert set(result.profile_results) == set(spec.vulnerabilities)
