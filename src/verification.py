"""Trusted, private verifier for generated challenge behavior."""

from __future__ import annotations

import hashlib
import json
import shlex
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.challenge import ChallengeVariation, StaticCheckResult, static_check
from src.vulnerability_profiles import profiles_for


class FixtureSeedError(RuntimeError):
    pass


class TrustedFixtureSeeder:
    """Seed the flag through a trusted file-transfer boundary, never a command string."""

    seed_path = "/root/.vulnforge_seed.json"

    def seed(
        self,
        spec: ChallengeVariation,
        *,
        upload: Callable[[str, bytes], None],
        execute: Callable[[str], object],
    ) -> None:
        payload = json.dumps(
            {
                "flag": spec.flag,
                "records": list(spec.records),
                "profiles": [
                    {
                        "id": 1,
                        "username": "learner-one",
                        "email": "learner-one@example.invalid",
                        "secret": "synthetic-public-profile",
                    },
                    {
                        "id": 2,
                        "username": "learner-two",
                        "email": "learner-two@example.invalid",
                        "secret": (
                            spec.marker_for("idor")
                            if "idor" in spec.vulnerabilities
                            else "synthetic-private-profile"
                        ),
                    },
                ],
                "path_secret": (
                    spec.marker_for("path_traversal")
                    if "path_traversal" in spec.vulnerabilities
                    else "synthetic-private-file"
                ),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        upload(self.seed_path, payload)
        result = execute(
            "python3 -c '"
            "import json,pathlib,sqlite3; "
            "p=json.load(open(\"/root/.vulnforge_seed.json\")); "
            "db=sqlite3.connect(\"/root/app.db\"); "
            "db.execute(\"CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL)\"); "
            "db.execute(\"DELETE FROM secrets\"); "
            "db.execute(\"INSERT INTO secrets(name,value) VALUES (?,?)\",(\"flag\",p[\"flag\"])); "
            "db.execute(\"CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, name TEXT, email TEXT)\"); "
            "db.executemany(\"INSERT OR REPLACE INTO records VALUES (?,?,?)\",[(r[\"id\"],r[\"name\"],r[\"email\"]) for r in p[\"records\"]]); "
            "db.execute(\"CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY, username TEXT, email TEXT, secret TEXT)\"); "
            "db.execute(\"DELETE FROM profiles\"); "
            "db.executemany(\"INSERT INTO profiles VALUES (?,?,?,?)\",[(r[\"id\"],r[\"username\"],r[\"email\"],r[\"secret\"]) for r in p[\"profiles\"]]); "
            "base=pathlib.Path(\"/root/vulnforge_files\"); (base/\"public\").mkdir(parents=True,exist_ok=True); "
            "(base/\"public\"/\"README.txt\").write_text(\"synthetic public file\\n\"); "
            "(base/\"secret.txt\").write_text(p[\"path_secret\"]); "
            "db.commit()'"
        )
        if getattr(result, "exit_code", 0) != 0:
            raise FixtureSeedError("trusted fixture seed command failed")
        upload(self.seed_path, b"")


@dataclass(frozen=True)
class VerificationResult:
    passed: bool
    benign_revealed: bool
    exploit_matched: bool
    static_pass: bool
    expected_flag_length: int
    expected_flag_sha256: str
    benign_body_sha256: str
    exploit_body_sha256: str
    benign_body_length: int
    exploit_body_length: int
    model_visible_summary: str
    static: StaticCheckResult | None = None
    profile_results: dict[str, dict[str, object]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "benign_revealed": self.benign_revealed,
            "exploit_matched": self.exploit_matched,
            "static_pass": self.static_pass,
            "expected_flag_length": self.expected_flag_length,
            "expected_flag_sha256": self.expected_flag_sha256,
            "benign_body_sha256": self.benign_body_sha256,
            "exploit_body_sha256": self.exploit_body_sha256,
            "benign_body_length": self.benign_body_length,
            "exploit_body_length": self.exploit_body_length,
            "model_visible_summary": self.model_visible_summary,
            "profile_results": self.profile_results,
        }


def build_benign_path(spec: ChallengeVariation, profile_id: str | None = None) -> str:
    selected = profile_id or spec.vulnerabilities[0]
    if selected == "sql_injection":
        return "/search?q=" + urllib.parse.quote("ordinary search")
    if selected == "reflected_xss":
        return "/echo?name=" + urllib.parse.quote("ordinary visitor")
    if selected == "path_traversal":
        return "/download?file=" + urllib.parse.quote("README.txt", safe="/")
    if selected == "idor":
        return "/profile?id=1"
    raise ValueError(f"unsupported vulnerability profile: {selected}")


def build_exploit_path(spec: ChallengeVariation, profile_id: str | None = None) -> str:
    selected = profile_id or spec.vulnerabilities[0]
    if selected == "sql_injection":
        injection = "' UNION SELECT value FROM secrets --"
        return "/search?q=" + urllib.parse.quote(injection, safe="")
    if selected == "reflected_xss":
        return "/echo?name=" + urllib.parse.quote(spec.marker_for(selected), safe="")
    if selected == "path_traversal":
        return "/download?file=" + urllib.parse.quote("../secret.txt", safe="")
    if selected == "idor":
        return "/profile?id=2"
    raise ValueError(f"unsupported vulnerability profile: {selected}")


def verify_private_target(
    spec: ChallengeVariation,
    request: Callable[[str], str | bytes],
    *,
    source: str | None = None,
) -> VerificationResult:
    static: StaticCheckResult | None = None
    if source is not None:
        static = static_check(source, spec)
    profile_results: dict[str, dict[str, object]] = {}
    for profile in profiles_for(spec.vulnerabilities):
        benign = _body_bytes(request(build_benign_path(spec, profile.id)))
        exploit = _body_bytes(request(build_exploit_path(spec, profile.id)))
        expected = (
            spec.flag
            if profile.id == "sql_injection"
            else spec.marker_for(profile.id)
        ).encode()
        benign_revealed = expected in benign
        exploit_matched = expected in exploit
        profile_results[profile.id] = {
            "benign_revealed": benign_revealed,
            "exploit_matched": exploit_matched,
            "benign_body_sha256": hashlib.sha256(benign).hexdigest(),
            "exploit_body_sha256": hashlib.sha256(exploit).hexdigest(),
            "benign_body_length": len(benign),
            "exploit_body_length": len(exploit),
        }
    first_profile = profile_results[spec.vulnerabilities[0]]
    benign_revealed = any(
        bool(result["benign_revealed"]) for result in profile_results.values()
    )
    exploit_matched = all(
        bool(result["exploit_matched"]) for result in profile_results.values()
    )
    static_pass = static.passed if static is not None else True
    passed = static_pass and not benign_revealed and exploit_matched
    benign_hash = str(first_profile["benign_body_sha256"])
    exploit_hash = str(first_profile["exploit_body_sha256"])
    return VerificationResult(
        passed=passed,
        benign_revealed=benign_revealed,
        exploit_matched=exploit_matched,
        static_pass=static_pass,
        expected_flag_length=len(spec.flag.encode()),
        expected_flag_sha256=spec.flag_digest,
        benign_body_sha256=benign_hash,
        exploit_body_sha256=exploit_hash,
        benign_body_length=int(str(first_profile["benign_body_length"])),
        exploit_body_length=int(str(first_profile["exploit_body_length"])),
        model_visible_summary=(
            f"private verification passed={passed} profiles={len(profile_results)} "
            f"benign_revealed={benign_revealed} exploit_matched={exploit_matched}"
        ),
        static=static,
        profile_results=profile_results,
    )


def _body_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode()
    raise TypeError("verifier response body must be text or bytes")


class PrivateRequestError(RuntimeError):
    pass


def make_control_plane_requester(
    command_guard: Any,
    context: Any,
    allowed_routes: set[str] | tuple[str, ...] | list[str] | None = None,
) -> Callable[[str], str]:
    """Build a verifier-only localhost requester; raw body never enters model traces."""

    def request(path: str) -> str:
        allowed = set(allowed_routes or {"/search"})
        parsed = urllib.parse.urlsplit(path) if isinstance(path, str) else None
        if parsed is None or parsed.path not in allowed or not parsed.query:
            raise ValueError("private verifier path is not an allowed challenge query")
        target = "http://127.0.0.1:8000" + path
        command = (
            "python3 -c "
            + shlex.quote(
                "import urllib.request; "
                f"response=urllib.request.urlopen({target!r}, timeout=8); "
                "print(response.read().decode('utf-8', 'replace'), end='')"
            )
        )
        outcome = command_guard.execute_control_plane(
            context, command, cwd="/root", timeout=15, purpose="private challenge verification request"
        )
        if not outcome.dispatched or outcome.exit_code != 0:
            raise PrivateRequestError("private verifier request failed")
        return outcome.stdout

    return request
