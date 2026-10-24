"""Trusted SQL-injection challenge variation and prompt construction."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from random import Random
from typing import Any

from src.agent.tools import ToolValidationError, validate_generated_source


@dataclass(frozen=True)
class ChallengeVariation:
    seed: str
    flag: str
    flag_digest: str
    records: tuple[dict[str, str], ...]
    operator_description: str = ""
    route: str = "/search"
    parameter: str = "q"
    table: str = "secrets"

    @property
    def public_dict(self) -> dict[str, Any]:
        return {
            "challenge_type": "sql_injection",
            "seed": self.seed,
            "route": self.route,
            "parameter": self.parameter,
            "table": self.table,
            "records": [dict(record) for record in self.records],
            "operator_description": self.operator_description,
            "success_condition": "the intended q injection returns the trusted flag",
        }


@dataclass(frozen=True)
class StaticCheckResult:
    passed: bool
    flag_in_source: bool
    source_sha256: str
    source_length: int


def build_variation(
    seed: str | None = None,
    *,
    record_count: int = 4,
    operator_description: str = "",
) -> ChallengeVariation:
    seed = seed or secrets.token_hex(8)
    if not seed or not 1 <= record_count <= 20:
        raise ValueError("seed and record_count are invalid")
    normalized_description = _normalize_operator_description(operator_description)
    random = Random(seed)
    records = tuple(
        {
            "id": f"rec-{hashlib.sha256(f'{seed}:{index}'.encode()).hexdigest()[:10]}",
            "name": f"Learner {random.randrange(1000, 9999)}",
            "email": f"learner{index}@example.invalid",
        }
        for index in range(record_count)
    )
    flag = f"VF{{{secrets.token_hex(16)}}}"
    return ChallengeVariation(
        seed=seed,
        flag=flag,
        flag_digest=hashlib.sha256(flag.encode()).hexdigest(),
        records=records,
        operator_description=normalized_description,
    )


def _normalize_operator_description(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("operator description must be a string")
    if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
        raise ValueError("operator description contains unsupported control characters")
    normalized = " ".join(value.split())
    if len(normalized) > 2000:
        raise ValueError("operator description must be at most 2000 characters")
    return normalized


def build_prompt(spec: ChallengeVariation) -> str:
    public = json.dumps(spec.public_dict, sort_keys=True, separators=(",", ":"))
    design_guidance = ""
    if any(
        term in spec.operator_description.lower()
        for term in ("login", "sign-in", "signin")
    ):
        design_guidance = (
            "The operator requested a login-style website. Render a polished, self-contained "
            "login page at / with username and password fields, while keeping the required "
            "GET /search?q= route available for the private SQL-injection verifier. "
        )
    return (
        "Build the bounded educational challenge described below. "
        "Use the fixed write_app tool exactly once with complete Python source. "
        "The source must use only stdlib http.server and sqlite3, expose GET /search with q, "
        "query synthetic SQLite records, and never call external services. "
        "Do not embed any secret or flag; trusted control-plane setup handles the secrets table. "
        f"{design_guidance}"
        f"Challenge specification: {public}"
    )


def static_check(source: str, spec: ChallengeVariation) -> StaticCheckResult:
    if spec.flag in source:
        raise ToolValidationError("expected flag appears in generated source")
    checks = validate_generated_source(source)
    if spec.flag_digest in source:
        raise ToolValidationError("expected flag digest appears in generated source")
    lowered = source.lower()
    if "return flag" in lowered or "wfile.write(flag" in lowered:
        raise ToolValidationError("source contains an unconditional flag return")
    return StaticCheckResult(
        passed=True,
        flag_in_source=False,
        source_sha256=checks["source_sha256"],
        source_length=checks["bytes"],
    )
