from __future__ import annotations

import pytest

from src.agent.tools import ToolValidationError
from src.challenge import build_prompt, build_variation, static_check


def _source() -> str:
    return """import http.server
import sqlite3

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/search') and 'q' in self.path:
            db = sqlite3.connect('/root/app.db')
            row = db.execute('SELECT value FROM secrets WHERE name = ?', ('flag',)).fetchone()
            body = row[0] if row else 'not found'
        else:
            body = 'ok'
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body.encode())

if __name__ == '__main__':
    http.server.HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
"""


def test_variation_has_unique_seed_and_flag_and_prompt_omits_flag() -> None:
    first = build_variation("seed-one")
    second = build_variation("seed-two")

    assert first.seed != second.seed
    assert first.flag != second.flag
    assert first.flag.startswith("VF{") and len(first.flag) == 36
    prompt = build_prompt(first)
    assert first.flag not in prompt
    assert first.flag_digest not in prompt
    assert "/search" in prompt
    assert "http.server" in prompt
    assert "sqlite3" in prompt


def test_variation_supports_single_profile_and_explicit_bundle() -> None:
    xss = build_variation(
        "xss-seed",
        mode="single",
        vulnerabilities=["reflected_xss"],
    )
    bundle = build_variation(
        "bundle-seed",
        mode="bundle",
        vulnerabilities=["sql_injection", "path_traversal", "idor"],
    )

    assert xss.mode == "single"
    assert xss.vulnerabilities == ("reflected_xss",)
    assert xss.marker_for("reflected_xss") not in build_prompt(xss)
    assert bundle.mode == "bundle"
    assert bundle.vulnerabilities == (
        "sql_injection",
        "path_traversal",
        "idor",
    )
    assert all(profile_id in build_prompt(bundle) for profile_id in bundle.vulnerabilities)


def test_variation_rejects_invalid_profile_selection() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        build_variation(
            "bad-single-selection",
            mode="single",
            vulnerabilities=["sql_injection", "idor"],
        )

    with pytest.raises(ValueError, match="duplicates"):
        build_variation(
            "duplicate-selection",
            mode="bundle",
            vulnerabilities=["idor", "idor"],
        )

    with pytest.raises(ValueError, match="unsupported"):
        build_variation(
            "unknown-selection",
            mode="single",
            vulnerabilities=["command_injection"],
        )


def test_operator_description_is_included_as_untrusted_constrained_context() -> None:
    spec = build_variation(
        "description-seed",
        operator_description="Create a small product search page for a SQL injection lesson.",
    )

    prompt = build_prompt(spec)

    assert spec.operator_description in prompt
    assert "fixed write_app tool exactly once" in prompt
    assert "never call external services" in prompt
    assert spec.flag not in prompt
    assert spec.flag_digest not in prompt


def test_login_request_gets_login_ui_guidance_without_changing_verifier_route() -> None:
    spec = build_variation(
        "login-description-seed",
        operator_description="Create a login website with a SQL injection vulnerability.",
    )

    prompt = build_prompt(spec)

    assert "login-style website" in prompt
    assert "username and password fields" in prompt
    assert "GET /search?q=" in prompt


def test_operator_description_rejects_control_characters_and_excessive_length() -> None:
    with pytest.raises(ValueError, match="description"):
        build_variation("bad-description", operator_description="unsafe\x00text")

    with pytest.raises(ValueError, match="description"):
        build_variation("long-description", operator_description="x" * 2001)


def test_static_check_accepts_stdlib_source_and_rejects_flag_or_framework() -> None:
    spec = build_variation("seed-static")
    result = static_check(_source(), spec)
    assert result.passed is True
    assert result.flag_in_source is False

    with pytest.raises(ToolValidationError):
        static_check(_source().replace("body = 'ok'", f"body = '{spec.flag}'"), spec)
    with pytest.raises(ToolValidationError):
        static_check(_source().replace("import sqlite3", "import flask"), spec)
