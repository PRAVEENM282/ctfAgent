from __future__ import annotations

from src.challenge import build_variation
from src.verification import (
    FixtureSeedError,
    TrustedFixtureSeeder,
    make_control_plane_requester,
    verify_private_target,
)


def test_private_verifier_requires_negative_and_exact_positive_match() -> None:
    spec = build_variation("verify-seed")
    seen = []

    def request(path: str) -> str:
        seen.append(path)
        if "UNION" in path or "union" in path:
            return "result=" + spec.flag + "\n"
        return "no secret result\n"

    result = verify_private_target(spec, request)

    assert result.passed is True
    assert result.benign_revealed is False
    assert result.exploit_matched is True
    assert result.expected_flag_length == len(spec.flag)
    assert spec.flag not in result.model_visible_summary
    assert spec.flag not in result.as_dict().__repr__()
    assert len(seen) == 2


def test_private_verifier_fails_when_benign_request_reveals_flag() -> None:
    spec = build_variation("negative-seed")

    result = verify_private_target(spec, lambda _path: spec.flag)

    assert result.passed is False
    assert result.benign_revealed is True
    assert result.exploit_matched is True


def test_trusted_fixture_seeder_keeps_flag_out_of_command_text() -> None:
    spec = build_variation("seed-boundary")
    uploads = []
    commands = []

    class Result:
        exit_code = 0

    TrustedFixtureSeeder().seed(
        spec,
        upload=lambda path, payload: uploads.append((path, payload)),
        execute=lambda command: commands.append(command) or Result(),
    )

    assert uploads[0][1].find(spec.flag.encode()) >= 0
    assert spec.flag not in commands[0]
    assert uploads[-1][1] == b""


def test_fixture_seeder_fails_closed_without_verified_upload_boundary() -> None:
    spec = build_variation("no-upload")

    def upload(_path, _payload):
        raise FixtureSeedError("no verified upload")

    class Result:
        exit_code = 0

    try:
        TrustedFixtureSeeder().seed(spec, upload=upload, execute=lambda _command: Result())
    except FixtureSeedError as exc:
        assert "upload" in str(exc)
    else:
        raise AssertionError("expected trusted fixture seeder to fail closed")


def test_control_plane_requester_returns_private_body_without_model_trace() -> None:
    seen = []

    class Guard:
        def execute_control_plane(self, _context, command, **_kwargs):
            seen.append(command)
            return type("Outcome", (), {"dispatched": True, "exit_code": 0, "stdout": "private-body"})()

    body = make_control_plane_requester(Guard(), object())("/search?q=hello")

    assert body == "private-body"
    assert seen and "private-body" not in seen[0]
