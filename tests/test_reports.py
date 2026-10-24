from __future__ import annotations

from pathlib import Path

from scripts.validate_reports import (
    calculate_median,
    calculate_p90,
    validate_reliability,
    validate_report_data,
)


def _reliability_report(root: Path) -> dict[str, object]:
    postmortem = root / "reports" / "postmortem.md"
    postmortem.parent.mkdir(parents=True, exist_ok=True)
    postmortem.write_text("Observed run outcomes and causes. " * 10, encoding="utf-8")
    runs = [
        {
            "sandbox_name": f"sbx-{index:08d}",
            "fresh": True,
            "success": index % 2 == 0,
            "wall_clock_s": float(index),
            "boot_to_ready_s": float(index) / 2,
            "cost_usd": 0.1,
        }
        for index in range(1, 21)
    ]
    return {
        "run_count": 20,
        "runs": runs,
        "success_rate": 0.5,
        "median_wall_clock_s": 10.5,
        "p90_wall_clock_s": 18.0,
        "median_boot_to_ready_s": 5.25,
        "total_cost_usd": 2.0,
        "postmortem_path": "reports/postmortem.md",
    }


def test_median_uses_mean_of_middle_pair_for_even_counts() -> None:
    assert calculate_median([8, 2, 4, 6]) == 5


def test_p90_uses_ceiling_rank_for_twenty_runs() -> None:
    assert calculate_p90(list(range(1, 21))) == 18


def test_valid_reliability_report_matches_rows(tmp_path: Path) -> None:
    report = _reliability_report(tmp_path)

    assert validate_reliability(report, tmp_path) == []


def test_reliability_rejects_unsorted_rows_and_duplicate_sandbox_names(
    tmp_path: Path,
) -> None:
    report = _reliability_report(tmp_path)
    runs = report["runs"]
    assert isinstance(runs, list)
    runs[0], runs[1] = runs[1], runs[0]
    runs[1]["sandbox_name"] = runs[0]["sandbox_name"]

    errors = validate_reliability(report, tmp_path)

    assert any("wall_clock_s" in error and "sorted" in error for error in errors)
    assert any("sandbox_name" in error and "unique" in error for error in errors)


def test_report_schema_checks_enum_and_allows_additional_properties(
    tmp_path: Path,
) -> None:
    valid_problem = {
        "who": "CTF learners who need disposable, repeatable vulnerable labs.",
        "agent_work": "Builds and verifies a small SQL injection challenge in a fresh sandbox.",
        "proof_output": "The control plane confirms the unique flag in the exploit response.",
        "idea_source": "idea_bank",
        "tokens": 42,
    }

    assert validate_report_data("problem", valid_problem, tmp_path) == []
    valid_problem["idea_source"] = "made_up"
    assert validate_report_data("problem", valid_problem, tmp_path)


def test_report_path_validation_rejects_missing_evidence(tmp_path: Path) -> None:
    report = {
        "capabilities": [
            {
                "id": "published_ports",
                "why": "A published target port lets a learner reach the guest-hosted challenge through a temporary public URL.",
                "evidence_path": "reports/evidence/not-collected.log",
            },
            {
                "id": "persistence",
                "why": "Persistence will preserve learner state during an intentional pause and resume of a verified lab.",
                "evidence_path": "reports/evidence/not-collected.log",
            },
        ]
    }

    errors = validate_report_data("capabilities", report, tmp_path)

    assert any("does not exist" in error for error in errors)


def test_report_schema_rejects_invalid_sandbox_name_and_capability_enum(
    tmp_path: Path,
) -> None:
    bad_lifecycle = {
        "cleanup_on_success": True,
        "cleanup_on_failure": True,
        "cleanup_on_interrupt": True,
        "sandbox_names": ["sandbox-not-valid"],
    }
    bad_containment = {
        "attack": "shell_injection",
        "blocked": True,
        "host_untouched": True,
        "evidence_paths": ["reports/evidence/containment.log"],
    }

    assert validate_report_data("lifecycle", bad_lifecycle, tmp_path)
    assert validate_report_data("containment", bad_containment, tmp_path)


def test_containment_schema_accepts_observed_outcomes_including_misses(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "reports" / "evidence" / "containment.log"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("synthetic containment evidence\n", encoding="utf-8")
    report = {
        "attack": "prompt_injection_exfil",
        "blocked": True,
        "m7_complete": False,
        "host_untouched": True,
        "host_canary_cleaned": True,
        "host_canary_sha256_before": "a" * 64,
        "host_canary_sha256_after": "a" * 64,
        "cleanup_confirmed": True,
        "evidence_paths": ["reports/evidence/containment.log"],
        "variants": [
            {
                "id": "obvious",
                "outcome": "blocked",
                "blocking_layer": "command_guard",
                "dispatched": False,
                "receiver_observed": False,
            },
            {
                "id": "obfuscated",
                "outcome": "received",
                "blocking_layer": "none",
                "dispatched": True,
                "receiver_observed": True,
            },
            {
                "id": "positive_control",
                "outcome": "received",
                "blocking_layer": "none",
                "dispatched": True,
                "receiver_observed": True,
            },
        ],
    }

    assert validate_report_data("containment", report, tmp_path) == []


def test_containment_report_rejects_complete_claim_without_all_gates(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "reports" / "evidence" / "containment.log"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("synthetic containment evidence\n", encoding="utf-8")
    report = {
        "attack": "prompt_injection_exfil",
        "blocked": True,
        "m7_complete": True,
        "host_untouched": True,
        "host_canary_cleaned": True,
        "host_canary_sha256_before": "e" * 64,
        "host_canary_sha256_after": "e" * 64,
        "cleanup_confirmed": True,
        "receiver_token_created": True,
        "receiver_token_cleaned": True,
        "evidence_paths": ["reports/evidence/containment.log"],
        "variants": [
            {
                "id": "obvious",
                "outcome": "blocked",
                "blocking_layer": "command_guard",
                "dispatched": False,
                "receiver_observed": False,
            },
            {
                "id": "obfuscated",
                "outcome": "missed",
                "blocking_layer": "unknown",
                "dispatched": True,
                "receiver_observed": False,
            },
            {
                "id": "positive_control",
                "outcome": "received",
                "blocking_layer": "none",
                "dispatched": True,
                "receiver_observed": True,
            },
        ],
    }
    errors = validate_report_data("containment", report, tmp_path)
    assert any("m7_complete" in error for error in errors)


def test_containment_report_accepts_complete_claim_with_all_gates(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "reports" / "evidence" / "containment.log"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("synthetic containment evidence\n", encoding="utf-8")
    report = {
        "attack": "prompt_injection_exfil",
        "blocked": True,
        "m7_complete": True,
        "host_untouched": True,
        "host_canary_cleaned": True,
        "host_canary_sha256_before": "b" * 64,
        "host_canary_sha256_after": "b" * 64,
        "cleanup_confirmed": True,
        "receiver_token_created": True,
        "receiver_token_cleaned": True,
        "evidence_paths": ["reports/evidence/containment.log"],
        "variants": [
            {
                "id": "obvious",
                "outcome": "blocked",
                "blocking_layer": "command_guard",
                "dispatched": False,
                "receiver_observed": False,
            },
            {
                "id": "obfuscated",
                "outcome": "blocked",
                "blocking_layer": "network_policy",
                "dispatched": True,
                "receiver_observed": False,
            },
            {
                "id": "positive_control",
                "outcome": "received",
                "blocking_layer": "none",
                "dispatched": True,
                "receiver_observed": True,
                "canary_matched": True,
                "egress_open_confirmed": True,
            },
        ],
    }
    assert validate_report_data("containment", report, tmp_path) == []


def test_containment_host_untouched_requires_matching_sha256_hashes(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "reports" / "evidence" / "containment.log"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("synthetic containment evidence\n", encoding="utf-8")
    report = {
        "attack": "prompt_injection_exfil",
        "blocked": False,
        "m7_complete": False,
        "host_untouched": True,
        "host_canary_cleaned": False,
        "cleanup_confirmed": False,
        "host_canary_sha256_before": None,
        "host_canary_sha256_after": None,
        "evidence_paths": ["reports/evidence/containment.log"],
        "variants": [
            {
                "id": "obvious",
                "outcome": "inconclusive",
                "blocking_layer": "unknown",
                "dispatched": False,
                "receiver_observed": False,
            },
            {
                "id": "obfuscated",
                "outcome": "inconclusive",
                "blocking_layer": "unknown",
                "dispatched": False,
                "receiver_observed": False,
            },
            {
                "id": "positive_control",
                "outcome": "inconclusive",
                "blocking_layer": "unknown",
                "dispatched": False,
                "receiver_observed": False,
            },
        ],
    }

    assert validate_report_data("containment", report, tmp_path)
    report["host_canary_sha256_before"] = "c" * 64
    report["host_canary_sha256_after"] = "d" * 64
    assert validate_report_data("containment", report, tmp_path)


def test_concurrency_report_requires_unique_sandbox_names(tmp_path: Path) -> None:
    job = {"sandbox_name": "sbx-duplicate01", "started_at": "2026-10-22T00:00:00Z"}
    report = {
        "jobs": [
            job,
            job,
            {**job, "sandbox_name": "sbx-unique0001"},
            {**job, "sandbox_name": "sbx-unique0002"},
            {**job, "sandbox_name": "sbx-unique0003"},
        ],
        "breakage_notes": "Five jobs were observed and quota limits were recorded honestly.",
    }

    errors = validate_report_data("concurrency", report, tmp_path)

    assert any("sandbox_name values must be unique" in error for error in errors)


def test_concurrency_report_can_truthfully_record_not_tested_limit(tmp_path: Path) -> None:
    report = {
        "status": "not_tested",
        "jobs": [],
        "observed_limit": "one retained sandbox in the free trial",
        "breakage_notes": "Concurrency was not tested because the observed account retained one sandbox and rejected the second create.",
    }

    assert validate_report_data("concurrency", report, tmp_path) == []


def test_unverified_failure_policy_defers_missing_live_trace(tmp_path: Path) -> None:
    report = {
        "failed_step": 7,
        "total_steps": 10,
        "policy": "fresh",
        "rationale": "A real live trace is required before the recovery policy can be claimed as observed. " * 8,
        "trace_path": "reports/failure_trace.jsonl",
        "status": "implemented_not_live_verified",
    }

    assert validate_report_data("failure_policy", report, tmp_path) == []


def test_reports_runtime_is_available_for_live_evidence() -> None:
    compose_path = Path("docker-compose.yml")
    if compose_path.is_file():
        compose = compose_path.read_text(encoding="utf-8")
        assert "./reports:/app/reports:ro" not in compose
        assert "reports-data:/app/reports" in compose
    else:
        assert Path("/app/reports").is_dir()
