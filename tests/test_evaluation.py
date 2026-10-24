from __future__ import annotations

import pytest

from src.evaluation import summarize_runs, validate_variation_seeds


def test_summarize_runs_sorts_rows_and_uses_ceiling_p90() -> None:
    rows = [
        {"sandbox_name": "sbx-bbbbbbbb", "success": False, "wall_clock_s": 20.0, "boot_to_ready_s": 4.0, "cost_usd": 0.2},
        {"sandbox_name": "sbx-aaaaaaaa", "success": True, "wall_clock_s": 10.0, "boot_to_ready_s": 2.0, "cost_usd": 0.1},
        {"sandbox_name": "sbx-cccccccc", "success": True, "wall_clock_s": 30.0, "boot_to_ready_s": 6.0, "cost_usd": 0.3},
    ]

    result = summarize_runs(rows)

    assert [row["sandbox_name"] for row in result["runs"]] == [
        "sbx-aaaaaaaa",
        "sbx-bbbbbbbb",
        "sbx-cccccccc",
    ]
    assert result["success_rate"] == pytest.approx(2 / 3)
    assert result["median_wall_clock_s"] == 20.0
    assert result["p90_wall_clock_s"] == 30.0
    assert result["median_boot_to_ready_s"] == 4.0
    assert result["total_cost_usd"] == pytest.approx(0.6)


def test_variation_seeds_must_be_unique() -> None:
    validate_variation_seeds(["one", "two"])
    with pytest.raises(ValueError, match="variation"):
        validate_variation_seeds(["same", "same"])


def test_summarize_runs_serializes_decimal_like_numeric_values_as_numbers() -> None:
    from decimal import Decimal

    result = summarize_runs([
        {
            "sandbox_name": "sbx-aaaaaaaa",
            "success": True,
            "wall_clock_s": Decimal("1.5"),
            "boot_to_ready_s": Decimal("0.5"),
            "cost_usd": Decimal("0.25"),
        }
    ])

    row = result["runs"][0]
    assert isinstance(row["wall_clock_s"], float)
    assert isinstance(row["boot_to_ready_s"], float)
    assert isinstance(row["cost_usd"], float)
