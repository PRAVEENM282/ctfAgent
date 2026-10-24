from __future__ import annotations

from pathlib import Path

import pytest

from src.api.schemas import LabCreate
from src.ledger.repository import RunRepository

ROOT = Path(__file__).resolve().parents[1]


def test_fresh_runs_schema_contains_dashboard_phase_and_description() -> None:
    schema = (ROOT / "seeds" / "01_runs.sql").read_text(encoding="utf-8")

    assert "description TEXT NOT NULL DEFAULT ''" in schema
    assert "phase TEXT NOT NULL DEFAULT 'queued'" in schema
    assert "awaiting_publication" in schema
    assert "cleaned_up" in schema


def test_existing_database_migration_is_idempotent_and_does_not_store_raw_urls() -> None:
    migration = (ROOT / "seeds" / "06_lab_dashboard.sql").read_text(encoding="utf-8")

    assert "ADD COLUMN IF NOT EXISTS description" in migration
    assert "ADD COLUMN IF NOT EXISTS phase" in migration
    assert "runs_dashboard_phase_check" in migration
    assert "public_url" not in migration


def test_lab_create_trims_description_and_rejects_empty_input() -> None:
    payload = LabCreate(description="  Create a product search lesson.  ")

    assert payload.description == "Create a product search lesson."

    with pytest.raises(ValueError):
        LabCreate(description="   ")

    with pytest.raises(ValueError, match="control characters"):
        LabCreate(description="unsafe\x00description")


@pytest.mark.anyio
async def test_set_run_phase_rejects_unknown_phase_before_database_access() -> None:
    repository = RunRepository("postgresql://unused")

    with pytest.raises(ValueError, match="unsupported lab phase"):
        await repository.set_run_phase("run-abc123def456", "not-a-phase")


def test_repository_exposes_browser_lookup_operations() -> None:
    assert callable(RunRepository.get_run)
    assert callable(RunRepository.set_run_phase)
    assert callable(RunRepository.get_publication)
