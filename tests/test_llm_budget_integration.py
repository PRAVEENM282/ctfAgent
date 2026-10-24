"""PostgreSQL integration coverage for the M5 reservation ledger."""

from __future__ import annotations

import os
from decimal import Decimal
from uuid import uuid4

import psycopg
import pytest

from src.ledger.repository import LedgerUnavailable, LlmBudgetExceeded, RunRepository


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_llm_budget_migration_reservation_retry_and_cost() -> None:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        pytest.skip("DATABASE_URL is not set; skipping PostgreSQL integration test")
    repository = RunRepository(database_url)
    try:
        await repository.check_health()
        await repository.migrate_runtime_schema()
        await repository.migrate_runtime_schema()
    except (LedgerUnavailable, OSError):
        pytest.skip("PostgreSQL at DATABASE_URL is not reachable")

    run_id = f"run-{uuid4().hex}"
    attempt_id = f"attempt-{uuid4().hex[:16]}"
    batch_id = f"batch-{uuid4().hex[:16]}"
    sandbox_name = f"sbx-{uuid4().hex[:16]}"
    provider = f"integration-{uuid4().hex}"
    model = "reservation-retry-cost-test"
    created = False
    try:
        await repository.create_run(
            {
                "run_id": run_id,
                "attempt_id": attempt_id,
                "parent_run_id": run_id,
                "batch_id": batch_id,
                "sandbox_name": sandbox_name,
                "problem_id": "m5-budget-integration",
                "state": "created",
                "execution_target": "celesto_sandbox",
            }
        )
        created = True
        budget = await repository.create_llm_attempt_budget(
            attempt_id,
            run_id=run_id,
            batch_id=batch_id,
            provider=provider,
            model=model,
            max_http_attempts=3,
            token_budget=100,
            time_budget_seconds=30,
            max_retries=2,
            daily_request_limit=10,
            daily_token_limit=500,
        )
        assert budget["daily_token_limit"] == 500

        preflight = await repository.preflight_llm_batch(
            provider=provider,
            model=model,
            attempt_count=2,
            max_http_attempts=3,
            token_budget=100,
            daily_request_limit=10,
            daily_token_limit=500,
        )
        assert preflight["required_requests"] == 6
        assert preflight["required_tokens"] == 200

        first = await repository.reserve_llm_request(attempt_id, 40, retry_index=0)
        await repository.mark_llm_request_sent(first["request_id"])
        await repository.record_llm_response(
            first["request_id"],
            http_status=429,
            headers={"Retry-After": "1", "Authorization": "Bearer secret"},
            input_tokens=0,
            output_tokens=0,
            total_tokens=0,
            error_code="rate_limited",
        )

        retry = await repository.reserve_llm_request(attempt_id, 40, retry_index=1)
        await repository.mark_llm_request_sent(retry["request_id"])
        await repository.record_llm_response(
            retry["request_id"],
            http_status=200,
            headers={"x-ratelimit-remaining-tokens": "1234"},
            input_tokens=10,
            output_tokens=20,
            total_tokens=30,
            response_model=model,
        )

        released = await repository.reserve_llm_request(attempt_id, 20, retry_index=0)
        assert await repository.release_llm_request(released["request_id"]) is True
        assert await repository.release_llm_request(released["request_id"]) is False

        completed = await repository.complete_llm_attempt_budget(attempt_id)
        assert completed["status"] == "completed"
        rows = await repository.list_llm_requests(attempt_id)
        assert [row["status"] for row in rows] == ["failed", "succeeded", "released"]
        assert all(
            "authorization" not in (row["response_headers"] or {}) for row in rows
        )

        cost = await repository.record_llm_cost(
            run_id,
            input_rate_usd_per_million=Decimal(0),
            output_rate_usd_per_million=Decimal(0),
            rate_source="configured_free_rate",
        )
        assert cost["llm_cost_usd"] == Decimal("0.000000")
        assert cost["llm_cost_method"] == "computed_from_tokens"
        assert cost["total_cost_usd"] is None

        with pytest.raises(LlmBudgetExceeded):
            await repository.reserve_llm_request(attempt_id, 1)
    finally:
        if created:
            async with await psycopg.AsyncConnection.connect(
                database_url
            ) as connection:
                await connection.execute(
                    "DELETE FROM runs WHERE run_id = %s", (run_id,)
                )
