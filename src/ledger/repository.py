"""PostgreSQL repository for run records."""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import psycopg
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row

from src.approval import APPROVAL_ACTION, ApprovalBinding, expiry_from_ttl

RUN_COLUMNS = """
    run_id, attempt_id, parent_run_id, batch_id, sandbox_name, problem_id,
    state, execution_target, description, phase, created_at, updated_at, variation_seed,
    source_revision, spec_revision, error_code, wall_clock_s,
    boot_to_ready_s, app_ready_s, published_url_probe_status,
    token_input, token_output, llm_cost_usd, celesto_duration_s, celesto_cost_usd,
    celesto_cost_method, total_cost_usd, llm_cost_method, llm_provider,
    llm_model, llm_rate_source
"""

LAB_PHASES = {
    "queued",
    "generating",
    "verifying",
    "awaiting_publication",
    "published",
    "cleaning_up",
    "cleaned_up",
    "failed",
}

_STATE_TRANSITIONS = {
    "created": {"ready", "running", "failed", "deleted"},
    "ready": {"running", "failed", "deleted"},
    "running": {"ready", "succeeded", "failed", "deleted"},
    "succeeded": {"deleted"},
    "failed": {"deleted"},
    "deleted": set(),
}
_TRANSITION_FIELDS = {
    "error_code",
    "wall_clock_s",
    "boot_to_ready_s",
    "app_ready_s",
    "published_url_probe_status",
    "token_input",
    "token_output",
    "llm_cost_usd",
    "celesto_duration_s",
    "celesto_cost_usd",
    "celesto_cost_method",
    "total_cost_usd",
}


class DuplicateRunId(Exception):
    """Raised when a run ID already exists in the ledger."""


class DuplicateSandboxName(Exception):
    """Raised when a sandbox name is already associated with another run."""


class LedgerUnavailable(Exception):
    """Raised when PostgreSQL cannot complete a ledger operation."""


class RunNotFound(Exception):
    """Raised when a lifecycle transition references an unknown run."""


class InvalidRunTransition(Exception):
    """Raised when a requested lifecycle transition is not allowed."""


class LlmBudgetExceeded(Exception):
    """Raised before a provider POST would exceed a persisted budget."""

    def __init__(self, message: str, *, code: str = "budget_exceeded") -> None:
        self.code = code
        super().__init__(message)


class LlmRequestNotFound(Exception):
    """Raised when a request reservation is unknown."""


class RunRepository:
    def __init__(self, database_url: str | None = None) -> None:
        self.database_url = database_url or os.getenv(
            "DATABASE_URL", "postgresql://ledger:ledger@ledger:5432/ledger"
        )

    async def _connect(self) -> psycopg.AsyncConnection[dict[str, Any]]:
        return await psycopg.AsyncConnection.connect(
            self.database_url,
            connect_timeout=3,
            row_factory=dict_row,
        )

    async def check_health(self) -> None:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute("SELECT 1")
                await cursor.fetchone()
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    async def list_runs(self) -> list[dict[str, Any]]:
        query = f"SELECT {RUN_COLUMNS} FROM runs ORDER BY created_at ASC, run_id ASC"
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(query)
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    async def create_run(self, values: dict[str, Any]) -> dict[str, Any]:
        query = (
            """
            INSERT INTO runs (
                run_id, attempt_id, parent_run_id, batch_id, sandbox_name,
                problem_id, state, execution_target, description, phase, variation_seed,
                source_revision, spec_revision
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING """
            + RUN_COLUMNS
        )
        params = (
            values["run_id"],
            values.get("attempt_id"),
            values.get("parent_run_id"),
            values.get("batch_id"),
            values["sandbox_name"],
            values["problem_id"],
            values["state"],
            values["execution_target"],
            values.get("description", ""),
            values.get("phase", "queued"),
            values.get("variation_seed"),
            values.get("source_revision"),
            values.get("spec_revision"),
        )
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(query, params)
                row = await cursor.fetchone()
                if row is not None:
                    await connection.execute(
                        """
                        INSERT INTO run_events
                            (run_id, from_state, to_state, event_type)
                        VALUES (%s, NULL, %s, 'state_transition')
                        """,
                        (values["run_id"], values["state"]),
                    )
        except UniqueViolation as exc:
            constraint = getattr(getattr(exc, "diag", None), "constraint_name", None)
            if constraint == "runs_pkey":
                raise DuplicateRunId from exc
            if constraint == "uq_runs_sandbox_name":
                raise DuplicateSandboxName from exc
            raise
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if row is None:
            raise RuntimeError("Run insert returned no row")
        return dict(row)

    async def get_run(self, run_id: str) -> dict[str, Any] | None:
        query = f"SELECT {RUN_COLUMNS} FROM runs WHERE run_id = %s"
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(query, (run_id,))
                row = await cursor.fetchone()
                return dict(row) if row is not None else None
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    async def set_run_phase(self, run_id: str, phase: str) -> dict[str, Any]:
        if phase not in LAB_PHASES:
            raise ValueError(f"unsupported lab phase: {phase}")
        query = (
            f"UPDATE runs SET phase = %s, updated_at = now() WHERE run_id = %s "
            f"RETURNING {RUN_COLUMNS}"
        )
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(query, (phase, run_id))
                row = await cursor.fetchone()
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if row is None:
            raise RunNotFound(run_id)
        return dict(row)

    async def sandbox_name_exists(self, sandbox_name: str) -> bool:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    "SELECT EXISTS (SELECT 1 FROM runs WHERE sandbox_name = %s) AS present",
                    (sandbox_name,),
                )
                row = await cursor.fetchone()
                return bool(row["present"])
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    async def transition_run(
        self,
        run_id: str,
        next_state: str,
        **updates: Any,
    ) -> dict[str, Any]:
        unknown_fields = set(updates) - _TRANSITION_FIELDS
        if unknown_fields:
            raise ValueError(
                f"unsupported run update fields: {', '.join(sorted(unknown_fields))}"
            )
        if "celesto_cost_method" in updates and updates["celesto_cost_method"] not in {
            None,
            "computed_from_duration",
        }:
            raise ValueError("celesto_cost_method must be computed_from_duration")

        not_found = False
        invalid_transition = False
        result: dict[str, Any] | None = None
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    "SELECT state FROM runs WHERE run_id = %s FOR UPDATE", (run_id,)
                )
                current = await cursor.fetchone()
                if current is None:
                    not_found = True
                else:
                    previous_state = current["state"]
                    if next_state not in _STATE_TRANSITIONS.get(previous_state, set()):
                        await connection.execute(
                            """
                            INSERT INTO run_events
                                (run_id, from_state, to_state, event_type, error_code)
                            VALUES (%s, %s, %s, 'transition_rejected', %s)
                            """,
                            (run_id, previous_state, next_state, "invalid_transition"),
                        )
                        invalid_transition = True
                    else:
                        assignments = ["state = %s", "updated_at = now()"]
                        params: list[Any] = [next_state]
                        for field, value in updates.items():
                            assignments.append(f"{field} = %s")
                            params.append(value)
                        params.append(run_id)
                        update = await connection.execute(
                            f"UPDATE runs SET {', '.join(assignments)} "
                            f"WHERE run_id = %s RETURNING {RUN_COLUMNS}",
                            params,
                        )
                        row = await update.fetchone()
                        if row is None:
                            raise RuntimeError("Run transition returned no row")
                        result = dict(row)
                        await connection.execute(
                            """
                            INSERT INTO run_events
                                (run_id, from_state, to_state, event_type)
                            VALUES (%s, %s, %s, 'state_transition')
                            """,
                            (run_id, previous_state, next_state),
                        )
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

        if not_found:
            raise RunNotFound(run_id)
        if invalid_transition:
            raise InvalidRunTransition(f"cannot transition {run_id} to {next_state}")
        if result is None:
            raise RuntimeError("Run transition produced no result")
        return result

    async def list_run_events(self, run_id: str) -> list[dict[str, Any]]:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    """
                    SELECT event_id, run_id, from_state, to_state, event_type,
                           error_code, occurred_at
                    FROM run_events WHERE run_id = %s
                    ORDER BY event_id ASC
                    """,
                    (run_id,),
                )
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc


    async def migrate_llm_budget_schema(self, migration_path: str | Path | None = None) -> None:
        """Apply the idempotent M5 migration to an existing or fresh database."""
        path = Path(migration_path) if migration_path else Path(__file__).resolve().parents[2] / "seeds" / "03_llm_budgets.sql"
        sql = path.read_text(encoding="utf-8")
        try:
            async with await self._connect() as connection, connection.transaction():
                await connection.execute(sql)
        except (OSError, psycopg.Error) as exc:
            raise LedgerUnavailable from exc

    async def migrate_runtime_schema(self) -> None:
        """Apply all post-foundation idempotent migrations in filename order."""
        seed_dir = Path(__file__).resolve().parents[2] / "seeds"
        for name in (
            "02_lifecycle.sql",
            "03_llm_budgets.sql",
            "04_publication.sql",
            "05_approvals.sql",
            "06_lab_dashboard.sql",
        ):
            await self.migrate_llm_budget_schema(seed_dir / name)

    async def create_llm_attempt_budget(
        self,
        attempt_id: str,
        *,
        run_id: str,
        batch_id: str | None,
        provider: str,
        model: str,
        max_http_attempts: int,
        token_budget: int,
        time_budget_seconds: float,
        max_retries: int,
        daily_request_limit: int,
        daily_token_limit: int,
    ) -> dict[str, Any]:
        if daily_token_limit <= 0:
            raise ValueError("daily_token_limit must be positive")
        values = (
            attempt_id,
            run_id,
            batch_id,
            provider,
            model,
            max_http_attempts,
            token_budget,
            time_budget_seconds,
            max_retries,
            daily_request_limit,
            daily_token_limit,
        )
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    """
                    INSERT INTO llm_attempt_budgets (
                        attempt_id, run_id, batch_id, provider, model,
                        max_http_attempts, max_token_budget, time_budget_s,
                        max_retries, daily_request_limit, daily_token_limit
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING attempt_id, run_id, batch_id, provider, model,
                              max_http_attempts, max_token_budget, time_budget_s,
                              max_retries, daily_request_limit, daily_token_limit,
                              reserved_requests, reserved_tokens, consumed_tokens,
                              status, created_at, completed_at
                    """,
                    values,
                )
                row = await cursor.fetchone()
        except psycopg.errors.UniqueViolation as exc:
            raise LlmBudgetExceeded("attempt already has an LLM budget", code="duplicate_budget") from exc
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if row is None:
            raise RuntimeError("LLM budget insert returned no row")
        return dict(row)

    async def get_llm_attempt_budget(self, attempt_id: str) -> dict[str, Any] | None:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    "SELECT * FROM llm_attempt_budgets WHERE attempt_id = %s", (attempt_id,)
                )
                row = await cursor.fetchone()
                return dict(row) if row else None
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    async def preflight_llm_batch(
        self,
        *,
        provider: str,
        model: str,
        attempt_count: int,
        max_http_attempts: int,
        token_budget: int,
        daily_request_limit: int,
        daily_token_limit: int,
    ) -> dict[str, Any]:
        if min(attempt_count, max_http_attempts, token_budget, daily_request_limit, daily_token_limit) <= 0:
            raise ValueError("batch and LLM limits must be positive")
        required_requests = attempt_count * max_http_attempts
        required_tokens = attempt_count * token_budget
        try:
            async with await self._connect() as connection, connection.transaction():
                await connection.execute(
                    """
                    INSERT INTO llm_provider_daily_usage (provider, model, usage_date)
                    VALUES (%s, %s, CURRENT_DATE)
                    ON CONFLICT (provider, model, usage_date) DO NOTHING
                    """,
                    (provider, model),
                )
                cursor = await connection.execute(
                    """
                    SELECT request_count, reserved_token_count, consumed_token_count
                    FROM llm_provider_daily_usage
                    WHERE provider = %s AND model = %s AND usage_date = CURRENT_DATE
                    FOR UPDATE
                    """,
                    (provider, model),
                )
                current = await cursor.fetchone()
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if current is None:
            raise RuntimeError("daily usage row was not created")
        used_requests = int(current["request_count"])
        used_tokens = int(current["reserved_token_count"]) + int(current["consumed_token_count"])
        allowed = (
            used_requests + required_requests <= daily_request_limit
            and used_tokens + required_tokens <= daily_token_limit
        )
        result = {
            "allowed": allowed,
            "provider": provider,
            "model": model,
            "attempt_count": attempt_count,
            "required_requests": required_requests,
            "required_tokens": required_tokens,
            "used_requests": used_requests,
            "used_tokens": used_tokens,
            "daily_request_limit": daily_request_limit,
            "daily_token_limit": daily_token_limit,
            "limit_source": "configured_account_limit",
        }
        if not allowed:
            raise LlmBudgetExceeded(
                "LLM batch preflight exceeds the configured daily provider budget",
                code="daily_preflight_exceeded",
            )
        return result

    async def reserve_llm_request(
        self,
        attempt_id: str,
        estimated_tokens: int,
        *,
        retry_index: int = 0,
    ) -> dict[str, Any]:
        if isinstance(estimated_tokens, bool) or estimated_tokens <= 0:
            raise ValueError("estimated_tokens must be positive")
        if isinstance(retry_index, bool) or retry_index < 0:
            raise ValueError("retry_index must be non-negative")
        try:
            async with await self._connect() as connection, connection.transaction():
                budget_cursor = await connection.execute(
                    "SELECT * FROM llm_attempt_budgets WHERE attempt_id = %s FOR UPDATE",
                    (attempt_id,),
                )
                budget = await budget_cursor.fetchone()
                if budget is None:
                    raise LlmBudgetExceeded("LLM attempt budget does not exist", code="missing_budget")
                if budget["status"] != "active":
                    raise LlmBudgetExceeded("LLM attempt budget is not active", code="budget_closed")
                if int(budget["reserved_requests"]) >= int(budget["max_http_attempts"]):
                    raise LlmBudgetExceeded("per-attempt provider request budget exhausted", code="attempt_request_limit")
                if int(budget["reserved_tokens"]) + int(budget["consumed_tokens"]) + estimated_tokens > int(budget["max_token_budget"]):
                    raise LlmBudgetExceeded("per-attempt token budget exhausted", code="attempt_token_limit")
                await connection.execute(
                    """
                    INSERT INTO llm_provider_daily_usage (provider, model, usage_date)
                    VALUES (%s, %s, CURRENT_DATE)
                    ON CONFLICT (provider, model, usage_date) DO NOTHING
                    """,
                    (budget["provider"], budget["model"]),
                )
                usage_cursor = await connection.execute(
                    """
                    SELECT * FROM llm_provider_daily_usage
                    WHERE provider = %s AND model = %s AND usage_date = CURRENT_DATE
                    FOR UPDATE
                    """,
                    (budget["provider"], budget["model"]),
                )
                usage = await usage_cursor.fetchone()
                if usage is None:
                    raise RuntimeError("daily usage row was not created")
                if int(usage["request_count"]) >= int(budget["daily_request_limit"]):
                    raise LlmBudgetExceeded("daily provider request budget exhausted", code="daily_request_limit")
                if int(usage["reserved_token_count"]) + int(usage["consumed_token_count"]) + estimated_tokens > int(budget["daily_token_limit"]):
                    raise LlmBudgetExceeded("daily provider token budget exhausted", code="daily_token_limit")
                request_cursor = await connection.execute(
                    """
                    INSERT INTO llm_requests (attempt_id, retry_index, status, reserved_tokens)
                    VALUES (%s, %s, 'reserved', %s)
                    RETURNING request_id, attempt_id, retry_index, status, reserved_tokens, created_at
                    """,
                    (attempt_id, retry_index, estimated_tokens),
                )
                request = await request_cursor.fetchone()
                await connection.execute(
                    """
                    UPDATE llm_attempt_budgets
                    SET reserved_requests = reserved_requests + 1,
                        reserved_tokens = reserved_tokens + %s
                    WHERE attempt_id = %s
                    """,
                    (estimated_tokens, attempt_id),
                )
                await connection.execute(
                    """
                    UPDATE llm_provider_daily_usage
                    SET request_count = request_count + 1,
                        reserved_token_count = reserved_token_count + %s
                    WHERE provider = %s AND model = %s AND usage_date = CURRENT_DATE
                    """,
                    (estimated_tokens, budget["provider"], budget["model"]),
                )
        except LlmBudgetExceeded:
            raise
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if request is None:
            raise RuntimeError("LLM request reservation returned no row")
        return dict(request)

    async def mark_llm_request_sent(self, request_id: int) -> None:
        try:
            async with await self._connect() as connection, connection.transaction():
                result = await connection.execute(
                    """
                    UPDATE llm_requests SET status = 'sent', sent_at = now()
                    WHERE request_id = %s AND status = 'reserved'
                    """,
                    (request_id,),
                )
                if result.rowcount != 1:
                    raise LlmRequestNotFound(request_id)
        except LlmRequestNotFound:
            raise
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    async def record_llm_response(
        self,
        request_id: int,
        *,
        http_status: int | None,
        headers: Mapping[str, str] | None,
        input_tokens: int,
        output_tokens: int,
        total_tokens: int,
        response_model: str | None = None,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        for value, name in ((input_tokens, "input_tokens"), (output_tokens, "output_tokens"), (total_tokens, "total_tokens")):
            if isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be non-negative")
        safe_headers = _safe_rate_headers(headers or {})
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    """
                    SELECT request_id, attempt_id, reserved_tokens, status
                    FROM llm_requests WHERE request_id = %s FOR UPDATE
                    """,
                    (request_id,),
                )
                request = await cursor.fetchone()
                if request is None or request["status"] == "released":
                    raise LlmRequestNotFound(request_id)
                budget_cursor = await connection.execute(
                    "SELECT provider, model FROM llm_attempt_budgets WHERE attempt_id = %s FOR UPDATE",
                    (request["attempt_id"],),
                )
                budget = await budget_cursor.fetchone()
                if budget is None:
                    raise LlmRequestNotFound(request_id)
                status = "succeeded" if http_status is not None and 200 <= http_status < 300 else "failed"
                update = await connection.execute(
                    """
                    UPDATE llm_requests
                    SET status = %s, input_tokens = %s, output_tokens = %s,
                        total_tokens = %s, http_status = %s, response_model = %s,
                        response_headers = %s::jsonb, error_code = %s,
                        finished_at = now()
                    WHERE request_id = %s
                    RETURNING request_id, attempt_id, status, input_tokens,
                              output_tokens, total_tokens, http_status,
                              response_headers, error_code, finished_at
                    """,
                    (status, input_tokens, output_tokens, total_tokens, http_status,
                     response_model, json.dumps(safe_headers), error_code, request_id),
                )
                row = await update.fetchone()
                await connection.execute(
                    """
                    UPDATE llm_attempt_budgets
                    SET reserved_tokens = GREATEST(0, reserved_tokens - %s),
                        consumed_tokens = consumed_tokens + %s
                    WHERE attempt_id = %s
                    """,
                    (request["reserved_tokens"], total_tokens, request["attempt_id"]),
                )
                await connection.execute(
                    """
                    UPDATE llm_provider_daily_usage
                    SET reserved_token_count = GREATEST(0, reserved_token_count - %s),
                        consumed_token_count = consumed_token_count + %s
                    WHERE provider = %s AND model = %s AND usage_date = CURRENT_DATE
                    """,
                    (request["reserved_tokens"], total_tokens, budget["provider"], budget["model"]),
                )
        except LlmRequestNotFound:
            raise
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if row is None:
            raise RuntimeError("LLM response update returned no row")
        return dict(row)

    async def release_llm_request(self, request_id: int) -> bool:
        """Release a reservation that was never sent; sent retries remain accounted."""
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    """
                    SELECT r.attempt_id, r.reserved_tokens, b.provider, b.model
                    FROM llm_requests r JOIN llm_attempt_budgets b USING (attempt_id)
                    WHERE r.request_id = %s AND r.status = 'reserved'
                    FOR UPDATE
                    """,
                    (request_id,),
                )
                row = await cursor.fetchone()
                if row is None:
                    return False
                await connection.execute(
                    "UPDATE llm_requests SET status = 'released', finished_at = now() WHERE request_id = %s",
                    (request_id,),
                )
                await connection.execute(
                    """
                    UPDATE llm_attempt_budgets
                    SET reserved_requests = GREATEST(0, reserved_requests - 1),
                        reserved_tokens = GREATEST(0, reserved_tokens - %s)
                    WHERE attempt_id = %s
                    """,
                    (row["reserved_tokens"], row["attempt_id"]),
                )
                await connection.execute(
                    """
                    UPDATE llm_provider_daily_usage
                    SET request_count = GREATEST(0, request_count - 1),
                        reserved_token_count = GREATEST(0, reserved_token_count - %s)
                    WHERE provider = %s AND model = %s AND usage_date = CURRENT_DATE
                    """,
                    (row["reserved_tokens"], row["provider"], row["model"]),
                )
                return True
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    async def complete_llm_attempt_budget(self, attempt_id: str) -> dict[str, Any]:
        """Close an attempt budget and release reservations that were not sent."""
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    """
                    SELECT r.request_id, r.reserved_tokens, b.provider, b.model
                    FROM llm_requests r JOIN llm_attempt_budgets b USING (attempt_id)
                    WHERE r.attempt_id = %s AND r.status = 'reserved'
                    FOR UPDATE
                    """,
                    (attempt_id,),
                )
                pending = await cursor.fetchall()
                for row in pending:
                    await connection.execute(
                        "UPDATE llm_requests SET status = 'released', finished_at = now() WHERE request_id = %s",
                        (row["request_id"],),
                    )
                    await connection.execute(
                        """
                        UPDATE llm_provider_daily_usage
                        SET request_count = GREATEST(0, request_count - 1),
                            reserved_token_count = GREATEST(0, reserved_token_count - %s)
                        WHERE provider = %s AND model = %s AND usage_date = CURRENT_DATE
                        """,
                        (row["reserved_tokens"], row["provider"], row["model"]),
                    )
                update = await connection.execute(
                    """
                    UPDATE llm_attempt_budgets
                    SET status = 'completed', reserved_requests = 0,
                        reserved_tokens = 0, completed_at = now()
                    WHERE attempt_id = %s
                    RETURNING *
                    """,
                    (attempt_id,),
                )
                result = await update.fetchone()
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if result is None:
            raise LlmBudgetExceeded("LLM attempt budget does not exist", code="missing_budget")
        return dict(result)

    async def record_llm_cost(
        self,
        run_id: str,
        *,
        input_rate_usd_per_million: Decimal | float = Decimal(0),
        output_rate_usd_per_million: Decimal | float = Decimal(0),
        rate_source: str = "configured_rate_card",
    ) -> dict[str, Any]:
        input_rate = Decimal(str(input_rate_usd_per_million))
        output_rate = Decimal(str(output_rate_usd_per_million))
        if input_rate < 0 or output_rate < 0:
            raise ValueError("LLM token rates must be non-negative")
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    """
                    SELECT COALESCE(SUM(r.input_tokens), 0) AS input_tokens,
                           COALESCE(SUM(r.output_tokens), 0) AS output_tokens
                    FROM llm_requests r JOIN llm_attempt_budgets b USING (attempt_id)
                    WHERE b.run_id = %s AND r.status IN ('succeeded', 'failed')
                    """,
                    (run_id,),
                )
                usage = await cursor.fetchone()
                if usage is None:
                    raise RunNotFound(run_id)
                input_tokens = int(usage["input_tokens"])
                output_tokens = int(usage["output_tokens"])
                cost = (Decimal(input_tokens) * input_rate + Decimal(output_tokens) * output_rate) / Decimal(1_000_000)
                update = await connection.execute(
                    f"""
                    UPDATE runs SET token_input = %s, token_output = %s,
                        llm_cost_usd = %s, llm_cost_method = 'computed_from_tokens',
                        llm_provider = (SELECT provider FROM llm_attempt_budgets WHERE run_id = runs.run_id LIMIT 1),
                        llm_model = (SELECT model FROM llm_attempt_budgets WHERE run_id = runs.run_id LIMIT 1),
                        llm_rate_source = %s,
                        total_cost_usd = CASE WHEN celesto_cost_usd IS NULL THEN NULL ELSE celesto_cost_usd + %s END,
                        updated_at = now()
                    WHERE run_id = %s RETURNING {RUN_COLUMNS}
                    """,
                    (input_tokens, output_tokens, cost, rate_source, cost, run_id),
                )
                row = await update.fetchone()
        except RunNotFound:
            raise
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if row is None:
            raise RunNotFound(run_id)
        return dict(row)

    async def list_llm_requests(self, attempt_id: str) -> list[dict[str, Any]]:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    "SELECT * FROM llm_requests WHERE attempt_id = %s ORDER BY request_id",
                    (attempt_id,),
                )
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    async def record_publication(
        self,
        run_id: str,
        *,
        url_sha256: str,
        url_host: str,
        created_at: Any,
        expires_at: Any,
        probe_status: int,
        token: str | None = None,
    ) -> dict[str, Any]:
        import hashlib
        import re
        if not url_host or any(character in url_host for character in "\r\n /"):
            raise ValueError("url_host must be a sanitized hostname")
        if not re.fullmatch(r"[0-9a-f]{64}", url_sha256):
            raise ValueError("url_sha256 must be a lowercase SHA-256 digest")
        token_sha256 = hashlib.sha256(token.encode()).hexdigest() if token is not None else None
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    """
                    INSERT INTO published_endpoints
                        (run_id, url_sha256, url_host, token_sha256,
                         created_at, expires_at, probe_status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (run_id) DO UPDATE SET
                        url_sha256 = EXCLUDED.url_sha256,
                        url_host = EXCLUDED.url_host,
                        token_sha256 = EXCLUDED.token_sha256,
                        created_at = EXCLUDED.created_at,
                        expires_at = EXCLUDED.expires_at,
                        probe_status = EXCLUDED.probe_status,
                        revoked_at = NULL,
                        revoked = FALSE
                    RETURNING publication_id, run_id, url_sha256, url_host,
                              token_sha256, created_at, expires_at,
                              revoked_at, probe_status, revoked
                    """,
                    (run_id, url_sha256, url_host, token_sha256,
                     created_at, expires_at, probe_status),
                )
                row = await cursor.fetchone()
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if row is None:
            raise RuntimeError("publication record returned no row")
        return dict(row)

    async def mark_publication_revoked(
        self, run_id: str, *, revoked_at: Any
    ) -> dict[str, Any]:
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    """
                    UPDATE published_endpoints
                    SET revoked = TRUE, revoked_at = %s
                    WHERE run_id = %s
                    RETURNING publication_id, run_id, url_sha256, url_host,
                              token_sha256, created_at, expires_at,
                              revoked_at, probe_status, revoked
                    """,
                    (revoked_at, run_id),
                )
                row = await cursor.fetchone()
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if row is None:
            raise RunNotFound(run_id)
        return dict(row)

    async def get_publication(self, run_id: str) -> dict[str, Any] | None:
        try:
            async with await self._connect() as connection:
                cursor = await connection.execute(
                    """
                    SELECT publication_id, run_id, url_sha256, url_host,
                           created_at, expires_at, revoked_at, probe_status, revoked
                    FROM published_endpoints
                    WHERE run_id = %s
                    """,
                    (run_id,),
                )
                row = await cursor.fetchone()
                return dict(row) if row is not None else None
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    async def create_approval(
        self,
        *,
        run_id: str,
        attempt_id: str,
        sandbox_name: str,
        port: int,
        app_sha256: str,
        ttl_seconds: int,
        mode: str = "interactive",
    ) -> dict[str, Any]:
        if mode not in {"interactive", "pre_approved"}:
            raise ValueError("approval mode must be interactive or pre_approved")
        expiry_from_ttl(ttl_seconds)
        approval_id = f"approval-{secrets.token_hex(8)}"
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    """
                    INSERT INTO approvals (
                        approval_id, run_id, attempt_id, sandbox_name, action,
                        port, app_sha256, expires_at, mode
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        now() + (%s * interval '1 second'), %s
                    )
                    RETURNING approval_id, run_id, attempt_id, sandbox_name,
                              action, port, app_sha256, requested_at,
                              expires_at, decision, decided_by, decided_at,
                              mode, used_at
                    """,
                    (approval_id, run_id, attempt_id, sandbox_name, APPROVAL_ACTION,
                     port, app_sha256, ttl_seconds, mode),
                )
                row = await cursor.fetchone()
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if row is None:
            raise RuntimeError("approval insert returned no row")
        return dict(row)

    async def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    "SELECT * FROM approvals WHERE approval_id = %s FOR UPDATE",
                    (approval_id,),
                )
                row = await cursor.fetchone()
                if row is not None and row["decision"] == "pending" and row["expires_at"] <= datetime.now(UTC):
                    await connection.execute(
                        "UPDATE approvals SET decision = 'expired' WHERE approval_id = %s",
                        (approval_id,),
                    )
                    row = {**dict(row), "decision": "expired"}
                return dict(row) if row is not None else None
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    async def decide_approval(
        self,
        approval_id: str,
        *,
        decision: str,
        decided_by: str,
    ) -> dict[str, Any]:
        if decision not in {"approved", "denied"}:
            raise ValueError("approval decision must be approved or denied")
        expired = False
        row = None
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    "SELECT decision, expires_at FROM approvals WHERE approval_id = %s FOR UPDATE",
                    (approval_id,),
                )
                current = await cursor.fetchone()
                if current is None:
                    raise RunNotFound(approval_id)
                if current["decision"] != "pending":
                    raise ValueError("approval is no longer pending")
                if current["expires_at"] <= datetime.now(UTC):
                    update = await connection.execute(
                        """
                        UPDATE approvals
                        SET decision = 'expired'
                        WHERE approval_id = %s
                        RETURNING *
                        """,
                        (approval_id,),
                    )
                    row = await update.fetchone()
                    expired = True
                else:
                    update = await connection.execute(
                        """
                        UPDATE approvals
                        SET decision = %s, decided_by = %s, decided_at = now()
                        WHERE approval_id = %s
                        RETURNING *
                        """,
                        (decision, decided_by[:120], approval_id),
                    )
                    row = await update.fetchone()
        except (RunNotFound, ValueError):
            raise
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc
        if row is None:
            raise RuntimeError("approval decision returned no row")
        if expired:
            raise ValueError("approval has expired")
        return dict(row)

    async def consume_approval(
        self,
        *,
        approval_id: str,
        run_id: str,
        attempt_id: str,
        sandbox_name: str,
        port: int,
        app_sha256: str,
    ) -> ApprovalBinding | None:
        try:
            async with await self._connect() as connection, connection.transaction():
                cursor = await connection.execute(
                    "SELECT * FROM approvals WHERE approval_id = %s FOR UPDATE",
                    (approval_id,),
                )
                row = await cursor.fetchone()
                if row is None:
                    return None
                now = datetime.now(UTC)
                if row["expires_at"] <= now and row["decision"] == "pending":
                    await connection.execute(
                        "UPDATE approvals SET decision = 'expired' WHERE approval_id = %s",
                        (approval_id,),
                    )
                    return None
                if row["decision"] != "approved" or row["used_at"] is not None:
                    return None
                if (
                    row["run_id"] != run_id
                    or row["attempt_id"] != attempt_id
                    or row["sandbox_name"] != sandbox_name
                    or int(row["port"]) != port
                    or row["app_sha256"] != app_sha256
                ):
                    return None
                await connection.execute(
                    "UPDATE approvals SET used_at = now() WHERE approval_id = %s",
                    (approval_id,),
                )
                return ApprovalBinding(
                    approval_id=row["approval_id"],
                    run_id=row["run_id"],
                    attempt_id=row["attempt_id"],
                    sandbox_name=row["sandbox_name"],
                    action=row["action"],
                    port=int(row["port"]),
                    app_sha256=row["app_sha256"],
                    expires_at=row["expires_at"],
                    decision=row["decision"],
                    mode=row["mode"],
                )
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc


def _safe_rate_headers(headers: Mapping[str, str]) -> dict[str, str]:
    allowed = {"content-type", "retry-after"}
    result: dict[str, str] = {}
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered in allowed or lowered.startswith("x-ratelimit-"):
            result[lowered] = str(value)[:200]
    return result
