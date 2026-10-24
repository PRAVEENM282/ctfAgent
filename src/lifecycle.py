"""Persisted orchestration for one fresh Celesto attempt."""

from __future__ import annotations

import asyncio
import logging
import math
import secrets
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from src.celesto_adapter import (
    CelestoAdapter,
    Guest,
    PublishedEndpoint,
    ResumeReadiness,
    calculate_celesto_cost_usd,
)
from src.command_guard import CommandContext
from src.ledger.repository import DuplicateSandboxName

logger = logging.getLogger(__name__)


class LifecycleRepository(Protocol):
    async def create_run(self, values: dict[str, Any]) -> dict[str, Any]: ...

    async def sandbox_name_exists(self, sandbox_name: str) -> bool: ...

    async def transition_run(
        self, run_id: str, next_state: str, **updates: Any
    ) -> dict[str, Any]: ...


@dataclass
class LifecycleAttempt:
    run_id: str
    attempt_id: str
    guest: Guest
    batch_id: str | None = None
    state: str = "ready"
    endpoint: PublishedEndpoint | None = None
    cleaned: bool = False
    paused_at_monotonic: float | None = None
    stopped_duration_s: float = 0.0
    celesto_duration_s: float | None = None


class RunLifecycle:
    """Coordinate Celesto actions with durable attempt state and cleanup."""

    def __init__(
        self,
        repository: LifecycleRepository,
        adapter: CelestoAdapter,
        *,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self.repository = repository
        self.adapter = adapter
        self._monotonic = monotonic or time.monotonic

    async def create_attempt(
        self,
        *,
        problem_id: str,
        run_id: str | None = None,
        attempt_id: str | None = None,
        parent_run_id: str | None = None,
        batch_id: str | None = None,
        sandbox_name: str | None = None,
        persist_run: bool = True,
        variation_seed: str | None = None,
        source_revision: str | None = None,
        spec_revision: str | None = None,
        template_id: str = "coding-agent",
    ) -> LifecycleAttempt:
        run_id = run_id or f"run-{secrets.token_hex(6)}"
        attempt_id = attempt_id or f"attempt-{secrets.token_hex(6)}"
        parent_run_id = parent_run_id or run_id
        batch_id = batch_id or f"batch-{secrets.token_hex(6)}"

        values = {
            "run_id": run_id,
            "attempt_id": attempt_id,
            "parent_run_id": parent_run_id,
            "batch_id": batch_id,
            "sandbox_name": sandbox_name or "",
            "problem_id": problem_id,
            "state": "created",
            "execution_target": "celesto_sandbox",
            "variation_seed": variation_seed,
            "source_revision": source_revision,
            "spec_revision": spec_revision,
        }
        if persist_run:
            for _ in range(5):
                sandbox_name = f"sbx-{secrets.token_hex(8)}"
                if await self.repository.sandbox_name_exists(sandbox_name):
                    logger.warning("sandbox name collision; generating a new name")
                    continue
                values["sandbox_name"] = sandbox_name
                try:
                    await self.repository.create_run(values)
                except DuplicateSandboxName:
                    logger.warning("sandbox name insert collision; generating a new name")
                    continue
                break
            else:
                raise RuntimeError("could not allocate a unique sandbox name")
        elif not sandbox_name:
            raise ValueError("sandbox_name is required when persist_run is false")

        allocated_sandbox_name = str(values["sandbox_name"])

        context_factory = lambda name: CommandContext(
            run_id=run_id,
            parent_run_id=parent_run_id,
            batch_id=batch_id,
            attempt_id=attempt_id,
            sandbox_name=name,
        )
        guest: Guest | None = None
        try:
            guest = await asyncio.to_thread(
                self.adapter.create_guest,
                template_id,
                sandbox_name=allocated_sandbox_name,
                command_context_factory=context_factory,
            )
            await self.repository.transition_run(
                run_id,
                "ready",
                boot_to_ready_s=guest.boot_to_ready_s,
            )
        except Exception as exc:
            failed_updates: dict[str, Any] = {"error_code": "sandbox_create_failed"}
            failed_guest_duration = getattr(exc, "guest_duration_s", None)
            if guest is not None:
                try:
                    await asyncio.to_thread(self.adapter.delete_guest, guest)
                    failed_guest_duration = await asyncio.to_thread(
                        self.adapter.guest_duration_s, guest
                    )
                except Exception as cleanup_error:  # noqa: BLE001 - log only type, preserve the cause.
                    logger.error(
                        "guest cleanup after ledger failure was unconfirmed error=%s",
                        type(cleanup_error).__name__,
                    )
            if (
                isinstance(failed_guest_duration, (int, float))
                and not isinstance(failed_guest_duration, bool)
                and math.isfinite(failed_guest_duration)
                and failed_guest_duration >= 0
            ):
                failed_updates.update(
                    wall_clock_s=failed_guest_duration,
                    celesto_duration_s=failed_guest_duration,
                    celesto_cost_usd=calculate_celesto_cost_usd(failed_guest_duration),
                    celesto_cost_method="computed_from_duration",
                )
            try:
                await self.repository.transition_run(
                    run_id,
                    "failed",
                    **failed_updates,
                )
            except Exception as ledger_error:  # noqa: BLE001 - preserve original create failure.
                logger.error(
                    "failed to persist sandbox creation failure error=%s",
                    type(ledger_error).__name__,
                )
            raise

        return LifecycleAttempt(run_id, attempt_id, guest, batch_id=batch_id)

    async def start_and_publish(
        self,
        attempt: LifecycleAttempt,
        *,
        start_command: str,
        expected_marker: str,
        port: int = 8000,
    ) -> ResumeReadiness:
        if attempt.state != "ready":
            raise ValueError("attempt must be ready before publication")
        try:
            endpoint = await asyncio.to_thread(
                self.adapter.publish, attempt.guest, port
            )
            attempt.endpoint = endpoint
            readiness = await asyncio.to_thread(
                self.adapter.start_and_wait_ready,
                attempt.guest,
                endpoint,
                start_command=start_command,
                expected_marker=expected_marker,
            )
            await self.repository.transition_run(
                attempt.run_id,
                "running",
                app_ready_s=readiness.app_ready_s,
                published_url_probe_status=readiness.published_status,
            )
            attempt.state = "running"
            return readiness
        except Exception:
            await self.cleanup(attempt, error_code="application_not_ready")
            raise

    async def pause(self, attempt: LifecycleAttempt) -> float:
        if attempt.state != "running":
            raise ValueError("only a running attempt can be paused")
        stop_s = await asyncio.to_thread(self.adapter.stop_guest, attempt.guest)
        attempt.paused_at_monotonic = self._monotonic()
        await self.repository.transition_run(attempt.run_id, "ready")
        attempt.state = "ready"
        return stop_s

    async def resume(
        self,
        attempt: LifecycleAttempt,
        *,
        restart_command: str,
        expected_marker: str,
    ) -> ResumeReadiness:
        if attempt.state != "ready" or attempt.endpoint is None:
            raise ValueError(
                "attempt must be paused with a published endpoint before resume"
            )
        resume_started = self._monotonic()
        if attempt.paused_at_monotonic is not None:
            attempt.stopped_duration_s += max(
                0.0, resume_started - attempt.paused_at_monotonic
            )
            attempt.paused_at_monotonic = None
        try:
            readiness = await asyncio.to_thread(
                self.adapter.resume_and_wait_ready,
                attempt.guest,
                attempt.endpoint,
                restart_command=restart_command,
                expected_marker=expected_marker,
            )
            await self.repository.transition_run(
                attempt.run_id,
                "running",
                app_ready_s=readiness.app_ready_s,
                published_url_probe_status=readiness.published_status,
            )
            attempt.state = "running"
            return readiness
        except Exception:
            await self.cleanup(attempt, error_code="resume_not_ready")
            raise

    async def cleanup(
        self,
        attempt: LifecycleAttempt,
        *,
        interrupted: bool = False,
        error_code: str | None = None,
    ) -> dict[str, Any] | None:
        if attempt.cleaned:
            return None

        errors: list[str] = []
        if attempt.endpoint is not None:
            try:
                await asyncio.to_thread(
                    self.adapter.revoke, attempt.guest, attempt.endpoint
                )
            except Exception as exc:  # noqa: BLE001 - always continue to guest deletion.
                errors.append(f"revoke:{type(exc).__name__}")
        try:
            await asyncio.to_thread(self.adapter.delete_guest, attempt.guest)
        except Exception as exc:  # noqa: BLE001 - state must reflect unconfirmed deletion.
            errors.append(f"delete:{type(exc).__name__}")

        wall_clock_s = self.adapter.guest_duration_s(attempt.guest)
        stopped_duration_s = attempt.stopped_duration_s
        if attempt.paused_at_monotonic is not None:
            stopped_duration_s += max(
                0.0, self._monotonic() - attempt.paused_at_monotonic
            )
        delete_confirmed = not any(error.startswith("delete:") for error in errors)
        celesto_duration_s = (
            max(0.0, wall_clock_s - stopped_duration_s) if delete_confirmed else None
        )
        attempt.celesto_duration_s = celesto_duration_s
        cost = (
            calculate_celesto_cost_usd(celesto_duration_s)
            if celesto_duration_s is not None
            else None
        )
        cost_method = "computed_from_duration" if delete_confirmed else None
        final_state = "failed" if errors else "deleted"
        final_error = (
            ";".join(errors)
            if errors
            else (error_code or ("interrupted" if interrupted else None))
        )
        if errors and attempt.state == "failed":
            return None
        row = await self.repository.transition_run(
            attempt.run_id,
            final_state,
            error_code=final_error,
            wall_clock_s=wall_clock_s,
            celesto_duration_s=celesto_duration_s if delete_confirmed else None,
            celesto_cost_usd=cost,
            celesto_cost_method=cost_method,
            total_cost_usd=None,
        )
        attempt.state = final_state
        attempt.cleaned = not errors
        return row

    async def wait_for_sigint(self, attempt: LifecycleAttempt) -> dict[str, Any] | None:
        loop = asyncio.get_running_loop()
        stop_requested = asyncio.Event()
        previous_handler = signal.getsignal(signal.SIGINT)
        loop.add_signal_handler(signal.SIGINT, stop_requested.set)
        try:
            await stop_requested.wait()
        finally:
            loop.remove_signal_handler(signal.SIGINT)
            signal.signal(signal.SIGINT, previous_handler)
        return await self.cleanup(attempt, interrupted=True)
