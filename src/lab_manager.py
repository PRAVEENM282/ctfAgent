"""Single-operator orchestration for the browser-facing lab flow."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlsplit

from src.agent.loop import AgentLoopConfig
from src.agent.provider import (
    ProviderConfigurationError,
    ProviderHTTPError,
    ProviderProtocolError,
    ProviderSettings,
    ProviderTransportError,
    provider_client_from_settings,
    provider_config_from_environment,
)
from src.agent.tools import make_agent_tool_writer
from src.api.schemas import LabCreate, LabPhase, LabSnapshot, RunState
from src.approval import ApprovalRequired
from src.celesto_adapter import CelestoAdapter, NetworkPolicyViolation
from src.challenge import ChallengeVariation, build_variation
from src.generator import (
    ChallengeGenerationError,
    ChallengeGenerator,
    GeneratedChallenge,
)
from src.ledger.repository import LedgerUnavailable, RunNotFound
from src.lifecycle import LifecycleAttempt, RunLifecycle
from src.publish import PublicationError, PublishedSession, VerifiedPublisher
from src.verification import (
    TrustedFixtureSeeder,
    VerificationResult,
    build_benign_path,
    make_control_plane_requester,
    verify_private_target,
)
from src.vulnerability_profiles import profiles_for

logger = logging.getLogger(__name__)


class LabManagerError(RuntimeError):
    """Base error for safe browser-facing lab actions."""

    code = "lab_error"


class LabConflict(LabManagerError):
    code = "lab_action_not_available"


class LabExecutionError(LabManagerError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class LabStopRequested(Exception):
    """Internal signal used to let the stop action own cleanup."""


@dataclass
class _LabRecord:
    run_id: str
    attempt_id: str
    batch_id: str
    sandbox_name: str
    description: str
    state: str = "created"
    phase: str = "queued"
    message: str = "Lab creation queued."
    error_code: str | None = None
    cleanup_confirmed: bool = False
    stop_requested: bool = False
    worker: asyncio.Task[Any] | None = None
    adapter: Any | None = None
    lifecycle: RunLifecycle | None = None
    attempt: LifecycleAttempt | None = None
    variation: ChallengeVariation | None = None
    generated: GeneratedChallenge | None = None
    verification: VerificationResult | None = None
    approval_id: str | None = None
    publication: PublishedSession | None = None


_PHASE_MESSAGES = {
    "queued": "Lab creation queued.",
    "generating": "Generating the isolated lab.",
    "verifying": "Running private verification.",
    "awaiting_publication": "Private verification passed. Publish the lab when ready.",
    "published": "Lab published. Stop the sandbox when finished.",
    "cleaning_up": "Revoking the public route and deleting the sandbox.",
    "cleaned_up": "The public route was revoked and the sandbox was deleted.",
    "failed": "Lab creation failed. Start a new lab after cleanup is confirmed.",
}

_ERROR_CODES = {
    "provider_not_configured": "The configured model provider is not ready.",
    "provider_request_failed": "The model provider could not complete generation.",
    "rate_limited": "The provider rate-limited generation. Check its quota or wait before retrying.",
    "http_400": (
        "The provider rejected the request. Check the model, request format, and "
        "account inference access."
    ),
    "http_401": "The provider rejected authentication. Check the API key and authentication header.",
    "http_403": "The provider denied access. Check the account, model access, and endpoint permissions.",
    "http_404": "The provider endpoint or model was not found. Check the base URL and model ID.",
    "http_413": "The provider rejected the request size. Lower the request token setting or prompt size.",
    "http_422": "The provider rejected the request format. Check API format and tool-calling support.",
    "provider_protocol_failed": "The model provider returned an unusable response.",
    "generation_incomplete": (
        "The model responded but did not produce a valid app. Check tool-calling support "
        "and retry."
    ),
    "sandbox_create_failed": "The isolated sandbox could not be created.",
    "private_app_start_failed": "The generated site did not start privately.",
    "private_app_readiness_failed": "The generated site did not become ready privately.",
    "private_verification_failed": "The generated site did not pass private verification.",
    "publication_failed": "The verified lab could not be published safely.",
    "cleanup_unconfirmed": "Cleanup could not be confirmed; the sandbox may still exist.",
    "lab_execution_failed": "The lab could not be completed safely.",
}


class LabManager:
    """Own in-process execution handles while the ledger stores lifecycle state."""

    def __init__(
        self,
        repository: Any,
        *,
        adapter_factory: Callable[[], Any] = CelestoAdapter,
        provider_settings_factory: Callable[[], ProviderSettings] | None = None,
        provider_client_factory: Callable[[ProviderSettings], Any] | None = None,
        external_probe: Callable[[str], int] | None = None,
    ) -> None:
        self.repository = repository
        self.adapter_factory = adapter_factory
        self.provider_settings_factory = (
            provider_settings_factory or provider_config_from_environment
        )
        self.provider_client_factory = (
            provider_client_factory or provider_client_from_settings
        )
        self.external_probe = external_probe or _external_probe
        self._records: dict[str, _LabRecord] = {}
        self._closed = False

    async def create_lab(
        self,
        description: str,
        *,
        mode: str = "single",
        vulnerabilities: list[str] | tuple[str, ...] | None = None,
    ) -> LabSnapshot:
        if self._closed:
            raise LabConflict("the lab manager is closed")
        normalized = LabCreate(description=description).description
        variation = build_variation(
            os.getenv("VULNFORGE_VARIATION_SEED") or None,
            operator_description=normalized,
            mode=mode,
            vulnerabilities=vulnerabilities,
        )
        run_id = f"run-{secrets.token_hex(6)}"
        attempt_id = f"attempt-{secrets.token_hex(6)}"
        batch_id = f"batch-{secrets.token_hex(6)}"
        sandbox_name = f"sbx-{secrets.token_hex(8)}"
        await self.repository.create_run(
            {
                "run_id": run_id,
                "attempt_id": attempt_id,
                "parent_run_id": run_id,
                "batch_id": batch_id,
                "sandbox_name": sandbox_name,
                "problem_id": "ctf-sqli-mvp",
                "state": "created",
                "execution_target": "celesto_sandbox",
                "description": normalized,
                "phase": "queued",
                "source_revision": "dashboard-source-r1",
                "spec_revision": "dashboard-spec-r1",
            }
        )
        record = _LabRecord(
            run_id=run_id,
            attempt_id=attempt_id,
            batch_id=batch_id,
            sandbox_name=sandbox_name,
            description=normalized,
            variation=variation,
        )
        self._records[run_id] = record
        record.worker = asyncio.create_task(
            self._run(record), name=f"vulnforge-lab-{run_id}"
        )
        return self._snapshot(record)

    async def get_lab(self, run_id: str) -> LabSnapshot:
        record = self._records.get(run_id)
        if record is not None:
            return self._snapshot(record)
        row = await self.repository.get_run(run_id)
        if row is None:
            raise RunNotFound(run_id)
        phase = str(row.get("phase") or _phase_from_state(str(row.get("state"))))
        state = str(row.get("state", "failed"))
        cleanup_confirmed = phase == "cleaned_up" or state == "deleted"
        return LabSnapshot(
            run_id=run_id,
            state=cast(RunState, state),
            phase=cast(LabPhase, phase),
            message=_PHASE_MESSAGES.get(phase, _PHASE_MESSAGES["failed"]),
            can_publish=False,
            can_stop=state not in {"deleted", "failed"},
            cleanup_confirmed=cleanup_confirmed,
            error_code=row.get("error_code"),
        )

    async def publish_lab(self, run_id: str) -> LabSnapshot:
        record = await self._require_record(run_id)
        if record.phase != "awaiting_publication":
            raise LabConflict("lab is not ready for publication")
        if (
            record.attempt is None
            or record.generated is None
            or record.verification is None
            or record.approval_id is None
            or record.adapter is None
        ):
            raise LabConflict("lab is not ready for publication")

        publisher: VerifiedPublisher | None = None
        session: PublishedSession | None = None
        try:
            await self.repository.decide_approval(
                record.approval_id,
                decision="approved",
                decided_by="local-dashboard",
            )
            binding = await self.repository.consume_approval(
                approval_id=record.approval_id,
                run_id=record.run_id,
                attempt_id=record.attempt_id,
                sandbox_name=record.sandbox_name,
                port=8000,
                app_sha256=record.generated.static.source_sha256,
            )
            if binding is None:
                raise ApprovalRequired("publication approval is not available")
            publisher = VerifiedPublisher(
                record.adapter,
                external_probe=self.external_probe,
                lease_seconds=int(os.getenv("VULNFORGE_PUBLIC_LEASE_SECONDS", "900")),
                approval_checker=lambda **_kwargs: binding,
            )
            session = await asyncio.to_thread(
                publisher.publish_verified,
                record.attempt.guest,
                record.verification,
                port=8000,
                run_id=record.run_id,
                attempt_id=record.attempt_id,
                sandbox_name=record.sandbox_name,
                app_sha256=record.generated.static.source_sha256,
            )
            host = _published_host(session.url)
            await self.repository.record_publication(
                record.run_id,
                url_sha256=session.url_sha256,
                url_host=host,
                created_at=session.created_at,
                expires_at=session.expires_at,
                probe_status=session.probe_status,
            )
            record.publication = session
            record.attempt.endpoint = session.endpoint
            record.state = "succeeded"
            record.phase = "published"
            record.message = _PHASE_MESSAGES["published"]
            await self.repository.transition_run(
                record.run_id,
                "succeeded",
                published_url_probe_status=session.probe_status,
            )
            await self.repository.set_run_phase(record.run_id, "published")
        except LedgerUnavailable:
            await self._rollback_publication(record, publisher, session)
            raise
        except (ApprovalRequired, PublicationError) as exc:
            await self._rollback_publication(record, publisher, session)
            raise LabConflict(_safe_action_error(exc)) from None
        except Exception as exc:  # noqa: BLE001 - map all browser failures safely.
            await self._rollback_publication(record, publisher, session)
            logger.error("lab publication failed error_type=%s", type(exc).__name__)
            raise LabExecutionError("publication_failed") from None

        if session is None:
            raise LabExecutionError("publication_failed")
        return self._snapshot(record)

    async def _rollback_publication(
        self,
        record: _LabRecord,
        publisher: VerifiedPublisher | None,
        session: PublishedSession | None,
    ) -> None:
        if session is not None and publisher is not None:
            try:
                await asyncio.to_thread(publisher.cleanup, session)
            except Exception as cleanup_error:  # noqa: BLE001 - preserve original action error.
                logger.error(
                    "publication rollback cleanup failed error_type=%s",
                    type(cleanup_error).__name__,
                )
        try:
            await self.repository.mark_publication_revoked(
                record.run_id, revoked_at=datetime.now(UTC)
            )
        except Exception as metadata_error:  # noqa: BLE001 - publication may not have persisted.
            logger.debug(
                "publication rollback metadata unavailable error_type=%s",
                type(metadata_error).__name__,
            )

    async def stop_lab(self, run_id: str) -> LabSnapshot:
        record = await self._require_record(run_id)
        if record.phase == "cleaned_up" or (
            record.phase == "failed" and record.cleanup_confirmed
        ):
            return self._snapshot(record)
        record.stop_requested = True
        if record.worker is not None and not record.worker.done():
            await record.worker
        if record.attempt is None or record.lifecycle is None:
            if record.state not in {"failed", "deleted"}:
                await self.repository.transition_run(
                    record.run_id, "deleted", error_code="stopped_before_sandbox"
                )
                record.state = "deleted"
            record.phase = "cleaned_up"
            record.cleanup_confirmed = True
            record.message = _PHASE_MESSAGES["cleaned_up"]
            await self.repository.set_run_phase(record.run_id, "cleaned_up")
            return self._snapshot(record)
        return await self._cleanup(record)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        active = [
            record
            for record in self._records.values()
            if record.phase not in {"cleaned_up", "failed"}
        ]
        for record in active:
            try:
                await self.stop_lab(record.run_id)
            except Exception as exc:  # noqa: BLE001 - shutdown must continue.
                logger.error(
                    "lab shutdown cleanup failed error_type=%s", type(exc).__name__
                )

    async def _run(self, record: _LabRecord) -> None:
        try:
            settings = self.provider_settings_factory()
            variation = record.variation
            if variation is None:
                raise LabExecutionError("lab_execution_failed")
            await self.repository.set_run_phase(record.run_id, "generating")
            record.phase = "generating"
            record.message = _PHASE_MESSAGES[record.phase]

            adapter = self.adapter_factory()
            lifecycle = RunLifecycle(self.repository, adapter)
            record.adapter = adapter
            record.lifecycle = lifecycle
            attempt = await lifecycle.create_attempt(
                problem_id="ctf-sqli-mvp",
                run_id=record.run_id,
                attempt_id=record.attempt_id,
                parent_run_id=record.run_id,
                batch_id=record.batch_id,
                sandbox_name=record.sandbox_name,
                persist_run=False,
                variation_seed=variation.seed,
                source_revision="dashboard-source-r1",
                spec_revision="dashboard-spec-r1",
            )
            record.attempt = attempt
            record.state = "ready"
            self._raise_if_stop_requested(record)

            await self.repository.preflight_llm_batch(
                provider=settings.provider,
                model=settings.model,
                attempt_count=1,
                max_http_attempts=_int_setting("LLM_MAX_HTTP_ATTEMPTS", 8),
                token_budget=_int_setting("VULNFORGE_TOKEN_BUDGET", 16000),
                daily_request_limit=_int_setting("LLM_DAILY_REQUEST_LIMIT", 1000),
                daily_token_limit=_int_setting("LLM_DAILY_TOKEN_LIMIT", 200000),
            )
            await self.repository.create_llm_attempt_budget(
                attempt.attempt_id,
                run_id=attempt.run_id,
                batch_id=attempt.batch_id,
                provider=settings.provider,
                model=settings.model,
                max_http_attempts=_int_setting("LLM_MAX_HTTP_ATTEMPTS", 8),
                token_budget=_int_setting("VULNFORGE_TOKEN_BUDGET", 16000),
                time_budget_seconds=_float_setting(
                    "VULNFORGE_TIME_BUDGET_SECONDS", 600.0
                ),
                max_retries=_int_setting("LLM_MAX_RETRIES", 2),
                daily_request_limit=_int_setting("LLM_DAILY_REQUEST_LIMIT", 1000),
                daily_token_limit=_int_setting("LLM_DAILY_TOKEN_LIMIT", 200000),
            )

            writer = make_agent_tool_writer(adapter.agent_command_tool(attempt.guest))
            generator = ChallengeGenerator(
                self.provider_client_factory(settings),
                self.repository,
                attempt.attempt_id,
                writer,
                config=AgentLoopConfig(
                    max_iterations=_int_setting("VULNFORGE_MAX_ITERATIONS", 20),
                    max_tool_calls=_int_setting("VULNFORGE_MAX_TOOL_CALLS", 40),
                    token_budget=_int_setting("VULNFORGE_TOKEN_BUDGET", 16000),
                    time_budget_s=_float_setting(
                        "VULNFORGE_TIME_BUDGET_SECONDS", 600.0
                    ),
                    max_http_attempts=_int_setting("LLM_MAX_HTTP_ATTEMPTS", 8),
                    max_retries=_int_setting("LLM_MAX_RETRIES", 2),
                    request_max_tokens=_int_setting(
                        "VULNFORGE_REQUEST_MAX_TOKENS", 8192
                    ),
                ),
            )
            generated = await generator.generate(variation)
            record.generated = generated
            await self.repository.set_run_phase(record.run_id, "verifying")
            record.phase = "verifying"
            record.message = _PHASE_MESSAGES[record.phase]
            self._raise_if_stop_requested(record)

            await asyncio.to_thread(
                TrustedFixtureSeeder().seed,
                variation,
                upload=lambda path, payload: adapter.upload_trusted_file(
                    attempt.guest, path, payload
                ),
                execute=lambda command: adapter.control_plane_command(
                    attempt.guest, command, purpose="seed trusted SQLite fixture"
                ),
            )
            start = await asyncio.to_thread(
                adapter.control_plane_command,
                attempt.guest,
                'python3 -c \'import subprocess; subprocess.Popen(["python3","/root/app.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\'',
                purpose="start generated app privately",
            )
            if not start.dispatched or start.exit_code != 0:
                raise LabExecutionError("private_app_start_failed")
            ready = await asyncio.to_thread(
                adapter.control_plane_command,
                attempt.guest,
                "python3 -c "
                + repr(
                    "import urllib.request; "
                    f"print(urllib.request.urlopen('http://127.0.0.1:8000{build_benign_path(variation)}', timeout=8).status)"
                ),
                purpose="private app readiness probe",
            )
            if not ready.dispatched or ready.exit_code != 0:
                raise LabExecutionError("private_app_readiness_failed")
            await self.repository.transition_run(
                record.run_id, "running", app_ready_s=0.0
            )
            record.state = "running"
            verification = await asyncio.to_thread(
                verify_private_target,
                variation,
                make_control_plane_requester(
                    adapter.control_plane_guard(attempt.guest),
                    attempt.guest.command_context,
                    allowed_routes=tuple(
                        profile.route for profile in profiles_for(variation.vulnerabilities)
                    ),
                ),
                source=generated.source,
            )
            record.verification = verification
            if not verification.passed:
                raise LabExecutionError("private_verification_failed")
            self._raise_if_stop_requested(record)
            approval = await self.repository.create_approval(
                run_id=record.run_id,
                attempt_id=record.attempt_id,
                sandbox_name=record.sandbox_name,
                port=8000,
                app_sha256=generated.static.source_sha256,
                ttl_seconds=_int_setting("VULNFORGE_APPROVAL_TTL_SECONDS", 300),
                mode="interactive",
            )
            record.approval_id = approval["approval_id"]
            await self.repository.set_run_phase(record.run_id, "awaiting_publication")
            record.phase = "awaiting_publication"
            record.message = _PHASE_MESSAGES[record.phase]
        except LabStopRequested:
            record.message = "Stop requested; cleanup is being completed."
        except Exception as exc:  # noqa: BLE001 - safe error mapping is centralized.
            await self._fail(record, _error_code(exc))

    async def _cleanup(self, record: _LabRecord) -> LabSnapshot:
        record.phase = "cleaning_up"
        record.message = _PHASE_MESSAGES[record.phase]
        await self.repository.set_run_phase(record.run_id, "cleaning_up")
        try:
            attempt = record.attempt
            lifecycle = record.lifecycle
            if attempt is None or lifecycle is None:
                raise LabExecutionError("cleanup_unconfirmed")
            final = await lifecycle.cleanup(attempt)
            if final is None:
                raise LabExecutionError("cleanup_unconfirmed")
            record.state = str(final.get("state", "failed"))
            if record.state != "deleted" or not attempt.cleaned:
                raise LabExecutionError("cleanup_unconfirmed")
            if record.publication is not None:
                await self.repository.mark_publication_revoked(
                    record.run_id, revoked_at=datetime.now(UTC)
                )
            record.cleanup_confirmed = True
            record.phase = "cleaned_up"
            record.message = _PHASE_MESSAGES[record.phase]
            await self.repository.set_run_phase(record.run_id, "cleaned_up")
        except Exception as exc:  # noqa: BLE001 - cleanup must never claim success.
            record.error_code = "cleanup_unconfirmed"
            record.state = "failed"
            record.phase = "failed"
            record.message = _ERROR_CODES[record.error_code]
            logger.error("lab cleanup failed error_type=%s", type(exc).__name__)
            try:
                await self.repository.set_run_phase(record.run_id, "failed")
            except Exception as phase_error:  # noqa: BLE001 - preserve cleanup evidence.
                logger.error(
                    "lab cleanup phase persistence failed error_type=%s",
                    type(phase_error).__name__,
                )
        return self._snapshot(record)

    async def _fail(self, record: _LabRecord, code: str) -> None:
        record.error_code = code
        record.phase = "failed"
        record.message = _ERROR_CODES.get(code, _ERROR_CODES["lab_execution_failed"])
        if (
            record.attempt is not None
            and record.lifecycle is not None
            and not record.attempt.cleaned
        ):
            try:
                final = await record.lifecycle.cleanup(record.attempt, error_code=code)
                record.state = str(final.get("state", "failed")) if final else "failed"
                record.cleanup_confirmed = record.attempt.cleaned
            except Exception as cleanup_error:  # noqa: BLE001 - preserve safe failure.
                logger.error(
                    "lab failure cleanup failed error_type=%s",
                    type(cleanup_error).__name__,
                )
                record.state = "failed"
        try:
            row = await self.repository.get_run(record.run_id)
            if row is not None and row.get("state") not in {"failed", "deleted"}:
                await self.repository.transition_run(
                    record.run_id, "failed", error_code=code
                )
            if record.state != "deleted":
                record.state = "failed"
            await self.repository.set_run_phase(record.run_id, "failed")
        except Exception as persist_error:  # noqa: BLE001 - never expose persistence details.
            logger.error(
                "lab failure persistence failed error_type=%s",
                type(persist_error).__name__,
            )

    async def _require_record(self, run_id: str) -> _LabRecord:
        record = self._records.get(run_id)
        if record is None:
            row = await self.repository.get_run(run_id)
            if row is None:
                raise RunNotFound(run_id)
            raise LabConflict("lab execution is not attached to this control plane")
        return record

    def _raise_if_stop_requested(self, record: _LabRecord) -> None:
        if record.stop_requested:
            raise LabStopRequested

    def _snapshot(self, record: _LabRecord) -> LabSnapshot:
        show_url = record.phase == "published" and record.publication is not None
        publication = record.publication if show_url else None
        return LabSnapshot(
            run_id=record.run_id,
            state=cast(RunState, record.state),
            phase=cast(LabPhase, record.phase),
            message=record.message,
            can_publish=record.phase == "awaiting_publication",
            can_stop=record.phase
            in {
                "generating",
                "verifying",
                "awaiting_publication",
                "published",
                "cleaning_up",
            },
            cleanup_confirmed=record.cleanup_confirmed,
            public_url=publication.url if publication is not None else None,
            public_access_warning=(
                publication.public_access_warning if publication is not None else None
            ),
            error_code=record.error_code,
        )


def _phase_from_state(state: str) -> str:
    return {
        "created": "queued",
        "ready": "generating",
        "running": "verifying",
        "succeeded": "published",
        "deleted": "cleaned_up",
        "failed": "failed",
    }.get(state, "failed")


def _int_setting(name: str, default: int) -> int:
    value = os.getenv(name, str(default)).strip()
    try:
        parsed = int(value)
    except ValueError as exc:
        raise LabExecutionError("lab_execution_failed") from exc
    if parsed < 1:
        raise LabExecutionError("lab_execution_failed")
    return parsed


def _float_setting(name: str, default: float) -> float:
    value = os.getenv(name, str(default)).strip()
    try:
        parsed = float(value)
    except ValueError as exc:
        raise LabExecutionError("lab_execution_failed") from exc
    if parsed <= 0:
        raise LabExecutionError("lab_execution_failed")
    return parsed


def _published_host(url: str) -> str:
    parsed_host = urlsplit(url).hostname
    if not parsed_host:
        raise PublicationError("published URL has no host")
    return parsed_host


def _external_probe(url: str) -> int:
    request = urllib.request.Request(
        url, headers={"User-Agent": "VulnForge-Dashboard/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read(2048)
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, TimeoutError):
        return 503


def _safe_action_error(exc: BaseException) -> str:
    if isinstance(exc, ApprovalRequired):
        return "publication approval is not available"
    if isinstance(exc, LedgerUnavailable):
        return "ledger is unavailable"
    return "the requested lab action could not be completed"


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, LabExecutionError):
        return exc.code
    if isinstance(exc, ProviderConfigurationError):
        return "provider_not_configured"
    if isinstance(exc, ProviderHTTPError):
        if exc.status_code == 429:
            return "rate_limited"
        if exc.status_code in {400, 401, 403, 404, 413, 422}:
            return f"http_{exc.status_code}"
        return "provider_request_failed"
    if isinstance(exc, ProviderTransportError):
        return "provider_request_failed"
    if isinstance(exc, ProviderProtocolError):
        return "provider_protocol_failed"
    if isinstance(exc, NetworkPolicyViolation):
        return "sandbox_create_failed"
    if isinstance(exc, ChallengeGenerationError):
        return exc.error_code
    if isinstance(exc, PublicationError):
        return "publication_failed"
    return "lab_execution_failed"
