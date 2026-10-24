"""Run one real M6 generation/verification/publication attempt when credentials exist."""

from __future__ import annotations

import asyncio
import os
import sys
import traceback
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agent.loop import AgentLoopConfig
from src.agent.provider import OpenAICompatibleClient, ProviderConfig
from src.agent.tools import make_agent_tool_writer
from src.approval import ApprovalRequired
from src.celesto_adapter import CelestoAdapter
from src.challenge import build_variation
from src.generator import ChallengeGenerator
from src.ledger.repository import RunRepository
from src.lifecycle import RunLifecycle
from src.publish import VerifiedPublisher
from src.recovery import RecoveryAttempt, Step7FaultInjector
from src.verification import (
    TrustedFixtureSeeder,
    make_control_plane_requester,
    verify_private_target,
)


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value or value.startswith("replace-"):
        raise RuntimeError(f"{name} is not configured")
    return value


def _external_probe(url: str) -> int:
    request = urllib.request.Request(url, headers={"User-Agent": "VulnForge-M6/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read(2048)
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)



async def _obtain_publication_approval(repository, attempt, app_sha256: str):
    mode = os.getenv("VULNFORGE_APPROVAL_MODE", "interactive").strip().lower()
    ttl = int(os.getenv("VULNFORGE_APPROVAL_TTL_SECONDS", "300"))
    row = await repository.create_approval(
        run_id=attempt.run_id,
        attempt_id=attempt.attempt_id,
        sandbox_name=attempt.guest.sandbox_name,
        port=8000,
        app_sha256=app_sha256,
        ttl_seconds=ttl,
        mode=mode,
    )
    if mode == "pre_approved":
        await repository.decide_approval(
            row["approval_id"], decision="approved", decided_by="pre_approved"
        )
    else:
        print(
            f"APPROVAL_REQUIRED approval_id={row['approval_id']} run_id={attempt.run_id} "
            f"attempt_id={attempt.attempt_id} sandbox_name={attempt.guest.sandbox_name} "
            f"port=8000 expires_at={row['expires_at']} "
            "notice=public_and_unauthenticated",
            flush=True,
        )
        while True:
            current = await repository.get_approval(row["approval_id"])
            if current is None or current["decision"] in {"approved", "denied", "expired"}:
                break
            await asyncio.sleep(1)
    binding = await repository.consume_approval(
        approval_id=row["approval_id"],
        run_id=attempt.run_id,
        attempt_id=attempt.attempt_id,
        sandbox_name=attempt.guest.sandbox_name,
        port=8000,
        app_sha256=app_sha256,
    )
    if binding is None:
        raise ApprovalRequired("publication approval was not approved or has expired")
    return binding


async def run_once(
    recovery_attempt: RecoveryAttempt | None = None,
    fault_injector: Step7FaultInjector | None = None,
) -> dict[str, object]:
    _require("CELESTO_API_KEY")
    base_url = _require("LLM_BASE_URL")
    api_key = _require("LLM_API_KEY")
    model = _require("LLM_MODEL")
    provider = os.getenv("LLM_PROVIDER", "openai").strip() or "openai"
    repository = RunRepository()
    await repository.migrate_runtime_schema()
    variation = build_variation(os.environ.get("VULNFORGE_VARIATION_SEED"))
    await repository.preflight_llm_batch(
        provider=provider, model=model, attempt_count=1, max_http_attempts=int(os.getenv("LLM_MAX_HTTP_ATTEMPTS", "8")),
        token_budget=int(os.getenv("VULNFORGE_TOKEN_BUDGET", "8000")),
        daily_request_limit=int(os.getenv("LLM_DAILY_REQUEST_LIMIT", "1000")),
        daily_token_limit=int(os.getenv("LLM_DAILY_TOKEN_LIMIT", "200000")),
    )
    adapter = CelestoAdapter()
    lifecycle = RunLifecycle(repository, adapter)
    attempt = await lifecycle.create_attempt(
        problem_id="ctf-sqli-mvp",
        run_id=recovery_attempt.run_id if recovery_attempt else None,
        attempt_id=recovery_attempt.attempt_id if recovery_attempt else None,
        parent_run_id=recovery_attempt.parent_run_id if recovery_attempt else None,
        batch_id=recovery_attempt.batch_id if recovery_attempt else None,
        variation_seed=variation.seed,
        source_revision=recovery_attempt.source_revision if recovery_attempt else "source-r1",
        spec_revision=recovery_attempt.spec_revision if recovery_attempt else "spec-r1",
    )
    await repository.create_llm_attempt_budget(
        attempt.attempt_id,
        run_id=attempt.run_id,
        batch_id=recovery_attempt.batch_id if recovery_attempt else None,
         provider=provider,
        model=model,
        max_http_attempts=int(os.getenv("LLM_MAX_HTTP_ATTEMPTS", "8")),
        token_budget=int(os.getenv("VULNFORGE_TOKEN_BUDGET", "8000")),
        time_budget_seconds=float(os.getenv("VULNFORGE_TIME_BUDGET_SECONDS", "600")),
        max_retries=int(os.getenv("LLM_MAX_RETRIES", "2")),
        daily_request_limit=int(os.getenv("LLM_DAILY_REQUEST_LIMIT", "1000")),
        daily_token_limit=int(os.getenv("LLM_DAILY_TOKEN_LIMIT", "200000")),
    )
    try:
        writer = make_agent_tool_writer(adapter.agent_command_tool(attempt.guest))
        generator = ChallengeGenerator(
            OpenAICompatibleClient(ProviderConfig(base_url=base_url, api_key=api_key, model=model)),
            repository, attempt.attempt_id, writer,
            config=AgentLoopConfig(
                max_iterations=int(os.getenv("VULNFORGE_MAX_ITERATIONS", "20")),
                max_tool_calls=int(os.getenv("VULNFORGE_MAX_TOOL_CALLS", "40")),
                token_budget=int(os.getenv("VULNFORGE_TOKEN_BUDGET", "8000")),
                time_budget_s=float(os.getenv("VULNFORGE_TIME_BUDGET_SECONDS", "600")),
                max_http_attempts=int(os.getenv("LLM_MAX_HTTP_ATTEMPTS", "8")),
                max_retries=int(os.getenv("LLM_MAX_RETRIES", "2")),
            ),
        )
        generated = await generator.generate(variation)
        TrustedFixtureSeeder().seed(
            variation,
            upload=lambda path, payload: adapter.upload_trusted_file(
                attempt.guest, path, payload
            ),
            execute=lambda command: adapter.control_plane_command(
                attempt.guest, command, purpose="seed trusted SQLite fixture"
            ),
        )
        start = adapter.control_plane_command(attempt.guest, "python3 -c 'import subprocess; subprocess.Popen([\"python3\",\"/root/app.py\"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)'", purpose="start generated app privately")
        if not start.dispatched or start.exit_code != 0:
            raise RuntimeError("private app start failed")
        ready = adapter.control_plane_command(attempt.guest, "python3 -c 'import urllib.request; print(urllib.request.urlopen(\"http://127.0.0.1:8000/search?q=health\", timeout=8).status)'", purpose="private app readiness probe")
        if not ready.dispatched or ready.exit_code != 0:
            raise RuntimeError("private app readiness failed")
        (fault_injector or Step7FaultInjector.from_environment()).before_verifier()
        verification = verify_private_target(
            variation,
            make_control_plane_requester(
                adapter.control_plane_guard(attempt.guest),
                attempt.guest.command_context,
            ),
            source=generated.source,
        )
        approval = await _obtain_publication_approval(
            repository, attempt, generated.static.source_sha256
        )
        publisher = VerifiedPublisher(
            adapter,
            external_probe=_external_probe,
            lease_seconds=900,
            approval_checker=lambda **_kwargs: approval,
        )
        session = publisher.publish_verified(
            attempt.guest,
            verification,
            run_id=attempt.run_id,
            attempt_id=attempt.attempt_id,
            sandbox_name=attempt.guest.sandbox_name,
            app_sha256=generated.static.source_sha256,
        )
        host = urlsplit(session.url).hostname
        if host is None:
            raise RuntimeError("published URL host is missing")
        await repository.record_publication(
            attempt.run_id,
            url_sha256=session.url_sha256,
            url_host=host,
            created_at=session.created_at,
            expires_at=session.expires_at,
            probe_status=session.probe_status,
        )
        attempt.endpoint = session.endpoint
        attempt.state = "succeeded"
        await repository.transition_run(attempt.run_id, "running", app_ready_s=0.0, published_url_probe_status=200)
        await repository.transition_run(attempt.run_id, "succeeded")
        final = await lifecycle.cleanup(attempt)
        await repository.mark_publication_revoked(
            attempt.run_id, revoked_at=datetime.now(UTC)
        )
        return {"run_id": attempt.run_id, "attempt_id": attempt.attempt_id, "sandbox_name": attempt.guest.sandbox_name, "verified": verification.passed, "published_status": session.probe_status, "final_state": final.get("state") if final else None}
    except Exception as exc:
        exc.sandbox_name = attempt.guest.sandbox_name
        exc.run_id = attempt.run_id
        exc.attempt_id = attempt.attempt_id
        if not attempt.cleaned:
            await lifecycle.cleanup(attempt, error_code="m6_failed")
        raise


def main() -> int:
    step = "validate_configuration"
    try:
        step = "m6_attempt"
        result = asyncio.run(run_once())
        print(result)
        return 0
    except Exception as exc:  # noqa: BLE001 - required redacted failure diagnostics.
        frames = traceback.extract_tb(exc.__traceback__)
        frame = frames[-1] if frames else None
        location = f"{frame.filename}:{frame.lineno}" if frame else "unavailable"
        print(f"M6 blocked/failed step={step} error={type(exc).__name__}: {exc} last_frame={location}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
