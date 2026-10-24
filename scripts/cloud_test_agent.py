"""Run the test-only deterministic agent inside one real Celesto Cloud guest."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import shlex
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agent.loop import AgentLoopConfig
from src.agent.test_client import DeterministicTestClient
from src.agent.tools import make_agent_tool_writer
from src.celesto_adapter import CelestoAdapter, calculate_celesto_cost_usd
from src.challenge import build_variation
from src.command_guard import CommandContext
from src.generator import ChallengeGenerator

EVIDENCE = ROOT / "reports" / "evidence" / "cloud_test_agent.log"


class NoopRepository:
    """Keep the test-only client independent of PostgreSQL and provider quotas."""

    def __init__(self) -> None:
        self.request_id = 0

    async def reserve_llm_request(self, *_args, **_kwargs):
        self.request_id += 1
        return {"request_id": self.request_id}

    async def mark_llm_request_sent(self, *_args, **_kwargs):
        return None

    async def record_llm_response(self, *_args, **_kwargs):
        return None

    async def complete_llm_attempt_budget(self, *_args, **_kwargs):
        return None


def _context(name: str) -> CommandContext:
    return CommandContext(
        run_id=f"run-{secrets.token_hex(6)}",
        parent_run_id=None,
        batch_id=f"batch-{secrets.token_hex(6)}",
        attempt_id=f"attempt-{secrets.token_hex(6)}",
        sandbox_name=name,
    )


def _database_command() -> str:
    code = (
        "import sqlite3; "
        "db=sqlite3.connect('/root/app.db'); "
        "db.execute(\"CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL)\"); "
        "db.execute(\"DELETE FROM secrets\"); "
        "db.execute(\"INSERT INTO secrets VALUES ('test-marker','CLOUD_TEST_MARKER')\"); "
        "db.execute(\"CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, name TEXT, email TEXT)\"); "
        "db.execute(\"DELETE FROM records\"); "
        "db.execute(\"INSERT INTO records VALUES ('r1','health','health@example.invalid')\"); "
        "db.commit()"
    )
    return f"python3 -c {shlex.quote(code)}"


def _start_command() -> str:
    code = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable,'/root/app.py'], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, "
        "start_new_session=True)"
    )
    return f"python3 -c {shlex.quote(code)}"


def _probe(url: str) -> int:
    request = urllib.request.Request(url, headers={"User-Agent": "VulnForge-Test/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            response.read(2048)
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def run() -> int:
    if os.getenv("CELESTO_PROVIDER", "cloud").strip().lower() != "cloud":
        raise RuntimeError("cloud_test_agent requires CELESTO_PROVIDER=cloud")

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    adapter = CelestoAdapter(audit_path=ROOT / "logs" / "commands.jsonl")
    guest = None
    endpoint = None
    cleanup_confirmed = False
    return_code = 1
    result: dict[str, object] = {"execution_target": "celesto_sandbox"}
    try:
        context = _context(f"sbx-{secrets.token_hex(8)}")
        guest = adapter.create_guest(
            "coding-agent",
            sandbox_name=context.sandbox_name,
            command_context_factory=lambda _name: context,
        )
        result.update(
            {
                "sandbox_name": guest.sandbox_name,
                "computer_id": guest.computer_id,
                "boot_to_ready_s": guest.boot_to_ready_s,
                "egress_status": guest.egress_check.status if guest.egress_check else None,
            }
        )

        writer = make_agent_tool_writer(adapter.agent_command_tool(guest))
        generator = ChallengeGenerator(
            DeterministicTestClient(),
            NoopRepository(),
            context.attempt_id,
            writer,
            config=AgentLoopConfig(
                max_iterations=1,
                max_tool_calls=1,
                token_budget=1024,
                time_budget_s=60,
                max_http_attempts=1,
                max_retries=0,
                request_max_tokens=128,
            ),
        )
        generated = asyncio.run(generator.generate(build_variation("cloud-test-agent")))
        result.update(
            {
                "agent_model": "deterministic_test_policy",
                "generated_source_sha256": generated.static.source_sha256,
                "generated_source_bytes": generated.static.source_length,
            }
        )

        seed = adapter.control_plane_command(
            guest,
            _database_command(),
            timeout=30,
            purpose="seed test-only SQLite fixture",
        )
        if seed.exit_code != 0:
            raise RuntimeError("test fixture seed failed")
        start = adapter.control_plane_command(
            guest,
            _start_command(),
            timeout=30,
            purpose="start generated app in the guest",
        )
        if start.exit_code != 0:
            raise RuntimeError("generated app start failed")
        ready = adapter.control_plane_command(
            guest,
            "python3 -c 'import urllib.request; print(urllib.request.urlopen(\"http://127.0.0.1:8000/search?q=health\", timeout=8).status)'",
            timeout=15,
            purpose="probe generated app inside the guest",
        )
        if ready.exit_code != 0 or ready.stdout.strip() != "200":
            raise RuntimeError("generated app readiness failed")
        endpoint = adapter.publish(guest, 8000)
        public_status = _probe(endpoint.url)
        result.update(
            {
                "generated_app_private_status": 200,
                "published_status": public_status,
                "published_url_host": endpoint.url.split("/", 3)[2],
            }
        )
        if public_status != 200:
            raise RuntimeError("published endpoint did not return HTTP 200")
        return_code = 0
    except Exception as exc:  # noqa: BLE001 - evidence records a safe type only.
        result.update(
            {
                "success": False,
                "error_type": type(exc).__name__,
                "provider_status": getattr(exc, "status_code", None),
                "provider_code": getattr(exc, "code", None),
                "provider_side_effects": getattr(exc, "side_effects", None),
            }
        )
        return_code = 1
    finally:
        if guest is not None:
            if endpoint is not None:
                try:
                    adapter.revoke(guest, endpoint)
                except Exception as exc:  # noqa: BLE001 - deletion still runs.
                    result["revoke_error_type"] = type(exc).__name__
            try:
                adapter.delete_guest(guest)
                cleanup_confirmed = True
            except Exception as exc:  # noqa: BLE001 - preserve unconfirmed cleanup.
                result["delete_error_type"] = type(exc).__name__
        duration = max(0.0, time.monotonic() - started)
        result.update(
            {
                "success": return_code == 0 and cleanup_confirmed,
                "cleanup_confirmed": cleanup_confirmed,
                "wall_clock_s": duration,
                "cost_usd": float(calculate_celesto_cost_usd(duration)),
            }
        )
        EVIDENCE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return return_code if cleanup_confirmed else 1


if __name__ == "__main__":
    raise SystemExit(run())
