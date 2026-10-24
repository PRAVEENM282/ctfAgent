"""Run one real Celesto create, egress check, publish, resume, and SIGINT cleanup."""

from __future__ import annotations

import asyncio
import logging
import shlex

from src.celesto_adapter import CelestoAdapter
from src.ledger.repository import RunRepository
from src.lifecycle import LifecycleAttempt, RunLifecycle

_MARKER = "M3_LIFECYCLE_READY"


def _server_command() -> str:
    server_code = (
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.send_response(200)\n"
        "        self.end_headers()\n"
        f"        self.wfile.write(b'{_MARKER}')\n"
        "    def log_message(self, *_args):\n"
        "        pass\n"
        "HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()\n"
    )
    launcher = (
        "import os, signal, subprocess, sys, time\n"
        "pid_file = '/root/.vulnforge-m3-http.pid'\n"
        "try:\n"
        "    old_pid = int(open(pid_file).read().strip())\n"
        "    os.kill(old_pid, signal.SIGTERM)\n"
        "    time.sleep(0.2)\n"
        "except (OSError, ValueError):\n"
        "    pass\n"
        f"server_code = {server_code!r}\n"
        "log = open('/root/.vulnforge-m3-http.log', 'ab', buffering=0)\n"
        "process = subprocess.Popen([sys.executable, '-c', server_code], "
        "stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, "
        "start_new_session=True, close_fds=True)\n"
        "log.close()\n"
        "open(pid_file, 'w').write(str(process.pid))\n"
        "time.sleep(0.2)\n"
        "if process.poll() is not None:\n"
        "    raise SystemExit(1)\n"
        "print('SERVER_STARTED')\n"
    )
    return f"python3 -c {shlex.quote(launcher)}"


async def run() -> int:
    adapter_logger = logging.getLogger("src.celesto_adapter")
    adapter_logger.setLevel(logging.INFO)
    adapter_logger.addHandler(logging.StreamHandler())
    adapter_logger.propagate = False
    adapter = CelestoAdapter()
    lifecycle = RunLifecycle(RunRepository(), adapter)
    attempt: LifecycleAttempt | None = None
    try:
        attempt = await lifecycle.create_attempt(problem_id="ctf-m3-live-lifecycle")
        check = attempt.guest.egress_check
        if check is None or check.status != "blocked":
            raise RuntimeError(
                "project egress self-check did not confirm blocked egress"
            )
        print(
            f"CREATE_READY run_id={attempt.run_id} "
            f"egress={check.status} curl_exit={check.curl_exit_code} "
            f"boot_to_ready_s={attempt.guest.boot_to_ready_s:.3f}",
            flush=True,
        )

        readiness = await lifecycle.start_and_publish(
            attempt,
            start_command=_server_command(),
            expected_marker=_MARKER,
        )
        print(
            f"PUBLISH_READY status={readiness.published_status} "
            f"app_ready_s={readiness.app_ready_s:.3f}",
            flush=True,
        )

        stop_s = await lifecycle.pause(attempt)
        resumed = await lifecycle.resume(
            attempt,
            restart_command=_server_command(),
            expected_marker=_MARKER,
        )
        print(
            f"RESUME_READY same_computer_id=true status={resumed.published_status} "
            f"stop_s={stop_s:.3f} resume_s={resumed.resume_s:.3f} "
            f"app_ready_s={resumed.app_ready_s:.3f}",
            flush=True,
        )
        print("LIFECYCLE_ACTIVE waiting_for_sigint=true", flush=True)
        row = await lifecycle.wait_for_sigint(attempt)
        if row is None or row.get("state") != "deleted":
            raise RuntimeError("SIGINT cleanup did not persist deleted state")
        print(
            f"SIGINT_CLEANUP state=deleted error_code={row.get('error_code')} "
            f"celesto_duration_s={attempt.celesto_duration_s:.3f} "
            f"celesto_cost_usd={row.get('celesto_cost_usd')} "
            f"cost_method={row.get('celesto_cost_method')}",
            flush=True,
        )
        return 0
    except BaseException:
        if attempt is not None and not attempt.cleaned:
            try:
                await lifecycle.cleanup(attempt, error_code="live_probe_failed")
            except Exception as cleanup_error:  # noqa: BLE001 - preserve the live probe error.
                print(
                    f"EMERGENCY_CLEANUP_UNCONFIRMED error={type(cleanup_error).__name__}"
                )
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(run()))
    except Exception as exc:  # noqa: BLE001 - provider errors may contain response details.
        # Provider exceptions can carry response details; keep evidence sanitized.
        print(f"LIFECYCLE_FAILED error_type={type(exc).__name__}", flush=True)
        raise SystemExit(1) from None
