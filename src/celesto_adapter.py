"""Version-isolated Celesto lifecycle adapter."""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from celesto import Computer

from scripts.reap_orphans import _cli, delete_guest, reap_orphans, record_guest
from src.command_guard import AgentCommandTool, CommandContext, CommandGuard

logger = logging.getLogger(__name__)
_LIST_LIMIT = 100
_DELETE_POLL_SECONDS = 2
_REVOKE_TIMEOUT_SECONDS = 90
_CELESTO_SDK_VERSION = "0.1.7"
_MICRO_USD_PER_HOUR = Decimal("0.015")
_OUTBOUND_CHECK = (
    "curl -m 5 -fsS -o /dev/null https://example.com "
    "&& echo OUTBOUND_RESULT=reachable "
    "|| { result=$?; printf 'OUTBOUND_RESULT=blocked curl_exit=%s\\n' \"$result\"; }"
)
_OUTBOUND_RESULT = re.compile(
    r"^OUTBOUND_RESULT=(reachable|blocked)(?: curl_exit=(\d+))?$"
)


@dataclass(frozen=True)
class Guest:
    computer_id: str
    sandbox_name: str
    computer: Any
    boot_to_ready_s: float
    egress_check: EgressCheck | None = None
    command_context: CommandContext | None = None
    created_monotonic: float | None = None


@dataclass(frozen=True)
class EgressCheck:
    status: str
    curl_exit_code: int | None
    duration_ms: int


@dataclass(frozen=True)
class PublishedEndpoint:
    port: int
    url: str
    status: str


@dataclass(frozen=True)
class ResumeReadiness:
    resume_s: float
    app_ready_s: float
    published_status: int


class NetworkPolicyViolation(RuntimeError):
    """Raised when a guest created with egress disabled can reach the internet."""

    def __init__(self, message: str, *, guest_duration_s: float | None = None) -> None:
        super().__init__(message)
        self.guest_duration_s = guest_duration_s


def _delete_local_guest(computer_id: str, *, computer: Any | None = None, **_kwargs: Any) -> float:
    """Delete a local VM object without calling the Cloud inventory API."""
    started = time.monotonic()
    if computer is None:
        raise RuntimeError(f"local Celesto guest {computer_id} is not attached")
    try:
        computer.delete()
    finally:
        close = getattr(computer, "close", None)
        if callable(close):
            close()
    return max(0.0, time.monotonic() - started)


def _configure_network_policy_off(computer: Any) -> None:
    """Set the pinned SDK's generated create field; never fall back to egress-on."""
    try:
        sdk_version = version("celesto")
    except PackageNotFoundError as exc:
        raise RuntimeError("pinned Celesto SDK is unavailable") from exc
    if sdk_version != _CELESTO_SDK_VERSION:
        raise RuntimeError("network_policy=off requires the pinned Celesto SDK version")

    provider = getattr(computer, "_provider", None)
    body = getattr(provider, "_body", None)
    if body is None or not hasattr(body, "network_policy"):
        raise RuntimeError("pinned Celesto create request has no network_policy field")

    from _celesto_cloud_api.models.network_policy import NetworkPolicy
    from _celesto_cloud_api.models.network_policy_mode import NetworkPolicyMode

    policy = NetworkPolicy(mode=NetworkPolicyMode.OFF)
    if policy.mode != NetworkPolicyMode.OFF:
        raise RuntimeError("failed to configure Celesto network_policy=off")
    body.network_policy = policy


def calculate_celesto_cost_usd(duration_s: float) -> Decimal:
    if duration_s < 0:
        raise ValueError("guest duration cannot be negative")
    cost = _MICRO_USD_PER_HOUR * Decimal(str(duration_s)) / Decimal(3600)
    return cost.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)


def _list_cloud_ids() -> set[str]:
    result = subprocess.run(
        [
            _cli(),
            "computer",
            "list",
            "--cloud",
            "--json",
            "--limit",
            str(_LIST_LIMIT),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    try:
        envelope = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Celesto inventory returned invalid JSON") from exc
    if result.returncode != 0 or envelope.get("ok") is not True:
        raise RuntimeError("Celesto inventory request failed")
    data = envelope.get("data") or {}
    computers = data.get("computers")
    if not isinstance(computers, list):
        raise TypeError("Celesto inventory omitted computers")
    if len(computers) >= _LIST_LIMIT:
        raise RuntimeError(
            "Celesto inventory reached its limit; refusing reconciliation"
        )
    return {
        item["computer_id"]
        for item in computers
        if isinstance(item, dict) and isinstance(item.get("computer_id"), str)
    }


def _unknown_create_outcome(exc: BaseException) -> bool:
    status = getattr(exc, "status_code", None)
    side_effects = getattr(exc, "side_effects", None)
    kind = type(exc).__name__
    return (
        status == 503
        or side_effects == "unknown"
        or kind in {"ReadTimeout", "ConnectError", "TimeoutError"}
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _published_url_probe(url: str) -> tuple[int | None, bytes]:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    if parsed.scheme != "https" or not hostname.endswith(".celesto.dev"):
        raise ValueError("published URL must use the observed Celesto HTTPS host")
    request = urllib.request.Request(url, headers={"User-Agent": "ctfAgent/1.0"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, response.read(4096)
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, TimeoutError):
        return None, b""


def _published_url_status(url: str) -> int | None:
    status, _body = _published_url_probe(url)
    return status


class CelestoAdapter:
    """Expose only the project-approved Celesto lifecycle operations."""

    def __init__(
        self,
        *,
        computer_factory: Callable[..., Any] | None = None,
        list_ids: Callable[[], set[str]] | None = None,
        reap: Callable[[], list[str]] | None = None,
        record: Callable[[str, str], None] | None = None,
        delete: Callable[..., float] | None = None,
        configure_network_policy: Callable[[Any], None] | None = None,
        command_guard_factory: Callable[[Any], CommandGuard] | None = None,
        audit_path: Path | None = None,
        monotonic: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
        trusted_file_uploader: Callable[[Any, str, bytes], None] | None = None,
    ) -> None:
        self._provider = os.getenv("CELESTO_PROVIDER", "cloud").strip().lower()
        if self._provider not in {"cloud", "local"}:
            raise ValueError("CELESTO_PROVIDER must be cloud or local")
        self._computer_factory = computer_factory or Computer
        self._list_ids = list_ids or (
            _list_cloud_ids if self._provider == "cloud" else lambda: set()
        )
        self._reap = reap or (reap_orphans if self._provider == "cloud" else list)
        self._record = record or (record_guest if self._provider == "cloud" else lambda *_args: None)
        self._delete = delete or (
            delete_guest if self._provider == "cloud" else _delete_local_guest
        )
        self._configure_network_policy = (
            configure_network_policy or _configure_network_policy_off
        )
        self._audit_path = audit_path or (
            Path(os.environ.get("VULNFORGE_STATE_DIR", ".")) / "logs" / "commands.jsonl"
        )
        self._monotonic = monotonic or time.monotonic
        self._sleep = sleep or time.sleep
        self._command_guard_factory = command_guard_factory or self._make_command_guard
        self._trusted_file_uploader = trusted_file_uploader

    def _make_command_guard(self, computer: Any) -> CommandGuard:
        return CommandGuard(
            lambda command, **options: self.run_command(computer, command, **options),
            audit_path=self._audit_path,
        )

    def agent_command_tool(self, guest: Guest) -> AgentCommandTool:
        if guest.command_context is None:
            raise ValueError("guest has no audited command identity")
        return AgentCommandTool(
            self._command_guard_factory(guest.computer), guest.command_context
        )

    def upload_trusted_file(self, guest: Guest, guest_path: str, payload: bytes) -> None:
        """Transfer trusted bytes only through an explicitly verified SDK boundary."""
        if not guest_path.startswith("/root/") or not isinstance(payload, bytes):
            raise ValueError("trusted uploads require a /root path and bytes payload")
        if self._trusted_file_uploader is None:
            raise RuntimeError(
                "Celesto 0.1.7 exposes no verified public file-upload method; "
                "refusing to put trusted data in a command string"
            )
        self._trusted_file_uploader(guest.computer, guest_path, payload)

    def control_plane_guard(self, guest: Guest) -> CommandGuard:
        if guest.command_context is None:
            raise ValueError("guest has no audited command identity")
        return self._command_guard_factory(guest.computer)

    def control_plane_command(
        self,
        guest: Guest,
        command: str,
        *,
        timeout: int = 30,
        purpose: str = "",
    ) -> Any:
        """Run trusted verifier/runtime work through the same audit path."""
        if guest.command_context is None:
            raise ValueError("guest has no audited command identity")
        return self._command_guard_factory(guest.computer).execute_control_plane(
            guest.command_context,
            command,
            cwd="/root",
            timeout=timeout,
            purpose=purpose,
        )

    def create_guest(
        self,
        template_id: str = "coding-agent",
        *,
        sandbox_name: str | None = None,
        command_context_factory: Callable[[str], CommandContext],
    ) -> Guest:
        """Create one guest with egress disabled and verify that policy per attempt."""
        self._reap()
        for attempt in (1, 2):
            baseline = self._list_ids()
            guest_name = sandbox_name or f"sbx-{secrets.token_hex(8)}"
            if not re.fullmatch(r"sbx-[a-z0-9]{8,}", guest_name):
                raise ValueError(
                    "sandbox_name must use the sbx- prefix and lowercase ID"
                )
            command_context = command_context_factory(guest_name)
            if command_context.sandbox_name != guest_name:
                raise ValueError("command context must use the created sandbox name")
            if self._provider == "cloud":
                computer_options = {
                    "provider": "cloud",
                    "lifetime": "ephemeral",
                    "template_id": template_id,
                }
            else:
                computer_options = {
                    "provider": "local",
                    "lifetime": "ephemeral",
                    "backend": os.getenv("CELESTO_BACKEND", "qemu"),
                    "os": os.getenv("CELESTO_OS", "ubuntu"),
                    "comm_channel": "ssh",
                    "internet_settings": {"mode": "off"},
                }
            computer = self._computer_factory(**computer_options)
            # The generated request path is intentionally isolated to this adapter.
            # Refuse to start if it cannot set the pinned policy field.
            if self._provider == "cloud":
                self._configure_network_policy(computer)
            started = self._monotonic()
            try:
                computer.start()
            except Exception as exc:
                computer_id = getattr(computer, "id", None)
                unknown = _unknown_create_outcome(exc)
                if not unknown and not computer_id:
                    raise
                self._reconcile_create(baseline, computer_id, guest_name)
                if not unknown or attempt == 2:
                    raise
                logger.warning(
                    "Celesto create outcome reconciled; retrying once status=%s",
                    getattr(exc, "status_code", "unknown"),
                )
                continue

            computer_id = getattr(computer, "id", None)
            if not computer_id:
                self._reconcile_create(baseline, None, guest_name)
                raise RuntimeError("Celesto create returned without a computer ID")

            self._record(computer_id, guest_name)
            boot_time = self._monotonic() - started
            logger.info("Celesto guest ready boot_to_ready_s=%.3f", boot_time)
            try:
                egress_check = self._check_egress(
                    self._command_guard_factory(computer),
                    command_context,
                )
            except Exception as check_error:  # noqa: BLE001 - fail closed for every check failure.
                delete_confirmed = False
                logger.error(
                    "network_policy_self_check_failed error_type=%s",
                    type(check_error).__name__,
                )
                try:
                    self._delete(computer_id, computer=computer, name=guest_name)
                    delete_confirmed = True
                except Exception as cleanup_error:  # noqa: BLE001 - any failed cleanup must be reported.
                    logger.error(
                        "Celesto guest cleanup after egress check failure was unconfirmed "
                        "cleanup_error=%s",
                        type(cleanup_error).__name__,
                    )
                if isinstance(check_error, NetworkPolicyViolation):
                    failure = check_error
                else:
                    failure = NetworkPolicyViolation(
                        "network_policy=off self-check failed; guest was not accepted"
                    )
                if delete_confirmed:
                    failure.guest_duration_s = max(0.0, self._monotonic() - started)
                raise failure from None
            return Guest(
                computer_id,
                guest_name,
                computer,
                boot_time,
                egress_check,
                command_context,
                started,
            )
        raise AssertionError("bounded create loop exhausted")

    def _check_egress(
        self, command_guard: CommandGuard, context: CommandContext
    ) -> EgressCheck:
        outcome = command_guard.execute_control_plane(
            context,
            _OUTBOUND_CHECK,
            timeout=8,
            purpose="per-attempt network_policy self-check",
        )
        if not outcome.dispatched or outcome.exit_code != 0:
            logger.error(
                "network_policy_self_check_command_failed dispatched=%s exit_code=%s "
                "duration_ms=%s",
                outcome.dispatched,
                outcome.exit_code,
                outcome.duration_ms,
            )
            raise NetworkPolicyViolation(
                "network_policy=off self-check did not complete"
            )
        match = _OUTBOUND_RESULT.fullmatch(outcome.stdout.strip())
        if match is None:
            logger.error(
                "network_policy_self_check_unparseable exit_code=%s stdout_bytes=%s "
                "stderr_bytes=%s duration_ms=%s",
                outcome.exit_code,
                len(outcome.stdout.encode()),
                len(outcome.stderr.encode()),
                outcome.duration_ms,
            )
            raise NetworkPolicyViolation(
                "network_policy=off self-check returned no result"
            )
        status, raw_exit_code = match.groups()
        if status == "reachable":
            logger.error(
                "network_policy_self_check_egress_reachable curl_exit_code=%s "
                "duration_ms=%s",
                raw_exit_code,
                outcome.duration_ms,
            )
            raise NetworkPolicyViolation(
                "network_policy=off self-check detected guest egress"
            )
        if raw_exit_code is None:
            logger.error("network_policy_self_check_missing_curl_status")
            raise NetworkPolicyViolation(
                "network_policy=off self-check omitted curl status"
            )
        check = EgressCheck(
            status="blocked",
            curl_exit_code=int(raw_exit_code),
            duration_ms=outcome.duration_ms,
        )
        logger.info(
            "network_policy_self_check status=%s curl_exit_code=%s duration_ms=%s",
            check.status,
            check.curl_exit_code,
            check.duration_ms,
        )
        return check

    def _reconcile_create(
        self, baseline: set[str], known_id: str | None, sandbox_name: str
    ) -> None:
        if self._provider == "local":
            return
        current = self._list_ids()
        added = current - baseline
        if known_id and added and known_id not in added:
            raise RuntimeError("ambiguous Celesto create inventory delta")
        if len(added) > 1 and not known_id:
            raise RuntimeError("ambiguous Celesto create inventory delta")
        candidate = known_id or (next(iter(added)) if added else None)
        if candidate:
            self._record(candidate, sandbox_name)
        # This also confirms absence for tracked IDs not present in inventory.
        self._reap()

    def run_command(
        self, computer: Any, command: str, *, cwd: str, timeout: int
    ) -> Any:
        """Internal dispatch primitive; give this only to CommandGuard."""
        if cwd != "/root":
            raise ValueError("guest commands must use /root as their working directory")
        return computer.run(f"cd /root && {command}", timeout=timeout)

    def publish(self, guest: Guest, port: int = 8000) -> PublishedEndpoint:
        if self._provider == "local":
            raise RuntimeError(
                "Celesto local computers cannot publish public ports; "
                "set CELESTO_PROVIDER=cloud for the publication lifecycle"
            )
        result = guest.computer.publish_port(port)
        if not result.url:
            raise RuntimeError("Celesto publish response omitted its URL")
        return PublishedEndpoint(port, result.url, result.status)

    def stop_guest(self, guest: Guest) -> float:
        started = self._monotonic()
        guest.computer.stop()
        elapsed = self._monotonic() - started
        logger.info("Celesto guest stopped stop_s=%.3f", elapsed)
        return elapsed

    def resume_guest(self, guest: Guest) -> float:
        started = self._monotonic()
        guest.computer.resume()
        elapsed = self._monotonic() - started
        logger.info("Celesto guest resumed resume_s=%.3f", elapsed)
        return elapsed

    def resume_and_wait_ready(
        self,
        guest: Guest,
        endpoint: PublishedEndpoint,
        *,
        restart_command: str,
        expected_marker: str,
        timeout: float = 60,
        poll_interval: float = 2,
    ) -> ResumeReadiness:
        resume_s = self.resume_guest(guest)
        return self._start_and_wait_ready(
            guest,
            endpoint,
            restart_command=restart_command,
            expected_marker=expected_marker,
            resume_s=resume_s,
            timeout=timeout,
            poll_interval=poll_interval,
        )

    def start_and_wait_ready(
        self,
        guest: Guest,
        endpoint: PublishedEndpoint,
        *,
        start_command: str,
        expected_marker: str,
        timeout: float = 60,
        poll_interval: float = 2,
    ) -> ResumeReadiness:
        return self._start_and_wait_ready(
            guest,
            endpoint,
            restart_command=start_command,
            expected_marker=expected_marker,
            resume_s=0,
            timeout=timeout,
            poll_interval=poll_interval,
        )

    def _start_and_wait_ready(
        self,
        guest: Guest,
        endpoint: PublishedEndpoint,
        *,
        restart_command: str,
        expected_marker: str,
        resume_s: float,
        timeout: float,
        poll_interval: float,
    ) -> ResumeReadiness:
        if guest.command_context is None:
            raise ValueError("guest has no audited command identity")
        if not expected_marker or timeout <= 0 or poll_interval <= 0:
            raise ValueError("readiness marker and positive timeouts are required")

        guard = self._command_guard_factory(guest.computer)
        restart = guard.execute_control_plane(
            guest.command_context,
            restart_command,
            timeout=30,
            purpose="restart application after sandbox resume",
        )
        if not restart.dispatched or restart.exit_code != 0:
            raise RuntimeError(
                "application restart command failed after sandbox resume"
            )

        started = self._monotonic()
        deadline = started + timeout
        expected = expected_marker.encode()
        while self._monotonic() < deadline:
            status, body = _published_url_probe(endpoint.url)
            if status == 200 and expected in body:
                elapsed = self._monotonic() - started
                logger.info(
                    "application ready after resume app_ready_s=%.3f status=200",
                    elapsed,
                )
                return ResumeReadiness(resume_s, elapsed, 200)
            self._sleep(min(poll_interval, max(0, deadline - self._monotonic())))
        raise TimeoutError(
            "application did not return the expected marker after resume"
        )

    def revoke(self, guest: Guest, endpoint: PublishedEndpoint) -> float:
        if self._provider == "local":
            raise RuntimeError("local Celesto has no public route to revoke")
        started = self._monotonic()
        try:
            guest.computer.unpublish_port(endpoint.port)
            deadline = started + _REVOKE_TIMEOUT_SECONDS
            while self._monotonic() < deadline:
                if _published_url_status(endpoint.url) == 404:
                    elapsed = self._monotonic() - started
                    logger.info("Celesto endpoint revoked revoke_s=%.3f", elapsed)
                    return elapsed
                self._sleep(min(_DELETE_POLL_SECONDS, deadline - self._monotonic()))
            raise TimeoutError(
                "published endpoint did not return HTTP 404 after revoke"
            )
        except Exception as exc:
            elapsed = self._monotonic() - started
            logger.error(
                "Celesto endpoint revoke unconfirmed revoke_s=%.3f error=%s",
                elapsed,
                type(exc).__name__,
            )
            raise

    def delete_guest(self, guest: Guest) -> float:
        elapsed = self._delete(
            guest.computer_id,
            computer=guest.computer,
            name=guest.sandbox_name,
        )
        logger.info("Celesto guest deleted delete_s=%.3f", elapsed)
        return elapsed

    def guest_duration_s(self, guest: Guest) -> float:
        if guest.created_monotonic is None:
            raise ValueError("guest has no creation timestamp")
        return max(0.0, self._monotonic() - guest.created_monotonic)
