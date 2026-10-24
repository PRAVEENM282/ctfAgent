"""Probe the experimental cloud-only network_policy=off create request."""

from __future__ import annotations

import os
import re
import secrets
import time
import traceback
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

import httpx
from _celesto_cloud_api.api.computers import (
    create_computer_v1_computers_post as create_computer,
)
from _celesto_cloud_api.api.computers import (
    get_computer_v1_computers_computer_id_get as get_computer,
)
from _celesto_cloud_api.api.computers import (
    list_computers_v1_computers_get as list_computers,
)
from _celesto_cloud_api.client import AuthenticatedClient
from _celesto_cloud_api.models.computer_create_request import ComputerCreateRequest
from _celesto_cloud_api.models.computer_list_response import ComputerListResponse
from _celesto_cloud_api.models.computer_response import ComputerResponse
from _celesto_cloud_api.models.network_policy import NetworkPolicy
from _celesto_cloud_api.models.network_policy_mode import NetworkPolicyMode
from _celesto_cloud_api.types import UNSET

from scripts.phase0_ephemeral_port_probe import (
    _PYTHON_SERVER_COMMAND,
    _http_probe,
    _NoRedirect,
    _redact,
)
from scripts.reap_orphans import delete_guest, reap_orphans, record_guest

BASE_URL = "https://api.celesto.ai"
PORT = 8000
MARKER = b"phase0-publication-ok"
STARTUP_TIMEOUT_SECONDS = 180
REVOKE_TIMEOUT_SECONDS = 90
REVOKE_POLL_SECONDS = 2

_OUTBOUND_CHECK = (
    "curl -m 5 -fsS -o /dev/null https://example.com "
    "&& echo OUTBOUND_RESULT=reachable "
    "|| { result=$?; printf 'OUTBOUND_RESULT=blocked curl_exit=%s\\n' \"$result\"; }"
)


class ProbeError(RuntimeError):
    pass


def _request_id(response: Any) -> str:
    for key, value in response.headers.items():
        if key.lower() in {"x-request-id", "request-id"}:
            return str(value)
    return "unavailable"


def _raw_list(client: AuthenticatedClient) -> tuple[set[str], dict[str, ComputerResponse]]:
    response = list_computers.sync_detailed(client=client, limit=100)
    if response.status_code != 200 or not isinstance(response.parsed, ComputerListResponse):
        raise ProbeError(f"cloud list failed status={response.status_code}")
    payload = response.parsed
    if payload.count != len(payload.computers):
        raise ProbeError(
            f"cloud list may be truncated count={payload.count} returned={len(payload.computers)}"
        )
    rows = {row.id: row for row in payload.computers}
    return set(rows), rows


def _shape(value: Any) -> str:
    if value is UNSET or value is None:
        return "not_visible"
    return str(value)


def _url_shape(url: str) -> tuple[str, bool]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProbeError("published URL was not a valid HTTPS URL")
    labels = parsed.hostname.split(".")
    # The first hostname label is the route-bearing component on the observed
    # Celesto URL form; do not persist its value because it is publicly usable.
    route_label = labels[0] if len(labels) > 2 else ""
    has_opaque_label = bool(
        re.search(r"[0-9a-f]{8,}|[a-z0-9]{16,}", route_label, re.IGNORECASE)
    )
    path_parts = [part for part in parsed.path.split("/") if part]
    has_opaque_path = any(
        re.search(r"[0-9a-f]{8,}|[A-Za-z0-9_-]{20,}", part)
        for part in path_parts
    )
    has_opaque_query = bool(re.search(r"[A-Za-z0-9_-]{20,}", parsed.query))
    shape_labels = list(labels)
    if route_label:
        shape_labels[0] = "<route-label>"
    path_shape = "/" + "/".join("<path-part>" for _ in path_parts) if path_parts else "/"
    shape = f"https://{'.'.join(shape_labels)}{path_shape}"
    return shape, has_opaque_label or has_opaque_path or has_opaque_query


def _guest_command(computer: Any, step: str, command: str, timeout: int = 15) -> Any:
    allowed = {"outbound_policy_check": _OUTBOUND_CHECK,
               "start_python_http_server": _PYTHON_SERVER_COMMAND}
    if computer.provider != "cloud" or command != allowed.get(step):
        raise ProbeError(f"guest command guard rejected step={step}")
    print(f"COMMAND_DISPATCH step={step} execution_target=celesto_sandbox")
    result = computer.run(command, timeout=timeout)
    if result.exit_code != 0:
        raise ProbeError(f"guest command failed step={step} exit_code={result.exit_code}")
    if step == "outbound_policy_check":
        print("GUEST_OUTBOUND_RESULT " + result.stdout.strip().replace("\n", " "))
    else:
        print("GUEST_SERVER_RESULT started=true")
    return result


def _http_get(url: str, timeout: float = 8) -> tuple[int | None, bool, str | None]:
    request = urllib.request.Request(url, headers={"User-Agent": "phase0-probe/1"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(4096)
            return response.status, MARKER in body, None
    except urllib.error.HTTPError as exc:
        return exc.code, MARKER in exc.read(4096), None
    except (urllib.error.URLError, TimeoutError) as exc:
        reason = getattr(exc, "reason", exc)
        return None, False, type(reason).__name__


def _wait_revoked(url: str, started: float) -> tuple[int | None, float, int]:
    deadline = started + REVOKE_TIMEOUT_SECONDS
    attempts = 0
    status: int | None = None
    while time.monotonic() < deadline:
        attempts += 1
        status, _marker, _error = _http_get(url)
        if status == 404:
            latency = time.monotonic() - started
            print(f"REVOKE_CONFIRMED status=404 latency_s={latency:.3f} polls={attempts}")
            return status, latency, attempts
        time.sleep(min(REVOKE_POLL_SECONDS, max(0, deadline - time.monotonic())))
    latency = time.monotonic() - started
    print(f"REVOKE_TIMEOUT last_status={status or 'none'} elapsed_s={latency:.3f} polls={attempts}")
    return status, latency, attempts


def _wait_running(client: AuthenticatedClient, computer_id: str) -> ComputerResponse:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    polls = 0
    while time.monotonic() < deadline:
        response = get_computer.sync_detailed(client=client, computer_id=computer_id)
        if response.status_code != 200 or not isinstance(response.parsed, ComputerResponse):
            raise ProbeError(f"computer status lookup failed status={response.status_code}")
        computer = response.parsed
        polls += 1
        if computer.status == "running":
            print(f"COMPUTER_READY status=running polls={polls}")
            return computer
        if computer.status not in {"creating", "starting", "pending", "restoring"}:
            raise ProbeError(f"created computer entered status={computer.status}")
        time.sleep(2)
    raise TimeoutError(f"computer did not reach running within {STARTUP_TIMEOUT_SECONDS}s")


def _create(
    client: AuthenticatedClient,
    *,
    idempotency_key: str,
) -> tuple[ComputerResponse | None, int, str, str]:
    body = ComputerCreateRequest(
        template_id="coding-agent",
        network_policy=NetworkPolicy(mode=NetworkPolicyMode.OFF),
    )
    response = create_computer.sync_detailed(
        client=client,
        body=body,
        idempotency_key=idempotency_key,
        x_celesto_experimental=UNSET,
    )
    parsed = response.parsed if isinstance(response.parsed, ComputerResponse) else None
    detail = "none"
    if response.status_code not in (200, 201):
        detail = _redact(response.content.decode("utf-8", errors="replace")[:500])
        detail = " ".join(detail.split()) or "none"
    return parsed, response.status_code, _request_id(response), detail


def _reconcile_uncertain_create(
    client: AuthenticatedClient, baseline: set[str], logical_name: str
) -> None:
    current, rows = _raw_list(client)
    added = sorted(current - baseline)
    print(f"CREATE_RECONCILIATION baseline_count={len(baseline)} new_count={len(added)}")
    if not added:
        print("CREATE_RECONCILIATION_RESULT no_new_computer")
        return
    if len(added) != 1 or rows[added[0]].template_id != "coding-agent":
        print("CREATE_RECONCILIATION_RESULT ambiguous; refusing to delete unmatched resources")
        raise ProbeError("uncertain create produced an ambiguous inventory delta")
    record_guest(added[0], logical_name)
    print("CREATE_RECONCILIATION_RESULT one_coding_agent_tracked; invoking_reaper")
    reap_orphans()


def run() -> int:
    from celesto import Computer

    api_key = os.environ.get("CELESTO_API_KEY")
    if not api_key:
        raise ProbeError("CELESTO_API_KEY is not configured")
    client = AuthenticatedClient(
        base_url=BASE_URL,
        token=api_key,
        timeout=httpx.Timeout(30),
        raise_on_unexpected_status=False,
    )
    computer: Any | None = None
    computer_id: str | None = None
    logical_name = f"sbx-{secrets.token_hex(8)}"
    route_url: str | None = None
    revoke_started: float | None = None
    cleanup_error: Exception | None = None
    route_published = False
    successful_probe = False
    try:
        reap_orphans()
        baseline, _rows = _raw_list(client)
        print("CREATE_REQUEST template_id=coding-agent network_policy=off experimental_header=omitted")
        create_started = time.monotonic()
        try:
            result, status, request_id, detail = _create(
                client, idempotency_key=secrets.token_hex(16)
            )
        except Exception as exc:  # A transport failure has an unknown create outcome.
            print(f"CREATE_OUTCOME_UNKNOWN error_type={type(exc).__name__}; reconciling")
            _reconcile_uncertain_create(client, baseline, logical_name)
            raise ProbeError("create transport failed; reconciled inventory and stopped") from exc
        print(f"CREATE_RESPONSE status={status} request_id={request_id} detail={detail}")
        if status not in (200, 201) or result is None:
            if status >= 500 or (status in (200, 201) and result is None):
                print("CREATE_OUTCOME_UNKNOWN response_incomplete=true; reconciling")
                _reconcile_uncertain_create(client, baseline, logical_name)
            else:
                print("CREATE_OUTCOME_REJECTED no_retry=true")
            raise ProbeError(f"lower-level create did not succeed; status={status}")
        computer_id = result.id
        record_guest(computer_id, logical_name)
        ready = _wait_running(client, computer_id)
        boot_duration = time.monotonic() - create_started
        policy_mode = getattr(ready.network_policy, "mode", ready.network_policy)
        policy_mode = getattr(policy_mode, "value", policy_mode)
        print(
            "CREATE_RESULT "
            f"logical_name={logical_name} computer_id={computer_id} "
            f"boot_to_ready_s={boot_duration:.3f} "
            f"vcpus={_shape(ready.vcpus)} ram_mb={_shape(ready.ram_mb)} "
            f"disk_size_mb={_shape(ready.disk_size_mb)} size_id={_shape(ready.size_id)} "
            f"price_version={_shape(ready.price_version)} "
            f"template_id={_shape(ready.template_id)} "
            f"network_policy={_shape(policy_mode)}"
        )

        computer = Computer.get(computer_id, provider="cloud")
        outbound = _guest_command(computer, "outbound_policy_check", _OUTBOUND_CHECK)
        outbound_blocked = "OUTBOUND_RESULT=blocked" in outbound.stdout
        print(f"OUTBOUND_POLICY_RESULT blocked={str(outbound_blocked).lower()}")

        _guest_command(computer, "start_python_http_server", _PYTHON_SERVER_COMMAND)
        time.sleep(1)
        published = computer.publish_port(PORT)
        route_url = published.url
        if not route_url:
            raise ProbeError("publish response omitted URL")
        route_published = True
        url_shape, url_random = _url_shape(route_url)
        print(
            f"PUBLISH_RESULT port={PORT} status={published.status} "
            f"url_shape={url_shape} random_component={str(url_random).lower()}"
        )
        status, marker, error = _http_probe(route_url)
        inbound_ok = status == 200 and marker
        print(
            f"INBOUND_RESULT status={status if status is not None else 'none'} "
            f"marker_visible={str(marker).lower()} transport_error={error or 'none'} "
            f"published_ports_verified={str(inbound_ok).lower()}"
        )

        revoke_started = time.monotonic()
        computer.unpublish_port(PORT)
        route_published = False
        revoke_status, revoke_latency, revoke_polls = _wait_revoked(route_url, revoke_started)
        print(
            f"REVOKE_RESULT status={revoke_status if revoke_status is not None else 'none'} "
            f"latency_s={revoke_latency:.3f} polls={revoke_polls} "
            f"verified={str(revoke_status == 404).lower()}"
        )
        if not outbound_blocked or not inbound_ok or revoke_status != 404:
            raise ProbeError("network policy probe did not meet all pass criteria")
        successful_probe = True
    except Exception as exc:  # noqa: BLE001 - preserve probe evidence and run cleanup.
        frames = traceback.extract_tb(exc.__traceback__)
        last = frames[-1] if frames else None
        location = f"{last.filename}:{last.lineno}" if last else "unavailable"
        print(
            f"FAIL step=network_policy_probe error={_redact(repr(exc))} "
            f"last_frame={location}"
        )
    finally:
        if computer is not None and computer_id and route_published:
            try:
                revoke_started = time.monotonic()
                computer.unpublish_port(PORT)
                route_published = False
                if route_url:
                    _wait_revoked(route_url, revoke_started)
            except Exception as exc:  # noqa: BLE001 - cleanup diagnostics must not mask probe result.
                cleanup_error = exc
                print(f"CLEANUP_REVOKE_UNCERTAIN error={_redact(repr(exc))}")
        if computer_id:
            try:
                delete_duration = delete_guest(
                    computer_id, computer=computer, name=logical_name
                )
                print(f"DELETE_DURATION duration_s={delete_duration:.3f}")
            except Exception as exc:  # noqa: BLE001 - preserve cleanup diagnostics.
                cleanup_error = cleanup_error or exc
                print(f"CLEANUP_DELETE_FAILED error={_redact(repr(exc))}")
                if computer is not None:
                    computer.close()
        if computer_id:
            print(f"PROBE_GUEST_CLEANUP complete={str(cleanup_error is None).lower()}")
        client.get_httpx_client().close()
    if successful_probe and cleanup_error is None:
        print("PASS network_policy_off_inbound_publish_probe")
        return 0
    if cleanup_error is not None:
        print(f"FAIL cleanup error={_redact(repr(cleanup_error))}")
    return 1


if __name__ == "__main__":
    raise SystemExit(run())
