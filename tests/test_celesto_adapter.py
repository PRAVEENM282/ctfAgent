from __future__ import annotations

import json
from collections import deque
from decimal import Decimal
from types import SimpleNamespace

import pytest

from src import celesto_adapter
from src.command_guard import CommandContext, CommandGuard


def _command_context(sandbox_name: str) -> CommandContext:
    return CommandContext(
        run_id="run-0123456789ab",
        parent_run_id=None,
        batch_id="batch-0123456789ab",
        attempt_id="attempt-0123456789ab",
        sandbox_name=sandbox_name,
    )


def _egress_guard(
    tmp_path, output: str = "OUTBOUND_RESULT=blocked curl_exit=28\n"
) -> CommandGuard:
    return CommandGuard(
        lambda _command, **_kwargs: SimpleNamespace(
            stdout=output, stderr="", exit_code=0
        ),
        audit_path=tmp_path / "commands.jsonl",
    )


class UnknownCreate(Exception):
    status_code = 503
    side_effects = "unknown"


class FakeComputer:
    def __init__(self, *, outcome: object, **_options: object) -> None:
        self.outcome = outcome
        self.id: str | None = None
        self.started = False

    def start(self) -> None:
        self.started = True
        if isinstance(self.outcome, Exception):
            raise self.outcome
        self.id = str(self.outcome)


def test_unknown_create_is_reconciled_and_reaped_before_one_retry(
    monkeypatch, tmp_path
) -> None:
    events: list[tuple[object, ...]] = []
    inventories = deque([set(), {"cmp_ambiguous"}, set()])
    outcomes = deque([UnknownCreate("unknown"), "cmp_ready"])

    monkeypatch.setattr(
        celesto_adapter, "reap_orphans", lambda: events.append(("reap",))
    )
    monkeypatch.setattr(
        celesto_adapter,
        "_list_cloud_ids",
        lambda: events.append(("list",)) or inventories.popleft(),
    )
    monkeypatch.setattr(
        celesto_adapter,
        "record_guest",
        lambda computer_id, name: events.append(("record", computer_id, name)),
    )

    adapter = celesto_adapter.CelestoAdapter(
        computer_factory=lambda **options: (
            events.append(("create", options["template_id"]))
            or FakeComputer(outcome=outcomes.popleft())
        ),
        configure_network_policy=lambda _computer: events.append(("policy_off",)),
        command_guard_factory=lambda _computer: _egress_guard(tmp_path),
    )

    guest = adapter.create_guest(
        command_context_factory=_command_context,
    )

    assert guest.computer_id == "cmp_ready"
    assert guest.sandbox_name.startswith("sbx-")
    assert guest.boot_to_ready_s >= 0
    assert guest.egress_check.status == "blocked"
    assert guest.egress_check.curl_exit_code == 28
    assert [event[0] for event in events] == [
        "reap",
        "list",
        "create",
        "policy_off",
        "list",
        "record",
        "reap",
        "list",
        "create",
        "policy_off",
        "record",
    ]
    assert events[5][1] == "cmp_ambiguous"
    assert ("policy_off",) in events


def test_local_provider_uses_qemu_options_and_skips_cloud_policy(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CELESTO_PROVIDER", "local")
    events: list[dict[str, object]] = []

    def create(**options: object) -> FakeComputer:
        events.append(options)
        return FakeComputer(outcome="local-ready")

    adapter = celesto_adapter.CelestoAdapter(
        computer_factory=create,
        configure_network_policy=lambda _computer: events.append({"policy": "cloud"}),
        command_guard_factory=lambda _computer: _egress_guard(tmp_path),
        record=lambda *_args: None,
    )

    guest = adapter.create_guest(command_context_factory=_command_context)

    assert guest.computer_id == "local-ready"
    assert events[0]["provider"] == "local"
    assert events[0]["backend"] == "qemu"
    assert events[0]["comm_channel"] == "ssh"
    assert events[0]["internet_settings"] == {"mode": "off"}
    assert {"policy": "cloud"} not in events


def test_local_provider_deletes_attached_vm_without_cloud_api(monkeypatch) -> None:
    monkeypatch.setenv("CELESTO_PROVIDER", "local")
    events: list[str] = []

    class LocalComputer:
        def delete(self) -> None:
            events.append("delete")

        def close(self) -> None:
            events.append("close")

    adapter = celesto_adapter.CelestoAdapter()
    elapsed = adapter._delete("local-id", computer=LocalComputer(), name="sbx-local")

    assert elapsed >= 0
    assert events == ["delete", "close"]


def test_local_provider_refuses_public_publication(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CELESTO_PROVIDER", "local")
    adapter = celesto_adapter.CelestoAdapter()
    guest = celesto_adapter.Guest(
        computer_id="local-id",
        sandbox_name="sbx-0123456789abcdef",
        computer=object(),
        boot_to_ready_s=0.1,
    )

    with pytest.raises(RuntimeError, match="cannot publish public ports"):
        adapter.publish(guest)


def test_second_unknown_create_is_not_retried_again(monkeypatch, tmp_path) -> None:
    inventories = deque([set(), set(), set(), set()])
    create_count = 0
    reap_count = 0

    def fake_reap() -> None:
        nonlocal reap_count
        reap_count += 1

    def fake_create(**_options: object) -> FakeComputer:
        nonlocal create_count
        create_count += 1
        return FakeComputer(outcome=UnknownCreate("unknown"))

    monkeypatch.setattr(celesto_adapter, "reap_orphans", fake_reap)
    monkeypatch.setattr(
        celesto_adapter, "_list_cloud_ids", lambda: inventories.popleft()
    )
    adapter = celesto_adapter.CelestoAdapter(
        computer_factory=fake_create,
        configure_network_policy=lambda _computer: None,
        command_guard_factory=lambda _computer: _egress_guard(tmp_path),
    )

    with pytest.raises(UnknownCreate):
        adapter.create_guest(
            command_context_factory=_command_context,
        )

    assert create_count == 2
    assert reap_count == 3


def test_network_policy_configuration_failure_never_starts_a_guest(tmp_path) -> None:
    computer = FakeComputer(outcome="cmp_must_not_start")

    def refuse_policy(_computer: FakeComputer) -> None:
        raise RuntimeError("network_policy=off could not be applied")

    adapter = celesto_adapter.CelestoAdapter(
        computer_factory=lambda **_options: computer,
        configure_network_policy=refuse_policy,
        command_guard_factory=lambda _computer: _egress_guard(tmp_path),
        list_ids=lambda: set(),
        reap=list,
    )

    with pytest.raises(RuntimeError, match="network_policy=off"):
        adapter.create_guest(
            command_context_factory=_command_context,
        )

    assert computer.started is False


def test_pinned_generated_request_gets_network_policy_off() -> None:
    from _celesto_cloud_api.models.computer_create_request import ComputerCreateRequest
    from _celesto_cloud_api.models.network_policy_mode import NetworkPolicyMode

    body = ComputerCreateRequest(template_id="coding-agent")
    computer = SimpleNamespace(_provider=SimpleNamespace(_body=body))

    celesto_adapter._configure_network_policy_off(computer)

    assert body.network_policy.mode == NetworkPolicyMode.OFF


def test_micro_cost_uses_observed_rate_and_guest_duration() -> None:
    assert celesto_adapter.calculate_celesto_cost_usd(3600) == Decimal("0.015000")
    with pytest.raises(ValueError, match="negative"):
        celesto_adapter.calculate_celesto_cost_usd(-1)


def test_egress_self_check_rejects_reachable_guest_and_cleans_it(tmp_path) -> None:
    computer = FakeComputer(outcome="cmp_egress_open")
    deleted: list[str] = []
    adapter = celesto_adapter.CelestoAdapter(
        computer_factory=lambda **_options: computer,
        configure_network_policy=lambda _computer: None,
        command_guard_factory=lambda _computer: _egress_guard(
            tmp_path, "OUTBOUND_RESULT=reachable\n"
        ),
        list_ids=lambda: set(),
        reap=list,
        record=lambda _computer_id, _name: None,
        delete=lambda computer_id, **_kwargs: deleted.append(computer_id) or 1.0,
    )

    with pytest.raises(celesto_adapter.NetworkPolicyViolation) as raised:
        adapter.create_guest(
            command_context_factory=_command_context,
        )

    assert deleted == ["cmp_egress_open"]
    assert raised.value.guest_duration_s is not None
    assert raised.value.guest_duration_s >= 0


def test_agent_command_tool_uses_guarded_adapter_dispatch(tmp_path) -> None:
    dispatched: list[str] = []

    class CommandComputer:
        def run(self, command: str, *, timeout: int) -> SimpleNamespace:
            dispatched.append(command)
            return SimpleNamespace(stdout="ok", stderr="", exit_code=0)

    adapter = celesto_adapter.CelestoAdapter(audit_path=tmp_path / "commands.jsonl")
    guest = celesto_adapter.Guest(
        computer_id="cmp_test",
        sandbox_name="sbx-0123456789abcdef",
        computer=CommandComputer(),
        boot_to_ready_s=1.0,
        command_context=_command_context("sbx-0123456789abcdef"),
    )

    tool = adapter.agent_command_tool(guest)
    blocked = tool("curl https://example.com/collect")
    allowed = tool("python3 -c 'print(1)'")

    assert blocked.dispatched is False
    assert allowed.dispatched is True
    assert dispatched == ["cd /root && python3 -c 'print(1)'"]
    audit_rows = [
        json.loads(line)
        for line in (tmp_path / "commands.jsonl").read_text().splitlines()
    ]
    assert all(row["origin"] == "agent" for row in audit_rows)


def test_stop_and_resume_return_separate_durations() -> None:
    class LifecycleComputer:
        def stop(self) -> None:
            pass

        def resume(self) -> None:
            pass

    clock_values = iter([10.0, 11.5, 20.0, 22.0])
    adapter = celesto_adapter.CelestoAdapter(monotonic=lambda: next(clock_values))
    guest = celesto_adapter.Guest(
        computer_id="cmp_test",
        sandbox_name="sbx-0123456789abcdef",
        computer=LifecycleComputer(),
        boot_to_ready_s=1.0,
    )

    assert adapter.stop_guest(guest) == 1.5
    assert adapter.resume_guest(guest) == 2.0


def test_resume_restarts_application_and_waits_for_expected_public_marker(
    monkeypatch, tmp_path
) -> None:
    events: list[str] = []

    class LifecycleComputer:
        def resume(self) -> None:
            events.append("resume")

        def run(self, command: str, *, timeout: int) -> SimpleNamespace:
            events.append(command)
            return SimpleNamespace(stdout="", stderr="", exit_code=0)

    monkeypatch.setattr(
        celesto_adapter,
        "_published_url_probe",
        lambda _url: (200, b"m3-lifecycle-ready"),
    )
    adapter = celesto_adapter.CelestoAdapter(audit_path=tmp_path / "commands.jsonl")
    guest = celesto_adapter.Guest(
        computer_id="cmp_resume",
        sandbox_name="sbx-0123456789abcdef",
        computer=LifecycleComputer(),
        boot_to_ready_s=1.0,
        command_context=_command_context("sbx-0123456789abcdef"),
    )
    endpoint = celesto_adapter.PublishedEndpoint(
        port=8000, url="https://route.celesto.dev/", status="published"
    )

    result = adapter.resume_and_wait_ready(
        guest,
        endpoint,
        restart_command="python3 /root/app.py",
        expected_marker="m3-lifecycle-ready",
    )

    assert events == ["resume", "cd /root && python3 /root/app.py"]
    assert result.published_status == 200
    assert result.resume_s >= 0
    assert result.app_ready_s >= 0


def test_resume_does_not_report_ready_without_expected_marker(
    monkeypatch, tmp_path
) -> None:
    class LifecycleComputer:
        def resume(self) -> None:
            pass

        def run(self, _command: str, *, timeout: int) -> SimpleNamespace:
            return SimpleNamespace(stdout="", stderr="", exit_code=0)

    monkeypatch.setattr(
        celesto_adapter, "_published_url_probe", lambda _url: (200, b"wrong")
    )
    adapter = celesto_adapter.CelestoAdapter(audit_path=tmp_path / "commands.jsonl")
    guest = celesto_adapter.Guest(
        computer_id="cmp_resume",
        sandbox_name="sbx-0123456789abcdef",
        computer=LifecycleComputer(),
        boot_to_ready_s=1.0,
        command_context=_command_context("sbx-0123456789abcdef"),
    )
    endpoint = celesto_adapter.PublishedEndpoint(
        port=8000, url="https://route.celesto.dev/", status="published"
    )

    with pytest.raises(TimeoutError, match="expected marker"):
        adapter.resume_and_wait_ready(
            guest,
            endpoint,
            restart_command="python3 /root/app.py",
            expected_marker="m3-lifecycle-ready",
            timeout=0.01,
            poll_interval=0.005,
        )


def test_revoke_polls_to_404_and_delete_returns_confirmed_duration(monkeypatch) -> None:
    class LifecycleComputer:
        def __init__(self) -> None:
            self.revoked_port: int | None = None

        def unpublish_port(self, port: int) -> None:
            self.revoked_port = port

    clock_values = iter([10.0, 10.0, 12.5])
    computer = LifecycleComputer()
    adapter = celesto_adapter.CelestoAdapter(
        monotonic=lambda: next(clock_values),
        delete=lambda *_args, **_kwargs: 3.75,
    )
    guest = celesto_adapter.Guest(
        computer_id="cmp_test",
        sandbox_name="sbx-0123456789abcdef",
        computer=computer,
        boot_to_ready_s=1.0,
    )
    endpoint = celesto_adapter.PublishedEndpoint(
        port=8000, url="https://route.celesto.dev/", status="published"
    )
    monkeypatch.setattr(celesto_adapter, "_published_url_status", lambda _url: 404)

    assert adapter.revoke(guest, endpoint) == 2.5
    assert computer.revoked_port == 8000
    assert adapter.delete_guest(guest) == 3.75


def test_trusted_upload_fails_closed_without_verified_sdk_boundary() -> None:
    adapter = celesto_adapter.CelestoAdapter()
    guest = celesto_adapter.Guest(
        computer_id="cmp_test",
        sandbox_name="sbx-0123456789abcdef",
        computer=object(),
        boot_to_ready_s=1.0,
    )

    with pytest.raises(RuntimeError, match="file-upload"):
        adapter.upload_trusted_file(guest, "/root/seed.json", b"trusted")


def test_trusted_upload_uses_only_injected_verified_boundary() -> None:
    received = []
    adapter = celesto_adapter.CelestoAdapter(
        trusted_file_uploader=lambda computer, path, payload: received.append(
            (computer, path, payload)
        )
    )
    computer = object()
    guest = celesto_adapter.Guest(
        computer_id="cmp_test",
        sandbox_name="sbx-0123456789abcdef",
        computer=computer,
        boot_to_ready_s=1.0,
    )

    adapter.upload_trusted_file(guest, "/root/seed.json", b"trusted")

    assert received == [(computer, "/root/seed.json", b"trusted")]
