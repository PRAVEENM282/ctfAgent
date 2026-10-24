from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx2 import ASGITransport, AsyncClient

from src.api.main import create_app
from src.approval import (
    ApprovalBinding,
    authorization_header_token,
    expiry_from_ttl,
    operator_token_matches,
)
from src.ledger.repository import RunNotFound, RunRepository


class ApprovalMemoryRepository:
    def __init__(self) -> None:
        self.rows = {}

    async def create_approval(self, **values):
        row = {
            "approval_id": "approval-0123456789abcdef",
            "requested_at": datetime.now(UTC),
            "expires_at": datetime.now(UTC) + timedelta(seconds=300),
            "decision": "pending",
            "decided_by": None,
            "decided_at": None,
            "used_at": None,
            **values,
        }
        self.rows[row["approval_id"]] = row
        return row

    async def get_approval(self, approval_id):
        return self.rows.get(approval_id)

    async def decide_approval(self, approval_id, *, decision, decided_by):
        if approval_id not in self.rows:
            raise RunNotFound(approval_id)
        self.rows[approval_id].update(decision=decision, decided_by=decided_by)
        return self.rows[approval_id]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_approval_endpoints_require_operator_token(monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_TOKEN", "operator-secret")
    repository = ApprovalMemoryRepository()
    app = create_app(repository=repository)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        body = {
            "run_id": "run-0123456789ab",
            "attempt_id": "attempt-0123456789ab",
            "sandbox_name": "sbx-0123456789abcdef",
            "action": "publish_public_lab",
            "port": 8000,
            "app_sha256": "a" * 64,
        }
        denied = await client.post("/api/approvals", json=body)
        assert denied.status_code == 403
        created = await client.post("/api/approvals", json=body, headers={"X-Operator-Token": "operator-secret"})
        assert created.status_code == 201
        assert created.json()["decision"] == "pending"
        approval_id = created.json()["approval_id"]
        decided = await client.post(
            f"/api/approvals/{approval_id}/decision",
            json={"decision": "approved", "decided_by": "operator"},
            headers={"Authorization": "Bearer operator-secret"},
        )
        assert decided.status_code == 200
        assert decided.json()["decision"] == "approved"


def test_operator_token_helpers_are_constant_time_boundary(monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_TOKEN", "operator-secret")
    assert operator_token_matches("operator-secret") is True
    assert operator_token_matches("wrong") is False
    assert authorization_header_token("Bearer operator-secret", None) == "operator-secret"


def test_approval_binding_expires_and_is_bound_to_app_hash() -> None:
    now = datetime.now(UTC)
    binding = ApprovalBinding(
        approval_id="approval-0123456789abcdef",
        run_id="run-0123456789ab",
        attempt_id="attempt-0123456789ab",
        sandbox_name="sbx-0123456789abcdef",
        action="publish_public_lab",
        port=8000,
        app_sha256="a" * 64,
        expires_at=now + timedelta(seconds=2),
        decision="approved",
        mode="interactive",
    )
    assert binding.is_valid(
        run_id="run-0123456789ab",
        attempt_id="attempt-0123456789ab",
        sandbox_name="sbx-0123456789abcdef",
        port=8000,
        app_sha256="a" * 64,
        now=now,
    )
    assert not binding.is_valid(
        run_id="run-0123456789ab",
        attempt_id="attempt-0123456789ab",
        sandbox_name="sbx-0123456789abcdef",
        port=8000,
        app_sha256="b" * 64,
        now=now,
    )
    assert not binding.is_valid(
        run_id="run-0123456789ab",
        attempt_id="attempt-0123456789ab",
        sandbox_name="sbx-0123456789abcdef",
        port=8000,
        app_sha256="a" * 64,
        now=now + timedelta(seconds=3),
    )


def test_repository_exposes_approval_store_methods() -> None:
    assert callable(RunRepository.create_approval)
    assert callable(RunRepository.get_approval)
    assert callable(RunRepository.decide_approval)
    assert callable(RunRepository.consume_approval)


def test_approval_ttl_validation_rejects_bool_and_out_of_range_values() -> None:
    with pytest.raises(ValueError):
        expiry_from_ttl(0)
    with pytest.raises(ValueError):
        expiry_from_ttl(3601)
    with pytest.raises(ValueError):
        expiry_from_ttl(True)


def test_operator_placeholder_never_authorizes(monkeypatch) -> None:
    monkeypatch.setenv("OPERATOR_TOKEN", "replace-me")
    assert operator_token_matches("replace-me") is False
