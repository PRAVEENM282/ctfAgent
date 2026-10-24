"""Human approval binding for irreversible public publication."""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

APPROVAL_ACTION = "publish_public_lab"
APPROVAL_MODES = {"interactive", "pre_approved"}
APPROVAL_DECISIONS = {"pending", "approved", "denied", "expired"}


class ApprovalError(RuntimeError):
    pass


class ApprovalRequired(ApprovalError):
    pass


@dataclass(frozen=True)
class ApprovalBinding:
    approval_id: str
    run_id: str
    attempt_id: str
    sandbox_name: str
    action: str
    port: int
    app_sha256: str
    expires_at: datetime
    decision: str
    mode: str

    def is_valid(
        self,
        *,
        run_id: str,
        attempt_id: str,
        sandbox_name: str,
        port: int,
        app_sha256: str,
        now: datetime | None = None,
    ) -> bool:
        current = now or datetime.now(UTC)
        return (
            self.decision == "approved"
            and self.action == APPROVAL_ACTION
            and self.run_id == run_id
            and self.attempt_id == attempt_id
            and self.sandbox_name == sandbox_name
            and self.port == port
            and hmac.compare_digest(self.app_sha256, app_sha256)
            and current < self.expires_at
        )


def operator_token_configured() -> bool:
    value = os.getenv("OPERATOR_TOKEN", "")
    return bool(value and not value.startswith("replace-"))


def operator_token_matches(candidate: str | None) -> bool:
    expected = os.getenv("OPERATOR_TOKEN", "")
    if not expected or expected.startswith("replace-") or not candidate:
        return False
    return hmac.compare_digest(expected, candidate)


def authorization_header_token(authorization: str | None, header_token: str | None) -> str | None:
    if header_token:
        return header_token
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:].strip()
    return None


def public_approval_notice(expires_at: datetime) -> str:
    return (
        "This approval exposes the learner target on a public, unauthenticated URL; "
        "anyone who obtains the URL can reach the intentionally vulnerable app. "
        f"Approval expires at {expires_at.isoformat()}."
    )


def expiry_from_ttl(ttl_seconds: int, now: datetime | None = None) -> datetime:
    if isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 3600:
        raise ValueError("approval TTL must be between 1 and 3600 seconds")
    return (now or datetime.now(UTC)) + timedelta(seconds=ttl_seconds)
