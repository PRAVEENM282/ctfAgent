"""Publish only a privately verified target and clean it up."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

from src.approval import ApprovalBinding, ApprovalRequired
from src.verification import VerificationResult


class PublicationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PublishedSession:
    guest: Any
    endpoint: Any
    url: str
    url_sha256: str
    created_at: datetime
    expires_at: datetime
    probe_status: int
    public_access_warning: str


class VerifiedPublisher:
    def __init__(
        self,
        adapter: Any,
        *,
        external_probe: Callable[[str], int],
        record_publication: Callable[..., Any] | None = None,
        mark_revoked: Callable[..., Any] | None = None,
        lease_seconds: int = 900,
        now: Callable[[], datetime] | None = None,
        approval_checker: Callable[..., ApprovalBinding | None] | None = None,
        require_approval: bool = True,
    ) -> None:
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")
        self.adapter = adapter
        self.external_probe = external_probe
        self.record_publication = record_publication
        self.mark_revoked = mark_revoked
        self.lease_seconds = lease_seconds
        self.now = now or (lambda: datetime.now(UTC))
        self.approval_checker = approval_checker
        self.require_approval = require_approval

    def publish_verified(
        self,
        guest: Any,
        verification: VerificationResult,
        *,
        port: int = 8000,
        run_id: str | None = None,
        attempt_id: str | None = None,
        sandbox_name: str | None = None,
        app_sha256: str | None = None,
    ) -> PublishedSession:
        if not verification.passed:
            raise PublicationError("target failed private verification; publication refused")
        if self.require_approval:
            if not all((run_id, attempt_id, sandbox_name, app_sha256)) or self.approval_checker is None:
                raise ApprovalRequired("publication requires a matching operator approval")
            approval = self.approval_checker(
                run_id=run_id,
                attempt_id=attempt_id,
                sandbox_name=sandbox_name,
                port=port,
                app_sha256=app_sha256,
            )
            if approval is None or not approval.is_valid(
                run_id=run_id,
                attempt_id=attempt_id,
                sandbox_name=sandbox_name,
                port=port,
                app_sha256=app_sha256,
                now=self.now(),
            ):
                raise ApprovalRequired("publication approval is denied, expired, mismatched, or already used")
        endpoint = self.adapter.publish(guest, port)
        url = getattr(endpoint, "url", None)
        if not isinstance(url, str) or not url:
            raise PublicationError("publisher returned no URL")
        status = int(self.external_probe(url))
        if status != 200:
            try:
                self.adapter.revoke(guest, endpoint)
            except Exception as exc:
                raise PublicationError("external probe failed and revoke was unconfirmed") from exc
            raise PublicationError(f"external probe failed with status {status}")
        created_at = self.now()
        expires_at = created_at + timedelta(seconds=self.lease_seconds)
        url_sha256 = sha256(url.encode("utf-8")).hexdigest()
        if self.record_publication is not None:
            host = urlsplit(url).hostname
            if not host:
                raise PublicationError("published URL has no host")
            try:
                self.record_publication(
                    url_sha256=url_sha256,
                    url_host=host,
                    created_at=created_at,
                    expires_at=expires_at,
                    probe_status=status,
                )
            except Exception as exc:
                try:
                    self.adapter.revoke(guest, endpoint)
                except Exception as revoke_exc:
                    raise PublicationError(
                        "publication metadata failed and revoke was unconfirmed"
                    ) from revoke_exc
                raise PublicationError("publication metadata persistence failed") from exc
        return PublishedSession(
            guest=guest,
            endpoint=endpoint,
            url=url,
            url_sha256=url_sha256,
            created_at=created_at,
            expires_at=expires_at,
            probe_status=status,
            public_access_warning=(
                "Published URLs are public and unauthenticated; anyone who obtains this "
                "short-lived URL can reach the intentionally vulnerable target."
            ),
        )

    def cleanup(self, session: PublishedSession) -> None:
        self.adapter.revoke(session.guest, session.endpoint)
        if self.mark_revoked is not None:
            self.mark_revoked(revoked_at=self.now())
        self.adapter.delete_guest(session.guest)
