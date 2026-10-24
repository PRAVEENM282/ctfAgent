from __future__ import annotations

import pytest

from src.approval import ApprovalBinding, ApprovalRequired
from src.publish import PublicationError, VerifiedPublisher
from src.verification import VerificationResult


class Adapter:
    def __init__(self) -> None:
        self.calls = []

    def publish(self, guest, port):
        self.calls.append(("publish", guest, port))
        return type("Endpoint", (), {"port": port, "url": "https://opaque.celesto.dev/", "status": "published"})()

    def revoke(self, guest, endpoint):
        self.calls.append(("revoke", guest, endpoint.url))

    def delete_guest(self, guest):
        self.calls.append(("delete", guest))


def _verification(passed: bool) -> VerificationResult:
    return VerificationResult(
        passed=passed,
        benign_revealed=False,
        exploit_matched=passed,
        static_pass=True,
        expected_flag_length=35,
        expected_flag_sha256="a" * 64,
        benign_body_sha256="b" * 64,
        exploit_body_sha256="c" * 64,
        benign_body_length=2,
        exploit_body_length=40,
        model_visible_summary="private verifier result",
    )


def test_publisher_probes_only_after_verification_passes_and_cleans_up() -> None:
    adapter = Adapter()
    publisher = VerifiedPublisher(adapter, external_probe=lambda _url: 200, require_approval=False)

    session = publisher.publish_verified(object(), _verification(True), port=8000)
    assert session.url.startswith("https://")
    assert adapter.calls[0][0] == "publish"

    publisher.cleanup(session)
    assert [call[0] for call in adapter.calls] == ["publish", "revoke", "delete"]


def test_publisher_never_publishes_failed_verification() -> None:
    adapter = Adapter()
    publisher = VerifiedPublisher(adapter, external_probe=lambda _url: 200, require_approval=False)

    with pytest.raises(PublicationError):
        publisher.publish_verified(object(), _verification(False))

    assert adapter.calls == []


def test_publisher_revokes_when_external_probe_fails() -> None:
    adapter = Adapter()
    publisher = VerifiedPublisher(adapter, external_probe=lambda _url: 503, require_approval=False)

    with pytest.raises(PublicationError, match="external probe"):
        publisher.publish_verified(object(), _verification(True))

    assert [call[0] for call in adapter.calls] == ["publish", "revoke"]


def test_publisher_records_hashed_url_and_bounded_lease_without_raw_url() -> None:
    adapter = Adapter()
    records = []
    revoked = []
    publisher = VerifiedPublisher(
        adapter,
        external_probe=lambda _url: 200,
        record_publication=lambda **values: records.append(values),
        mark_revoked=lambda **values: revoked.append(values),
        lease_seconds=60,
        require_approval=False,
    )

    session = publisher.publish_verified(object(), _verification(True))
    publisher.cleanup(session)

    assert records[0]["url_sha256"] == session.url_sha256
    assert "url" not in records[0] and records[0]["url_host"] == "opaque.celesto.dev"
    assert session.expires_at > session.created_at
    assert revoked


def test_publisher_requires_matching_single_use_approval_before_publish() -> None:
    adapter = Adapter()
    now = __import__("datetime").datetime.now(__import__("datetime").UTC)
    binding = ApprovalBinding(
        approval_id="approval-0123456789abcdef",
        run_id="run-0123456789ab",
        attempt_id="attempt-0123456789ab",
        sandbox_name="sbx-0123456789abcdef",
        action="publish_public_lab",
        port=8000,
        app_sha256="a" * 64,
        expires_at=now + __import__("datetime").timedelta(seconds=60),
        decision="approved",
        mode="interactive",
    )
    publisher = VerifiedPublisher(
        adapter,
        external_probe=lambda _url: 200,
        approval_checker=lambda **_kwargs: binding,
        now=lambda: now,
    )

    session = publisher.publish_verified(
        object(), _verification(True), run_id="run-0123456789ab",
        attempt_id="attempt-0123456789ab", sandbox_name="sbx-0123456789abcdef",
        app_sha256="a" * 64,
    )

    assert session.probe_status == 200
    assert adapter.calls[0][0] == "publish"


def test_publisher_refuses_missing_or_mismatched_approval() -> None:
    publisher = VerifiedPublisher(Adapter(), external_probe=lambda _url: 200)

    with pytest.raises(ApprovalRequired):
        publisher.publish_verified(
            object(), _verification(True), run_id="run-0123456789ab",
            attempt_id="attempt-0123456789ab", sandbox_name="sbx-0123456789abcdef",
            app_sha256="b" * 64,
        )
