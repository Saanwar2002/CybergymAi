from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vulnresearch.execution import (
    BackendCapabilities,
    ExecutionLimits,
    ExecutionRequirements,
    ExecutionSpec,
    IsolationLevel,
    SecurityReviewApproval,
    SecurityReviewError,
    backend_capabilities_sha256,
    verify_independent_review,
)


def make_spec() -> ExecutionSpec:
    return ExecutionSpec(
        run_id="review-run-001",
        task_id="review-task-001",
        command_id="fixture",
        argv=("python", "-c", "pass"),
        timeout_seconds=30,
        requirements=ExecutionRequirements.for_benchmark(),
        limits=ExecutionLimits(
            vcpu_count=1,
            memory_bytes=1024 * 1024**2,
            disk_bytes=5 * 1024**3,
            max_processes=256,
            max_input_bytes=64 * 1024**2,
            max_output_bytes_total=2 * 1024**2,
        ),
    )


def make_capabilities() -> BackendCapabilities:
    return BackendCapabilities(
        isolation_level=IsolationLevel.DISPOSABLE_VM,
        network_isolated=True,
        immutable_guest_image=True,
        isolated_storage=True,
        bounded_input_output=True,
        resource_limits=True,
        cleanup_verification=True,
        host_docker_socket_isolated=True,
    )


class TrustedTestVerifier:
    """Test-only stand-in for an independently managed signature verifier."""

    def __init__(self, accepted=True):
        self.accepted = accepted
        self.calls = 0

    def verify(self, approval):
        self.calls += 1
        return self.accepted


def make_approval(spec=None, capabilities=None, *, now=None, **overrides):
    spec = spec or make_spec()
    capabilities = capabilities or make_capabilities()
    now = now or datetime.now(UTC)
    values = {
        "review_id": "review-001",
        "reviewer_id": "independent-reviewer",
        "reviewer_organization": "External Security Review Group",
        "scope": "benchmark_execution",
        "reviewed_commit_sha": "a" * 40,
        "execution_spec_sha256": spec.manifest_sha256,
        "backend_capabilities_sha256": backend_capabilities_sha256(capabilities),
        "evidence_sha256": "e" * 64,
        "issued_at": now - timedelta(minutes=1),
        "expires_at": now + timedelta(days=1),
        "signature": "opaque-test-signature",
    }
    values.update(overrides)
    return SecurityReviewApproval(**values)


def test_review_approval_manifest_round_trip_is_strict():
    approval = make_approval()

    restored = SecurityReviewApproval.from_manifest(approval.to_manifest())

    assert restored == approval


def test_independent_review_requires_a_trusted_verifier():
    with pytest.raises(SecurityReviewError, match="no trusted independent-review verifier"):
        verify_independent_review(
            make_approval(),
            None,
            spec=make_spec(),
            capabilities=make_capabilities(),
            software_commit_sha="a" * 40,
        )


def test_independent_review_binds_exact_commit_spec_and_capabilities():
    spec = make_spec()
    capabilities = make_capabilities()
    approval = make_approval(spec, capabilities)
    verifier = TrustedTestVerifier()

    actual = verify_independent_review(
        approval,
        verifier,
        spec=spec,
        capabilities=capabilities,
        software_commit_sha="a" * 40,
    )

    assert actual is approval
    assert verifier.calls == 1

    with pytest.raises(SecurityReviewError, match="deployed commit"):
        verify_independent_review(
            approval,
            verifier,
            spec=spec,
            capabilities=capabilities,
            software_commit_sha="b" * 40,
        )
    with pytest.raises(SecurityReviewError, match="execution specification"):
        verify_independent_review(
            approval,
            verifier,
            spec=make_spec(),
            capabilities=capabilities,
            software_commit_sha="a" * 40,
        )
    weaker = BackendCapabilities(
        isolation_level=IsolationLevel.CONTAINER,
        network_isolated=True,
        immutable_guest_image=True,
        isolated_storage=True,
        bounded_input_output=True,
        resource_limits=True,
        cleanup_verification=True,
        host_docker_socket_isolated=True,
    )
    with pytest.raises(SecurityReviewError, match="backend capability claims"):
        verify_independent_review(
            approval,
            verifier,
            spec=spec,
            capabilities=weaker,
            software_commit_sha="a" * 40,
        )


def test_expired_or_not_yet_valid_review_is_rejected():
    spec = make_spec()
    capabilities = make_capabilities()
    now = datetime.now(UTC)
    verifier = TrustedTestVerifier()

    expired = make_approval(
        spec,
        capabilities,
        now=now - timedelta(days=2),
        issued_at=now - timedelta(days=2),
        expires_at=now - timedelta(days=1),
    )
    with pytest.raises(SecurityReviewError, match="not currently valid"):
        verify_independent_review(
            expired,
            verifier,
            spec=spec,
            capabilities=capabilities,
            software_commit_sha="a" * 40,
            now=now,
        )

    future = make_approval(
        spec,
        capabilities,
        issued_at=now + timedelta(days=1),
        expires_at=now + timedelta(days=2),
    )
    with pytest.raises(SecurityReviewError, match="not currently valid"):
        verify_independent_review(
            future,
            verifier,
            spec=spec,
            capabilities=capabilities,
            software_commit_sha="a" * 40,
            now=now,
        )
    assert verifier.calls == 0


def test_verifier_rejection_and_exception_fail_closed():
    spec = make_spec()
    capabilities = make_capabilities()
    approval = make_approval(spec, capabilities)

    with pytest.raises(SecurityReviewError, match="verification failed"):
        verify_independent_review(
            approval,
            TrustedTestVerifier(accepted=False),
            spec=spec,
            capabilities=capabilities,
            software_commit_sha="a" * 40,
        )

    class BrokenVerifier:
        def verify(self, _approval):
            raise RuntimeError("trust store unavailable")

    with pytest.raises(SecurityReviewError, match="failed closed"):
        verify_independent_review(
            approval,
            BrokenVerifier(),
            spec=spec,
            capabilities=capabilities,
            software_commit_sha="a" * 40,
        )
