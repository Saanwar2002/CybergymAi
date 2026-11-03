from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from vulnresearch.execution import (
    BackendCapabilities,
    BackendContractError,
    BackendResult,
    ExecutionLimits,
    ExecutionOutput,
    ExecutionRequirements,
    ExecutionSpec,
    ExecutionStatus,
    IsolationLevel,
    SecurityReviewApproval,
    backend_capabilities_sha256,
    execute_with_policy,
)


@dataclass
class OutputBackend:
    capabilities: BackendCapabilities
    result: BackendResult
    calls: int = 0

    def execute(self, spec: ExecutionSpec) -> BackendResult:
        self.calls += 1
        return self.result


class AllowTestReview:
    def verify(self, approval: SecurityReviewApproval) -> bool:
        return True


def make_spec() -> ExecutionSpec:
    return ExecutionSpec(
        run_id="aggregate-output-run",
        task_id="aggregate-output-task",
        command_id="fixture-command",
        argv=("python", "-c", "print('fixture')"),
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


def make_result(spec: ExecutionSpec, artifact_size: int) -> BackendResult:
    return BackendResult(
        status=ExecutionStatus.COMPLETED,
        returncode=0,
        stdout="s" * (512 * 1024),
        stderr="e" * (512 * 1024),
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.1,
        cleanup_confirmed=True,
        allocated_vcpu_count=1,
        peak_memory_bytes=512 * 1024**2,
        peak_disk_bytes=1024**3,
        peak_processes=32,
        input_bytes_staged=0,
        execution_spec_sha256=spec.manifest_sha256,
        outputs=(
            ExecutionOutput(
                artifact_id="fixture-output",
                sha256="a" * 64,
                size_bytes=artifact_size,
                guest_path="artifacts/result.bin",
            ),
        ),
    )


def execute_result(result: BackendResult) -> tuple[BackendResult, OutputBackend]:
    spec = make_spec()
    backend_capabilities = make_capabilities()
    backend = OutputBackend(backend_capabilities, result)
    now = datetime.now(UTC)
    approval = SecurityReviewApproval(
        review_id="aggregate-output-test-review",
        reviewer_id="test-reviewer",
        reviewer_organization="Test Only",
        scope="benchmark_execution",
        reviewed_commit_sha="a" * 40,
        execution_spec_sha256=spec.manifest_sha256,
        backend_capabilities_sha256=backend_capabilities_sha256(backend_capabilities),
        evidence_sha256="e" * 64,
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(days=1),
        signature="test-only-signature",
    )
    accepted = execute_with_policy(
        backend,
        spec,
        security_review=approval,
        review_verifier=AllowTestReview(),
        software_commit_sha="a" * 40,
    )
    return accepted, backend


def test_execution_policy_rejects_aggregate_output_over_limit():
    spec = make_spec()
    backend_result = make_result(spec, artifact_size=1024 * 1024 + 1)

    with pytest.raises(BackendContractError, match="aggregate limit"):
        execute_result(backend_result)


def test_execution_policy_accepts_aggregate_output_at_exact_limit():
    spec = make_spec()
    backend_result = make_result(spec, artifact_size=1024 * 1024)

    accepted, backend = execute_result(backend_result)

    assert accepted is backend_result
    assert backend.calls == 1
