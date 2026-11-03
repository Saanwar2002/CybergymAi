from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from vulnresearch.execution import (
    BackendCapabilities,
    BackendResult,
    ExecutionLimits,
    ExecutionOutput,
    ExecutionRequirements,
    ExecutionSpec,
    ExecutionStatus,
    IsolationLevel,
    SecurityReviewApproval,
    backend_capabilities_sha256,
)
from vulnresearch.execution.reporting import write_benchmark_run_report


def make_spec() -> ExecutionSpec:
    return ExecutionSpec(
        run_id="report-output-limit-run",
        task_id="report-output-limit-task",
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


def make_approval(
    spec: ExecutionSpec, capabilities: BackendCapabilities
) -> SecurityReviewApproval:
    now = datetime.now(UTC)
    return SecurityReviewApproval(
        review_id="report-output-limit-review",
        reviewer_id="test-reviewer",
        reviewer_organization="Test Only",
        scope="benchmark_execution",
        reviewed_commit_sha="a" * 40,
        execution_spec_sha256=spec.manifest_sha256,
        backend_capabilities_sha256=backend_capabilities_sha256(capabilities),
        evidence_sha256="e" * 64,
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(days=1),
        signature="test-only-signature",
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


def test_benchmark_report_rejects_aggregate_output_over_limit_before_publication(
    tmp_path,
):
    spec = make_spec()
    capabilities = make_capabilities()
    result = make_result(spec, artifact_size=1024 * 1024 + 1)
    output_dir = tmp_path / "reports"

    with pytest.raises(ValueError, match="aggregate output limit"):
        write_benchmark_run_report(
            spec,
            result,
            backend_capabilities=capabilities,
            security_review=make_approval(spec, capabilities),
            output_dir=output_dir,
        )

    assert not output_dir.exists()


def test_benchmark_report_accepts_aggregate_output_at_exact_limit(tmp_path):
    spec = make_spec()
    capabilities = make_capabilities()
    result = make_result(spec, artifact_size=1024 * 1024)

    report_path = write_benchmark_run_report(
        spec,
        result,
        backend_capabilities=capabilities,
        security_review=make_approval(spec, capabilities),
        output_dir=tmp_path / "reports",
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report_path.is_file()
    assert report["output_artifacts"][0]["size_bytes"] == 1024 * 1024
