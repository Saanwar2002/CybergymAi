from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from vulnresearch.execution import (
    BackendAttestationError,
    BackendCapabilities,
    BackendCapabilityError,
    BackendResult,
    BenchmarkBackendUnavailable,
    BenchmarkReportPersistenceError,
    BenchmarkReportPublicationError,
    ExecutionLimits,
    ExecutionRequirements,
    ExecutionSpec,
    ExecutionStatus,
    IsolationLevel,
    SecurityReviewApproval,
    SecurityReviewError,
    backend_capabilities_sha256,
    execute_benchmark,
    execute_benchmark_and_report,
)
from vulnresearch.execution import runner as runner_module


@dataclass
class RecordingBackend:
    capabilities: BackendCapabilities
    calls: int = 0

    def execute(self, spec: ExecutionSpec) -> BackendResult:
        self.calls += 1
        return BackendResult(
            status=ExecutionStatus.COMPLETED,
            returncode=0,
            stdout="ok",
            stderr="",
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
        )


def make_spec() -> ExecutionSpec:
    return ExecutionSpec(
        run_id="run-1",
        task_id="task-1",
        command_id="command-1",
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


def capabilities(level: IsolationLevel) -> BackendCapabilities:
    return BackendCapabilities(
        isolation_level=level,
        network_isolated=True,
        immutable_guest_image=True,
        isolated_storage=True,
        bounded_input_output=True,
        resource_limits=True,
        cleanup_verification=True,
        host_docker_socket_isolated=True,
    )


class AllowTestReview:
    """Test-only verifier; never use as a deployment verifier."""

    def verify(self, approval):
        return True


def review_for(spec, backend_capabilities):
    now = datetime.now(UTC)
    return SecurityReviewApproval(
        review_id="runner-review-fixture",
        reviewer_id="independent-reviewer",
        reviewer_organization="External Security Review Group",
        scope="benchmark_execution",
        reviewed_commit_sha="a" * 40,
        execution_spec_sha256=spec.manifest_sha256,
        backend_capabilities_sha256=backend_capabilities_sha256(backend_capabilities),
        evidence_sha256="e" * 64,
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(days=1),
        signature="test-only-signature",
    )


def review_kwargs(spec, backend):
    return {
        "security_review": review_for(spec, backend.capabilities),
        "review_verifier": AllowTestReview(),
        "software_commit_sha": "a" * 40,
    }


def test_benchmark_entrypoint_fails_closed_without_injected_backend():
    with pytest.raises(BenchmarkBackendUnavailable, match="no disposable-VM backend"):
        execute_benchmark(make_spec())


def test_benchmark_entrypoint_never_falls_back_to_container_backend():
    backend = RecordingBackend(capabilities(IsolationLevel.CONTAINER))

    with pytest.raises(BackendCapabilityError, match="disposable_vm"):
        execute_benchmark(
            make_spec(),
            backend=backend,
            **review_kwargs(make_spec(), backend),
        )

    assert backend.calls == 0


def test_benchmark_entrypoint_fails_closed_without_independent_review():
    backend = RecordingBackend(capabilities(IsolationLevel.DISPOSABLE_VM))

    with pytest.raises(SecurityReviewError, match="independent security-review approval"):
        execute_benchmark(make_spec(), backend=backend)

    assert backend.calls == 0


def test_benchmark_entrypoint_uses_explicit_capable_backend():
    backend = RecordingBackend(capabilities(IsolationLevel.DISPOSABLE_VM))
    spec = make_spec()

    result = execute_benchmark(
        spec, backend=backend, **review_kwargs(spec, backend)
    )

    assert result.returncode == 0
    assert backend.calls == 1


def test_benchmark_execute_and_report_persists_result_and_manifest(tmp_path):
    backend = RecordingBackend(capabilities(IsolationLevel.DISPOSABLE_VM))

    spec = make_spec()
    run = execute_benchmark_and_report(
        spec,
        backend=backend,
        **review_kwargs(spec, backend),
        output_dir=tmp_path / "reports",
    )
    report = json.loads(run.report_path.read_text(encoding="utf-8"))

    assert backend.calls == 1
    assert run.result.returncode == 0
    assert run.report_path.is_file()
    assert report["execution_spec_sha256"] == make_spec().manifest_sha256
    assert report["execution_spec"] == make_spec().to_manifest()
    assert report["backend_capabilities"] == backend.capabilities.to_manifest()


def test_benchmark_execute_and_report_still_requires_explicit_backend(tmp_path):
    with pytest.raises(BenchmarkBackendUnavailable):
        execute_benchmark_and_report(
            make_spec(),
            output_dir=tmp_path / "reports",
        )

    assert not (tmp_path / "reports").exists()


def test_report_persistence_failure_retains_validated_execution_result(
    tmp_path, monkeypatch
):
    backend = RecordingBackend(capabilities(IsolationLevel.DISPOSABLE_VM))

    def fail_report(*args, **kwargs):
        raise OSError("simulated storage failure")

    monkeypatch.setattr(runner_module, "write_benchmark_run_report", fail_report)

    with pytest.raises(BenchmarkReportPersistenceError) as error:
        execute_benchmark_and_report(
            make_spec(),
            backend=backend,
            **review_kwargs(make_spec(), backend),
            output_dir=tmp_path / "reports",
        )

    assert backend.calls == 1
    assert error.value.result.returncode == 0
    assert isinstance(error.value.cause, OSError)


def test_unexpected_report_persistence_failure_preserves_execution_result(
    tmp_path, monkeypatch
):
    backend = RecordingBackend(capabilities(IsolationLevel.DISPOSABLE_VM))

    def fail_report_unexpectedly(*args, **kwargs):
        raise RuntimeError("unexpected publication failure")

    monkeypatch.setattr(
        runner_module, "write_benchmark_run_report", fail_report_unexpectedly
    )

    with pytest.raises(BenchmarkReportPersistenceError) as error:
        execute_benchmark_and_report(
            make_spec(),
            backend=backend,
            **review_kwargs(make_spec(), backend),
            output_dir=tmp_path / "reports",
        )

    assert backend.calls == 1
    assert error.value.result.returncode == 0
    assert error.value.result.cleanup_confirmed is True
    assert isinstance(error.value.cause, RuntimeError)
    assert str(error.value.cause) == "unexpected publication failure"


def test_report_durability_failure_retains_visible_report_path(tmp_path, monkeypatch):
    backend = RecordingBackend(capabilities(IsolationLevel.DISPOSABLE_VM))
    visible_report = tmp_path / "published" / "report.json"
    visible_report.parent.mkdir()
    visible_report.write_text("{}", encoding="utf-8")

    def fail_after_publication(*args, **kwargs):
        raise BenchmarkReportPublicationError(
            visible_report,
            OSError("simulated parent directory fsync failure"),
        )

    monkeypatch.setattr(
        runner_module, "write_benchmark_run_report", fail_after_publication
    )

    with pytest.raises(BenchmarkReportPersistenceError) as error:
        execute_benchmark_and_report(
            make_spec(),
            backend=backend,
            **review_kwargs(make_spec(), backend),
            output_dir=tmp_path / "reports",
        )

    assert backend.calls == 1
    assert error.value.result.returncode == 0
    assert error.value.report_path == visible_report
    assert error.value.publication_uncertain is True
    assert error.value.report_path.is_file()
    assert isinstance(error.value.cause, BenchmarkReportPublicationError)


def test_report_pins_backend_capability_snapshot_before_execution(tmp_path):
    class MutableCapabilityBackend:
        def __init__(self):
            self.calls = 0
            self._capabilities = capabilities(IsolationLevel.DISPOSABLE_VM)

        @property
        def capabilities(self):
            return self._capabilities

        def execute(self, spec):
            self.calls += 1
            self._capabilities = capabilities(IsolationLevel.CONTAINER)
            return RecordingBackend(
                capabilities(IsolationLevel.DISPOSABLE_VM)
            ).execute(spec)

    backend = MutableCapabilityBackend()

    with pytest.raises(BenchmarkReportPersistenceError) as error:
        execute_benchmark_and_report(
            make_spec(),
            backend=backend,
            **review_kwargs(make_spec(), backend),
            output_dir=tmp_path / "reports",
        )

    assert backend.calls == 1
    assert error.value.result.returncode == 0
    assert "changed during execution" in str(error.value.cause)
    assert not (tmp_path / "reports").exists()


def test_direct_benchmark_execution_preserves_result_if_capabilities_change():
    class MutableCapabilityBackend:
        def __init__(self):
            self.calls = 0
            self._capabilities = capabilities(IsolationLevel.DISPOSABLE_VM)

        @property
        def capabilities(self):
            return self._capabilities

        def execute(self, spec):
            self.calls += 1
            self._capabilities = capabilities(IsolationLevel.CONTAINER)
            return RecordingBackend(
                capabilities(IsolationLevel.DISPOSABLE_VM)
            ).execute(spec)

    backend = MutableCapabilityBackend()
    spec = make_spec()

    with pytest.raises(BackendAttestationError) as error:
        execute_benchmark(
            spec,
            backend=backend,
            **review_kwargs(spec, backend),
        )

    assert backend.calls == 1
    assert error.value.result.returncode == 0
    assert "changed during execution" in str(error.value.cause)
