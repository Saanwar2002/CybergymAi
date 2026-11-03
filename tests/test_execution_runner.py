from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from vulnresearch.execution import (
    BackendCapabilities,
    BackendCapabilityError,
    BackendResult,
    BenchmarkBackendUnavailable,
    BenchmarkReportPersistenceError,
    ExecutionLimits,
    ExecutionRequirements,
    ExecutionSpec,
    ExecutionStatus,
    IsolationLevel,
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


def test_benchmark_entrypoint_fails_closed_without_injected_backend():
    with pytest.raises(BenchmarkBackendUnavailable, match="no disposable-VM backend"):
        execute_benchmark(make_spec())


def test_benchmark_entrypoint_never_falls_back_to_container_backend():
    backend = RecordingBackend(capabilities(IsolationLevel.CONTAINER))

    with pytest.raises(BackendCapabilityError, match="disposable_vm"):
        execute_benchmark(make_spec(), backend=backend)

    assert backend.calls == 0


def test_benchmark_entrypoint_uses_explicit_capable_backend():
    backend = RecordingBackend(capabilities(IsolationLevel.DISPOSABLE_VM))

    result = execute_benchmark(make_spec(), backend=backend)

    assert result.returncode == 0
    assert backend.calls == 1


def test_benchmark_execute_and_report_persists_result_and_manifest(tmp_path):
    backend = RecordingBackend(capabilities(IsolationLevel.DISPOSABLE_VM))

    run = execute_benchmark_and_report(
        make_spec(),
        backend=backend,
        output_dir=tmp_path / "reports",
    )
    report = json.loads(run.report_path.read_text(encoding="utf-8"))

    assert backend.calls == 1
    assert run.result.returncode == 0
    assert run.report_path.is_file()
    assert report["execution_spec_sha256"] == make_spec().manifest_sha256
    assert report["execution_spec"] == make_spec().to_manifest()


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
            output_dir=tmp_path / "reports",
        )

    assert backend.calls == 1
    assert error.value.result.returncode == 0
    assert isinstance(error.value.cause, OSError)
