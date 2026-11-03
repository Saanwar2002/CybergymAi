from __future__ import annotations

from dataclasses import dataclass

import pytest

from vulnresearch.execution import (
    BackendCapabilities,
    BackendCapabilityError,
    BackendResult,
    BenchmarkBackendUnavailable,
    ExecutionRequirements,
    ExecutionSpec,
    ExecutionStatus,
    IsolationLevel,
    execute_benchmark,
)


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
        )


def make_spec() -> ExecutionSpec:
    return ExecutionSpec(
        run_id="run-1",
        task_id="task-1",
        command_id="command-1",
        argv=("python", "-c", "print('fixture')"),
        timeout_seconds=30,
        requirements=ExecutionRequirements.for_benchmark(),
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
    with pytest.raises(BenchmarkBackendUnavailable, match="no reviewed disposable-VM backend"):
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
