from __future__ import annotations

from dataclasses import dataclass

import pytest

from vulnresearch.execution import (
    BackendCapabilities,
    BackendCapabilityError,
    BackendCleanupError,
    BackendContractError,
    BackendResult,
    ExecutionLimits,
    ExecutionRequirements,
    ExecutionSpec,
    ExecutionStatus,
    IsolationLevel,
    execute_with_policy,
)


@dataclass
class FakeBackend:
    capabilities: BackendCapabilities
    result: BackendResult
    calls: int = 0

    def execute(self, spec: ExecutionSpec) -> BackendResult:
        self.calls += 1
        return self.result


def vm_capabilities(**overrides: bool) -> BackendCapabilities:
    values = {
        "isolation_level": IsolationLevel.DISPOSABLE_VM,
        "network_isolated": True,
        "immutable_guest_image": True,
        "isolated_storage": True,
        "bounded_input_output": True,
        "resource_limits": True,
        "cleanup_verification": True,
        "host_docker_socket_isolated": True,
    }
    values.update(overrides)
    return BackendCapabilities(**values)


def limits(**overrides: int) -> ExecutionLimits:
    values = {
        "vcpu_count": 1,
        "memory_bytes": 1024 * 1024**2,
        "disk_bytes": 5 * 1024**3,
        "max_processes": 256,
        "max_input_bytes": 64 * 1024**2,
        "max_output_bytes_total": 2 * 1024**2,
    }
    values.update(overrides)
    return ExecutionLimits(**values)


def result(*, cleanup_confirmed: bool = True, stdout: str = "ok") -> BackendResult:
    return BackendResult(
        status=ExecutionStatus.COMPLETED,
        returncode=0,
        stdout=stdout,
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.25,
        cleanup_confirmed=cleanup_confirmed,
    )


def spec(
    *,
    requirements: ExecutionRequirements | None = None,
    output_limit: int = 1024,
    total_output_limit: int = 2 * 1024**2,
):
    return ExecutionSpec(
        run_id="run-001",
        task_id="fixture-001",
        command_id="smoke-test",
        argv=("python", "-c", "print('safe')"),
        timeout_seconds=30,
        requirements=requirements or ExecutionRequirements.for_benchmark(),
        limits=limits(max_output_bytes_total=total_output_limit),
        max_output_bytes_per_stream=output_limit,
    )


def test_benchmark_requirements_accept_only_capable_disposable_vm_backend():
    backend = FakeBackend(vm_capabilities(), result())

    actual = execute_with_policy(backend, spec())

    assert actual.returncode == 0
    assert actual.cleanup_confirmed
    assert backend.calls == 1


def test_benchmark_requirements_block_container_backend_before_execution():
    capabilities = vm_capabilities(isolation_level=IsolationLevel.CONTAINER)
    backend = FakeBackend(capabilities, result())

    with pytest.raises(BackendCapabilityError, match="disposable_vm"):
        execute_with_policy(backend, spec())

    assert backend.calls == 0


def test_benchmark_requirements_block_missing_network_isolation():
    backend = FakeBackend(vm_capabilities(network_isolated=False), result())

    with pytest.raises(BackendCapabilityError, match="network_isolated"):
        execute_with_policy(backend, spec())

    assert backend.calls == 0


def test_unconfirmed_cleanup_rejects_backend_result():
    backend = FakeBackend(vm_capabilities(), result(cleanup_confirmed=False))

    with pytest.raises(BackendCleanupError, match="cleanup is unconfirmed"):
        execute_with_policy(backend, spec())


def test_backend_output_must_respect_per_stream_limit():
    backend = FakeBackend(vm_capabilities(), result(stdout="x" * 5))

    with pytest.raises(BackendContractError, match="stdout exceeds"):
        execute_with_policy(backend, spec(output_limit=4))


def test_execution_spec_rejects_shell_string_and_invalid_arguments():
    with pytest.raises(ValueError, match="argv must be a tuple"):
        ExecutionSpec(
            run_id="run-001",
            task_id="fixture-001",
            command_id="smoke-test",
            argv="python -c 'print(1)'",
            timeout_seconds=30,
            requirements=ExecutionRequirements.for_benchmark(),
            limits=limits(),
        )


def test_execution_spec_rejects_invalid_timeout_and_output_limits():
    with pytest.raises(ValueError, match="timeout_seconds"):
        ExecutionSpec(
            run_id="run-001",
            task_id="fixture-001",
            command_id="smoke-test",
            argv=("python",),
            timeout_seconds=0,
            requirements=ExecutionRequirements.for_benchmark(),
            limits=limits(),
        )
    with pytest.raises(ValueError, match="max_output_bytes"):
        ExecutionSpec(
            run_id="run-001",
            task_id="fixture-001",
            command_id="smoke-test",
            argv=("python",),
            timeout_seconds=30,
            requirements=ExecutionRequirements.for_benchmark(),
            limits=limits(),
            max_output_bytes_per_stream=20 * 1024 * 1024,
        )


def test_backend_cannot_claim_capabilities_with_non_boolean_values():
    with pytest.raises(TypeError, match="network_isolated must be a boolean"):
        vm_capabilities(network_isolated=1)


def test_backend_cleanup_capability_is_required_before_execution():
    backend = FakeBackend(vm_capabilities(cleanup_verification=False), result())

    with pytest.raises(BackendCapabilityError, match="cleanup_verification"):
        execute_with_policy(backend, spec())

    assert backend.calls == 0


def test_backend_result_rejects_success_without_exit_code():
    with pytest.raises(ValueError, match="require a returncode"):
        BackendResult(
            status=ExecutionStatus.COMPLETED,
            returncode=None,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            duration_seconds=0.1,
            cleanup_confirmed=True,
        )


def test_backend_result_rejects_non_finite_duration():
    with pytest.raises(ValueError, match="finite non-negative"):
        BackendResult(
            status=ExecutionStatus.COMPLETED,
            returncode=0,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            duration_seconds=float("nan"),
            cleanup_confirmed=True,
        )


def test_execution_spec_cannot_downgrade_benchmark_isolation_requirements():
    with pytest.raises(ValueError, match="every mandatory VM isolation requirement"):
        ExecutionSpec(
            run_id="run-001",
            task_id="fixture-001",
            command_id="smoke-test",
            argv=("python",),
            timeout_seconds=30,
            requirements=ExecutionRequirements(
                minimum_isolation=IsolationLevel.CONTAINER,
            ),
            limits=limits(),
        )



@pytest.mark.parametrize(
    "missing_capability",
    [
        "immutable_guest_image",
        "isolated_storage",
        "bounded_input_output",
        "resource_limits",
        "host_docker_socket_isolated",
    ],
)
def test_each_remaining_vm_security_capability_is_required_before_execution(
    missing_capability: str,
):
    backend = FakeBackend(
        vm_capabilities(**{missing_capability: False}),
        result(),
    )

    with pytest.raises(BackendCapabilityError) as error:
        execute_with_policy(backend, spec())

    assert error.value.missing == (missing_capability,)
    assert backend.calls == 0


@pytest.mark.parametrize(
    ("status", "returncode"),
    [
        (ExecutionStatus.COMPLETED, 1),
        (ExecutionStatus.FAILED, 0),
    ],
)
def test_backend_result_rejects_status_exit_code_mismatch(
    status: ExecutionStatus,
    returncode: int,
):
    with pytest.raises(ValueError, match="completed results require a zero|failed results require a non-zero"):
        BackendResult(
            status=status,
            returncode=returncode,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            duration_seconds=0.1,
            cleanup_confirmed=True,
        )

@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("vcpu_count", 0),
        ("memory_bytes", 1),
        ("disk_bytes", 1),
        ("max_processes", 0),
        ("max_input_bytes", 0),
        ("max_output_bytes_total", 0),
        ("vcpu_count", 65),
        ("memory_bytes", 65 * 1024**3),
        ("disk_bytes", 1025 * 1024**3),
        ("max_processes", 65537),
        ("max_input_bytes", 1024 * 1024**2 + 1),
        ("max_output_bytes_total", 100 * 1024**2 + 1),
    ],
)
def test_execution_limits_reject_unbounded_or_invalid_values(field: str, value: int):
    with pytest.raises(ValueError, match=field):
        limits(**{field: value})


def test_backend_output_must_respect_aggregate_limit():
    backend = FakeBackend(
        vm_capabilities(),
        BackendResult(
            status=ExecutionStatus.COMPLETED,
            returncode=0,
            stdout="x" * 4,
            stderr="y" * 4,
            stdout_truncated=False,
            stderr_truncated=False,
            duration_seconds=0.1,
            cleanup_confirmed=True,
        ),
    )

    with pytest.raises(BackendContractError, match="aggregate limit"):
        execute_with_policy(backend, spec(output_limit=10, total_output_limit=7))
