from __future__ import annotations

from dataclasses import dataclass

import pytest

from vulnresearch.execution import (
    BackendCapabilities,
    BackendCapabilityError,
    BackendCleanupError,
    BackendContractError,
    BackendResult,
    ExecutionInput,
    ExecutionOutput,
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


def result(
    *,
    cleanup_confirmed: bool = True,
    stdout: str = "ok",
    allocated_vcpu_count: int = 1,
    peak_memory_bytes: int = 512 * 1024**2,
    peak_disk_bytes: int = 1024**3,
    peak_processes: int = 32,
    input_bytes_staged: int = 0,
    outputs: tuple[ExecutionOutput, ...] = (),
) -> BackendResult:
    return BackendResult(
        status=ExecutionStatus.COMPLETED,
        returncode=0,
        stdout=stdout,
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.25,
        cleanup_confirmed=cleanup_confirmed,
        allocated_vcpu_count=allocated_vcpu_count,
        peak_memory_bytes=peak_memory_bytes,
        peak_disk_bytes=peak_disk_bytes,
        peak_processes=peak_processes,
        input_bytes_staged=input_bytes_staged,
        outputs=outputs,
    )


def spec(
    *,
    requirements: ExecutionRequirements | None = None,
    output_limit: int = 1024,
    total_output_limit: int = 2 * 1024**2,
    input_limit: int = 64 * 1024**2,
    inputs: tuple[ExecutionInput, ...] = (),
):
    return ExecutionSpec(
        run_id="run-001",
        task_id="fixture-001",
        command_id="smoke-test",
        argv=("python", "-c", "print('safe')"),
        timeout_seconds=30,
        requirements=requirements or ExecutionRequirements.for_benchmark(),
        limits=limits(max_output_bytes_total=total_output_limit, max_input_bytes=input_limit),
        inputs=inputs,
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
            allocated_vcpu_count=1,
            peak_memory_bytes=1,
            peak_disk_bytes=1,
            peak_processes=1,
            input_bytes_staged=1,
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
            allocated_vcpu_count=1,
            peak_memory_bytes=1,
            peak_disk_bytes=1,
            peak_processes=1,
            input_bytes_staged=1,
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
            allocated_vcpu_count=1,
            peak_memory_bytes=1,
            peak_disk_bytes=1,
            peak_processes=1,
            input_bytes_staged=1,
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
            allocated_vcpu_count=1,
            peak_memory_bytes=1,
            peak_disk_bytes=1,
            peak_processes=1,
            input_bytes_staged=1,
        ),
    )

    with pytest.raises(BackendContractError, match="aggregate limit"):
        execute_with_policy(backend, spec(output_limit=10, total_output_limit=7))


@pytest.mark.parametrize(
    ("usage_field", "usage_value"),
    [
        ("allocated_vcpu_count", 2),
        ("peak_memory_bytes", 1024 * 1024**2 + 1),
        ("peak_disk_bytes", 5 * 1024**3 + 1),
        ("peak_processes", 257),
    ],
)
def test_backend_reported_resource_usage_must_stay_within_limits(
    usage_field: str,
    usage_value: int,
):
    backend = FakeBackend(
        vm_capabilities(),
        result(**{usage_field: usage_value}),
    )

    with pytest.raises(BackendContractError, match=usage_field):
        execute_with_policy(backend, spec())



@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("allocated_vcpu_count", 0),
        ("peak_memory_bytes", -1),
        ("peak_disk_bytes", -1),
        ("peak_processes", -1),
        ("input_bytes_staged", -1),
        ("peak_memory_bytes", True),
    ],
)
def test_backend_result_rejects_invalid_resource_usage_metrics(field: str, value: int):
    with pytest.raises(ValueError, match=field):
        result(**{field: value})


def input_artifact(
    *,
    artifact_id: str = "input-1",
    sha256: str = "a" * 64,
    size_bytes: int = 16,
    guest_path: str = "src/fixture.bin",
) -> ExecutionInput:
    return ExecutionInput(
        artifact_id=artifact_id,
        sha256=sha256,
        size_bytes=size_bytes,
        guest_path=guest_path,
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("sha256", "not-a-digest", "sha256"),
        ("guest_path", "/etc/passwd", "guest_path"),
        ("guest_path", "../outside", "guest_path"),
        ("guest_path", "src/../outside", "guest_path"),
        ("guest_path", "src\\\\outside", "guest_path"),
        ("guest_path", "src/\x00bad", "guest_path"),
    ],
)
def test_execution_input_rejects_invalid_digest_and_guest_paths(
    field: str, value: str, message: str
):
    values = {
        "artifact_id": "input-1",
        "sha256": "a" * 64,
        "size_bytes": 16,
        "guest_path": "src/fixture.bin",
    }
    values[field] = value
    with pytest.raises(ValueError, match=message):
        ExecutionInput(**values)


def test_execution_spec_rejects_duplicate_input_ids_and_guest_paths():
    first = input_artifact()
    with pytest.raises(ValueError, match="artifact_id values must be unique"):
        spec(inputs=(first, input_artifact(guest_path="src/other.bin")))
    with pytest.raises(ValueError, match="guest_path values must be unique"):
        spec(inputs=(first, input_artifact(artifact_id="input-2")))
    with pytest.raises(ValueError, match="file/directory conflicts"):
        spec(
            inputs=(
                input_artifact(guest_path="src"),
                input_artifact(artifact_id="input-2", guest_path="src/nested.bin"),
            )
        )


def test_execution_spec_rejects_input_manifest_over_limit():
    with pytest.raises(ValueError, match="max_input_bytes"):
        spec(inputs=(input_artifact(size_bytes=6),), input_limit=5)
    with pytest.raises(ValueError, match="more than 64 artifacts"):
        spec(inputs=tuple(input_artifact(artifact_id=f"input-{i}") for i in range(65)))


def test_backend_must_report_exact_approved_input_bytes_staged():
    approved = input_artifact(size_bytes=16)
    backend = FakeBackend(vm_capabilities(), result(input_bytes_staged=15))

    with pytest.raises(BackendContractError, match="does not match the approved input manifest"):
        execute_with_policy(backend, spec(inputs=(approved,)))


def test_backend_accepts_exact_approved_input_bytes_staged():
    approved = input_artifact(size_bytes=16)
    backend = FakeBackend(vm_capabilities(), result(input_bytes_staged=16))

    actual = execute_with_policy(backend, spec(inputs=(approved,)))

    assert actual.input_bytes_staged == 16


def output_artifact(
    *,
    artifact_id: str = "output-1",
    sha256: str = "b" * 64,
    size_bytes: int = 4,
    guest_path: str = "results/report.json",
) -> ExecutionOutput:
    return ExecutionOutput(
        artifact_id=artifact_id,
        sha256=sha256,
        size_bytes=size_bytes,
        guest_path=guest_path,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sha256", "invalid"),
        ("guest_path", "/etc/passwd"),
        ("guest_path", "../escape"),
        ("guest_path", "result\\\\file.txt"),
    ],
)
def test_execution_output_rejects_invalid_digest_and_guest_path(field: str, value: str):
    values = {
        "artifact_id": "output-1",
        "sha256": "b" * 64,
        "size_bytes": 4,
        "guest_path": "results/report.json",
    }
    values[field] = value
    with pytest.raises(ValueError):
        ExecutionOutput(**values)


def test_backend_result_rejects_duplicate_or_conflicting_output_paths():
    first = output_artifact()
    with pytest.raises(ValueError, match="artifact_id values must be unique"):
        result(outputs=(first, output_artifact(guest_path="results/other.json")))
    with pytest.raises(ValueError, match="guest_path values must be unique"):
        result(outputs=(first, output_artifact(artifact_id="output-2")))
    with pytest.raises(ValueError, match="file/directory conflicts"):
        result(
            outputs=(
                output_artifact(guest_path="results"),
                output_artifact(artifact_id="output-2", guest_path="results/nested.json"),
            )
        )
    with pytest.raises(ValueError, match="more than 64 artifacts"):
        result(outputs=tuple(output_artifact(artifact_id=f"output-{i}") for i in range(65)))


def test_backend_output_artifacts_count_toward_aggregate_output_limit():
    backend = FakeBackend(
        vm_capabilities(),
        result(outputs=(output_artifact(size_bytes=6),)),
    )

    with pytest.raises(BackendContractError, match="aggregate limit"):
        execute_with_policy(backend, spec(output_limit=10, total_output_limit=7))


def test_backend_accepts_output_artifacts_within_aggregate_limit():
    output = output_artifact(size_bytes=4)
    backend = FakeBackend(vm_capabilities(), result(outputs=(output,)))

    actual = execute_with_policy(backend, spec(total_output_limit=10))

    assert actual.outputs == (output,)
