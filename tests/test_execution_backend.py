from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

from vulnresearch.execution import (
    BackendAttestationError,
    BackendCapabilities,
    BackendCapabilityError,
    BackendCleanupError,
    BackendContractError,
    BackendExecutionError,
    BackendResult,
    ExecutionInput,
    ExecutionLimits,
    ExecutionOutput,
    ExecutionRequirements,
    ExecutionSpec,
    ExecutionStatus,
    IsolationLevel,
    SecurityReviewApproval,
    SecurityReviewError,
    backend_capabilities_sha256,
    execute_with_policy,
)


@dataclass
class FakeBackend:
    capabilities: BackendCapabilities
    result: BackendResult
    calls: int = 0

    def execute(self, spec: ExecutionSpec) -> BackendResult:
        self.calls += 1
        return replace(self.result, execution_spec_sha256=spec.manifest_sha256)


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
    status: ExecutionStatus = ExecutionStatus.COMPLETED,
    returncode: int | None = 0,
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
        status=status,
        returncode=returncode,
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
        execution_spec_sha256="0" * 64,
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


class AllowTestReview:
    def verify(self, _approval):
        return True


def run_policy(backend, execution_spec):
    now = datetime.now(UTC)
    approval = SecurityReviewApproval(
        review_id="backend-test-review",
        reviewer_id="independent-reviewer",
        reviewer_organization="External Security Review Group",
        scope="benchmark_execution",
        reviewed_commit_sha="a" * 40,
        execution_spec_sha256=execution_spec.manifest_sha256,
        backend_capabilities_sha256=backend_capabilities_sha256(
            backend.capabilities
        ),
        evidence_sha256="e" * 64,
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(days=1),
        signature="test-only-signature",
    )
    return execute_with_policy(
        backend,
        execution_spec,
        security_review=approval,
        review_verifier=AllowTestReview(),
        software_commit_sha="a" * 40,
    )


def test_benchmark_requirements_accept_only_capable_disposable_vm_backend():
    backend = FakeBackend(vm_capabilities(), result())

    actual = run_policy(backend, spec())

    assert actual.returncode == 0
    assert actual.cleanup_confirmed
    assert backend.calls == 1


def test_benchmark_requirements_block_container_backend_before_execution():
    capabilities = vm_capabilities(isolation_level=IsolationLevel.CONTAINER)
    backend = FakeBackend(capabilities, result())

    with pytest.raises(BackendCapabilityError, match="disposable_vm"):
        run_policy(backend, spec())

    assert backend.calls == 0


def test_benchmark_requirements_block_missing_network_isolation():
    backend = FakeBackend(vm_capabilities(network_isolated=False), result())

    with pytest.raises(BackendCapabilityError, match="network_isolated"):
        run_policy(backend, spec())

    assert backend.calls == 0


def test_unconfirmed_cleanup_rejects_backend_result():
    backend = FakeBackend(vm_capabilities(), result(cleanup_confirmed=False))

    with pytest.raises(BackendCleanupError, match="cleanup is unconfirmed"):
        run_policy(backend, spec())


def test_backend_output_must_respect_per_stream_limit():
    backend = FakeBackend(vm_capabilities(), result(stdout="x" * 5))

    with pytest.raises(BackendContractError, match="stdout exceeds"):
        run_policy(backend, spec(output_limit=4))


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
        run_policy(backend, spec())

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
            execution_spec_sha256="0" * 64,
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
            execution_spec_sha256="0" * 64,
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
        run_policy(backend, spec())

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
            execution_spec_sha256="0" * 64,
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
            execution_spec_sha256="0" * 64,
        ),
    )

    with pytest.raises(BackendContractError, match="aggregate limit"):
        run_policy(backend, spec(output_limit=10, total_output_limit=7))


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
        run_policy(backend, spec())



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
        run_policy(backend, spec(inputs=(approved,)))


def test_backend_accepts_exact_approved_input_bytes_staged():
    approved = input_artifact(size_bytes=16)
    backend = FakeBackend(vm_capabilities(), result(input_bytes_staged=16))

    actual = run_policy(backend, spec(inputs=(approved,)))

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
        run_policy(backend, spec(output_limit=10, total_output_limit=7))


def test_backend_accepts_output_artifacts_within_aggregate_limit():
    output = output_artifact(size_bytes=4)
    backend = FakeBackend(vm_capabilities(), result(outputs=(output,)))

    actual = run_policy(backend, spec(total_output_limit=10))

    assert actual.outputs == (output,)


def test_execution_spec_digest_is_stable_and_binds_all_execution_fields():
    original = spec()
    same = spec()
    changed = spec(output_limit=output_limit_for_test())

    assert original.manifest_sha256 == same.manifest_sha256
    assert original.manifest_sha256 != changed.manifest_sha256
    assert len(original.manifest_sha256) == 64


def test_backend_result_must_match_exact_execution_spec_digest():
    class WrongDigestBackend(FakeBackend):
        def execute(self, execution_spec: ExecutionSpec) -> BackendResult:
            self.calls += 1
            return replace(
                self.result,
                execution_spec_sha256="f" * 64,
            )

    backend = WrongDigestBackend(vm_capabilities(), result())

    with pytest.raises(BackendContractError, match="does not match the approved specification"):
        run_policy(backend, spec())

    assert backend.calls == 1


def output_limit_for_test() -> int:
    return 2048


@pytest.mark.parametrize(
    "stream_value",
    [
        "x" * (10 * 1024 * 1024 + 1),
        "é" * (5 * 1024 * 1024 + 1),
    ],
)
def test_backend_result_rejects_streams_over_absolute_utf8_byte_limit(stream_value: str):
    with pytest.raises(ValueError, match="absolute 10 MiB backend result limit"):
        result(stdout=stream_value)


def test_execution_spec_manifest_is_versioned_complete_and_detached():
    execution_spec = spec(
        inputs=(input_artifact(artifact_id="source-1", size_bytes=8),)
    )

    manifest = execution_spec.to_manifest()
    assert manifest["schema_version"] == "1.0"
    assert manifest["argv"] == list(execution_spec.argv)
    assert manifest["requirements"]["minimum_isolation"] == "disposable_vm"
    assert manifest["limits"]["max_input_bytes"] == execution_spec.limits.max_input_bytes
    assert manifest["inputs"] == [
        {
            "artifact_id": "source-1",
            "sha256": "a" * 64,
            "size_bytes": 8,
            "guest_path": "src/fixture.bin",
        }
    ]

    manifest["argv"].append("mutated")
    manifest["inputs"][0]["guest_path"] = "../outside"

    fresh_manifest = execution_spec.to_manifest()
    assert fresh_manifest["argv"] == list(execution_spec.argv)
    assert fresh_manifest["inputs"][0]["guest_path"] == "src/fixture.bin"


def test_execution_spec_manifest_round_trip_revalidates_mandatory_vm_policy():
    original = spec(inputs=(input_artifact(),))

    restored = ExecutionSpec.from_manifest(original.to_manifest())

    assert restored == original
    assert restored.manifest_sha256 == original.manifest_sha256

    downgraded = original.to_manifest()
    downgraded["requirements"]["minimum_isolation"] = "container"
    with pytest.raises(ValueError, match="every mandatory VM isolation requirement"):
        ExecutionSpec.from_manifest(downgraded)


@pytest.mark.parametrize(
    ("status", "returncode", "message"),
    [
        (
            ExecutionStatus.TIMED_OUT,
            0,
            "timed-out results cannot have a zero returncode",
        ),
        (
            ExecutionStatus.BLOCKED,
            0,
            "blocked results cannot have a process returncode",
        ),
        (
            ExecutionStatus.BLOCKED,
            1,
            "blocked results cannot have a process returncode",
        ),
    ],
)
def test_backend_result_rejects_inconsistent_terminal_status(
    status: ExecutionStatus, returncode: int, message: str
):
    with pytest.raises(ValueError, match=message):
        result(status=status, returncode=returncode)


def test_backend_result_accepts_blocked_status_without_process_returncode():
    blocked = result(status=ExecutionStatus.BLOCKED, returncode=None)

    assert blocked.status is ExecutionStatus.BLOCKED
    assert blocked.returncode is None


def test_backend_result_accepts_timeout_without_process_returncode():
    timed_out = result(status=ExecutionStatus.TIMED_OUT, returncode=None)

    assert timed_out.status is ExecutionStatus.TIMED_OUT
    assert timed_out.returncode is None


def test_backend_exception_is_reported_as_unconfirmed_cleanup():
    class RaisingBackend(FakeBackend):
        def execute(self, execution_spec: ExecutionSpec) -> BackendResult:
            self.calls += 1
            raise OSError("provider connection dropped")

    backend = RaisingBackend(vm_capabilities(), result())

    with pytest.raises(BackendExecutionError, match="treat the run as unconfirmed") as error:
        run_policy(backend, spec())

    assert backend.calls == 1
    assert error.value.cleanup_confirmed is False
    assert isinstance(error.value.cause, OSError)
    assert str(error.value.cause) == "provider connection dropped"


@pytest.mark.parametrize(
    "backend_error",
    [
        BackendContractError("backend supplied an invalid result"),
        BackendCapabilityError(("backend claims container-only isolation",)),
    ],
)
def test_backend_policy_exception_is_still_unconfirmed_execution_failure(
    backend_error,
):
    class RaisingPolicyErrorBackend(FakeBackend):
        def execute(self, execution_spec):
            self.calls += 1
            raise backend_error

    backend = RaisingPolicyErrorBackend(vm_capabilities(), result())

    with pytest.raises(
        BackendExecutionError, match="treat the run as unconfirmed"
    ) as error:
        run_policy(backend, spec())

    assert backend.calls == 1
    assert error.value.cleanup_confirmed is False
    assert error.value.cause is backend_error


def test_backend_completed_result_must_respect_approved_timeout():
    backend = FakeBackend(
        vm_capabilities(),
        replace(result(), duration_seconds=spec().timeout_seconds + 0.01),
    )

    with pytest.raises(BackendContractError, match="exceeds the approved execution timeout"):
        run_policy(backend, spec())

    assert backend.calls == 1


def test_backend_timed_out_result_may_include_bounded_cleanup_overhead():
    backend = FakeBackend(
        vm_capabilities(),
        replace(
            result(
                status=ExecutionStatus.TIMED_OUT,
                returncode=None,
            ),
            duration_seconds=spec().timeout_seconds + 5,
        ),
    )

    actual = run_policy(backend, spec())

    assert actual.status is ExecutionStatus.TIMED_OUT


def test_backend_capability_manifest_round_trip_is_strict():
    original = vm_capabilities()

    restored = BackendCapabilities.from_manifest(original.to_manifest())

    assert restored == original
    downgraded = original.to_manifest()
    downgraded["network_isolated"] = 1
    with pytest.raises(ValueError, match="must be a boolean"):
        BackendCapabilities.from_manifest(downgraded)


def test_backend_private_guard_lookalikes_are_not_trusted_policy_hooks():
    class BackendWithPrivateLookalikes(FakeBackend):
        def _check_dispatch_capabilities(self):
            raise AssertionError("backend-supplied dispatch hook must not be called")

        def _check_post_execution_capabilities(self, _result):
            raise AssertionError("backend-supplied completion hook must not be called")

    backend = BackendWithPrivateLookalikes(vm_capabilities(), result())

    actual = run_policy(backend, spec())

    assert actual.returncode == 0
    assert backend.calls == 1


def test_unavailable_backend_capabilities_fail_closed_during_preflight():
    class UnavailableCapabilitiesBackend:
        calls = 0

        @property
        def capabilities(self):
            raise RuntimeError("provider capability endpoint unavailable")

        def execute(self, _spec):
            self.calls += 1
            return result()

    backend = UnavailableCapabilitiesBackend()

    with pytest.raises(
        BackendContractError, match="unavailable during preflight"
    ):
        execute_with_policy(backend, spec())

    assert backend.calls == 0


def test_low_level_execution_policy_cannot_bypass_independent_review():
    backend = FakeBackend(vm_capabilities(), result())

    with pytest.raises(SecurityReviewError, match="independent security-review approval"):
        execute_with_policy(backend, spec())

    assert backend.calls == 0


def test_low_level_policy_rechecks_capabilities_after_review_verification():
    backend = FakeBackend(vm_capabilities(), result())
    execution_spec = spec()
    now = datetime.now(UTC)
    approval = SecurityReviewApproval(
        review_id="review-time-capability-change",
        reviewer_id="independent-reviewer",
        reviewer_organization="External Security Review Group",
        scope="benchmark_execution",
        reviewed_commit_sha="a" * 40,
        execution_spec_sha256=execution_spec.manifest_sha256,
        backend_capabilities_sha256=backend_capabilities_sha256(
            backend.capabilities
        ),
        evidence_sha256="e" * 64,
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(days=1),
        signature="test-only-signature",
    )

    class MutatingVerifier:
        def verify(self, _approval):
            backend.capabilities = vm_capabilities(
                isolation_level=IsolationLevel.CONTAINER
            )
            return True

    with pytest.raises(
        BackendCapabilityError, match="changed after independent review"
    ):
        execute_with_policy(
            backend,
            execution_spec,
            security_review=approval,
            review_verifier=MutatingVerifier(),
            software_commit_sha="a" * 40,
        )

    assert backend.calls == 0


def test_low_level_policy_preserves_result_when_capability_claims_change():
    class MutableBackend:
        def __init__(self):
            self.capabilities = vm_capabilities()
            self.calls = 0

        def execute(self, execution_spec):
            self.calls += 1
            self.capabilities = vm_capabilities(
                isolation_level=IsolationLevel.CONTAINER
            )
            return replace(
                result(),
                execution_spec_sha256=execution_spec.manifest_sha256,
            )

    backend = MutableBackend()
    execution_spec = spec()
    now = datetime.now(UTC)
    approval = SecurityReviewApproval(
        review_id="mutable-backend-review",
        reviewer_id="independent-reviewer",
        reviewer_organization="External Security Review Group",
        scope="benchmark_execution",
        reviewed_commit_sha="a" * 40,
        execution_spec_sha256=execution_spec.manifest_sha256,
        backend_capabilities_sha256=backend_capabilities_sha256(
            backend.capabilities
        ),
        evidence_sha256="e" * 64,
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(days=1),
        signature="test-only-signature",
    )

    with pytest.raises(BackendAttestationError) as error:
        execute_with_policy(
            backend,
            execution_spec,
            security_review=approval,
            review_verifier=AllowTestReview(),
            software_commit_sha="a" * 40,
        )

    assert backend.calls == 1
    assert error.value.result.returncode == 0


@pytest.mark.parametrize("hook_name", ["_before_execute", "_after_execute"])
def test_low_level_policy_api_rejects_caller_supplied_execution_hooks(hook_name):
    execution_spec = spec()
    backend = FakeBackend(vm_capabilities(), result())
    now = datetime.now(UTC)
    approval = SecurityReviewApproval(
        review_id="hook-injection-review",
        reviewer_id="independent-reviewer",
        reviewer_organization="External Security Review Group",
        scope="benchmark_execution",
        reviewed_commit_sha="a" * 40,
        execution_spec_sha256=execution_spec.manifest_sha256,
        backend_capabilities_sha256=backend_capabilities_sha256(
            backend.capabilities
        ),
        evidence_sha256="e" * 64,
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(days=1),
        signature="test-only-signature",
    )

    def weaken_capabilities():
        backend.capabilities = vm_capabilities(network_isolated=False)

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        execute_with_policy(
            backend,
            execution_spec,
            security_review=approval,
            review_verifier=AllowTestReview(),
            software_commit_sha="a" * 40,
            **{hook_name: weaken_capabilities},
        )

    assert backend.calls == 0
    assert backend.capabilities == vm_capabilities()


def test_policy_preserves_exact_non_utf8_and_nul_output_bytes():
    stdout_bytes = b"stdout\\xff\\x00tail"
    stderr_bytes = b"stderr\\x80\\x00tail"
    backend = FakeBackend(
        vm_capabilities(),
        replace(
            result(
                stdout=stdout_bytes.decode("utf-8", errors="surrogateescape")
            ),
            stderr=stderr_bytes.decode("utf-8", errors="surrogateescape"),
        ),
    )

    actual = run_policy(backend, spec())

    assert actual.stdout.encode("utf-8", errors="surrogateescape") == stdout_bytes
    assert actual.stderr.encode("utf-8", errors="surrogateescape") == stderr_bytes
