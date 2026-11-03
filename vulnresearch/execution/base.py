"""Provider-neutral, fail-closed execution backend contracts.

This module defines requirements and validation only. It does not provision VMs,
start containers, execute commands, or provide a fallback execution path.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .security import IndependentReviewVerifier, SecurityReviewApproval


class IsolationLevel(str, Enum):
    """Isolation boundary provided by an execution backend."""

    CONTAINER = "container"
    DISPOSABLE_VM = "disposable_vm"


_ISOLATION_RANK = {
    IsolationLevel.CONTAINER: 1,
    IsolationLevel.DISPOSABLE_VM: 2,
}


class ExecutionStatus(str, Enum):
    """Terminal status reported by a backend."""

    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class ExecutionRequirements:
    """Minimum controls that must be verified before a backend may run a task."""

    minimum_isolation: IsolationLevel = IsolationLevel.CONTAINER
    network_isolated: bool = True
    immutable_guest_image: bool = True
    isolated_storage: bool = True
    bounded_input_output: bool = True
    resource_limits: bool = True
    cleanup_verification: bool = True
    host_docker_socket_isolated: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.minimum_isolation, IsolationLevel):
            raise TypeError("minimum_isolation must be an IsolationLevel")
        for field in (
            "network_isolated",
            "immutable_guest_image",
            "isolated_storage",
            "bounded_input_output",
            "resource_limits",
            "cleanup_verification",
            "host_docker_socket_isolated",
        ):
            if type(getattr(self, field)) is not bool:
                raise TypeError(f"{field} must be a boolean")

    @classmethod
    def for_benchmark(cls) -> ExecutionRequirements:
        """Requirements for hostile benchmark code; a disposable VM is mandatory."""
        return cls(minimum_isolation=IsolationLevel.DISPOSABLE_VM)


@dataclass(frozen=True)
class BackendCapabilities:
    """Backend-declared security claims; these fields are not independent proof.

    A deployment owner must verify each claim against the actual VM/runtime
    configuration and retain review evidence outside this data structure. The
    policy gate can compare declarations with requirements, but cannot inspect
    or authenticate the underlying infrastructure.
    """

    isolation_level: IsolationLevel
    network_isolated: bool
    immutable_guest_image: bool
    isolated_storage: bool
    bounded_input_output: bool
    resource_limits: bool
    cleanup_verification: bool
    host_docker_socket_isolated: bool

    def __post_init__(self) -> None:
        if not isinstance(self.isolation_level, IsolationLevel):
            raise TypeError("isolation_level must be an IsolationLevel")
        for field in (
            "network_isolated",
            "immutable_guest_image",
            "isolated_storage",
            "bounded_input_output",
            "resource_limits",
            "cleanup_verification",
            "host_docker_socket_isolated",
        ):
            if type(getattr(self, field)) is not bool:
                raise TypeError(f"{field} must be a boolean")

    def to_manifest(self) -> dict[str, object]:
        """Return the exact capability claims declared by this backend."""
        return {
            "isolation_level": self.isolation_level.value,
            "network_isolated": self.network_isolated,
            "immutable_guest_image": self.immutable_guest_image,
            "isolated_storage": self.isolated_storage,
            "bounded_input_output": self.bounded_input_output,
            "resource_limits": self.resource_limits,
            "cleanup_verification": self.cleanup_verification,
            "host_docker_socket_isolated": self.host_docker_socket_isolated,
        }

    @classmethod
    def from_manifest(cls, manifest: dict[str, object]) -> BackendCapabilities:
        """Reconstruct capability claims from their strict report representation."""
        expected_fields = {
            "isolation_level",
            "network_isolated",
            "immutable_guest_image",
            "isolated_storage",
            "bounded_input_output",
            "resource_limits",
            "cleanup_verification",
            "host_docker_socket_isolated",
        }
        if not isinstance(manifest, dict) or set(manifest) != expected_fields:
            raise ValueError("backend capability manifest has an unsupported schema")
        try:
            capabilities = cls(
                isolation_level=IsolationLevel(manifest["isolation_level"]),
                network_isolated=manifest["network_isolated"],
                immutable_guest_image=manifest["immutable_guest_image"],
                isolated_storage=manifest["isolated_storage"],
                bounded_input_output=manifest["bounded_input_output"],
                resource_limits=manifest["resource_limits"],
                cleanup_verification=manifest["cleanup_verification"],
                host_docker_socket_isolated=manifest["host_docker_socket_isolated"],
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"backend capability manifest is invalid: {exc}") from exc
        if capabilities.to_manifest() != manifest:
            raise ValueError("backend capability manifest is not canonical")
        return capabilities

    def missing_requirements(
        self, requirements: ExecutionRequirements
    ) -> tuple[str, ...]:
        """Return required controls absent from the backend's declarations."""
        missing: list[str] = []
        if _ISOLATION_RANK[self.isolation_level] < _ISOLATION_RANK[
            requirements.minimum_isolation
        ]:
            missing.append(
                f"isolation_level must be at least {requirements.minimum_isolation.value}"
            )
        for field in (
            "network_isolated",
            "immutable_guest_image",
            "isolated_storage",
            "bounded_input_output",
            "resource_limits",
            "cleanup_verification",
            "host_docker_socket_isolated",
        ):
            if getattr(requirements, field) and not getattr(self, field):
                missing.append(field)
        return tuple(missing)


@dataclass(frozen=True)
class ExecutionLimits:
    """Provider-neutral resource and transfer ceilings for one disposable run."""

    vcpu_count: int
    memory_bytes: int
    disk_bytes: int
    max_processes: int
    max_input_bytes: int
    max_output_bytes_total: int

    def __post_init__(self) -> None:
        bounds = {
            "vcpu_count": (1, 64),
            "memory_bytes": (128 * 1024**2, 64 * 1024**3),
            "disk_bytes": (256 * 1024**2, 1024 * 1024**3),
            "max_processes": (1, 65536),
            "max_input_bytes": (1, 1024 * 1024**2),
            "max_output_bytes_total": (1, 100 * 1024**2),
        }
        for field, (minimum, maximum) in bounds.items():
            value = getattr(self, field)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(
                    f"{field} must be an integer between {minimum} and {maximum}"
                )


@dataclass(frozen=True)
class ExecutionInput:
    """Immutable input artifact reference staged read-only at a guest-relative path."""

    artifact_id: str
    sha256: str
    size_bytes: int
    guest_path: str

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.artifact_id
        ):
            raise ValueError("artifact_id must be a 1-128 character opaque identifier")
        if not isinstance(self.sha256, str) or not re.fullmatch(
            r"[a-f0-9]{64}", self.sha256
        ):
            raise ValueError("sha256 must be a lowercase 64-character SHA-256 digest")
        if type(self.size_bytes) is not int or not 0 <= self.size_bytes <= 1024 * 1024**2:
            raise ValueError("size_bytes must be an integer between 0 and 1 GiB")
        if (
            not isinstance(self.guest_path, str)
            or not self.guest_path
            or self.guest_path.strip() != self.guest_path
            or len(self.guest_path) > 512
            or "\x00" in self.guest_path
            or "\\" in self.guest_path
        ):
            raise ValueError("guest_path must be a relative POSIX file path of at most 512 characters")
        path = PurePosixPath(self.guest_path)
        if (
            path.is_absolute()
            or path.as_posix() != self.guest_path
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("guest_path must be canonical and remain beneath the guest input root")


@dataclass(frozen=True)
class ExecutionOutput:
    """Collected output artifact metadata, relative to the guest output root."""

    artifact_id: str
    sha256: str
    size_bytes: int
    guest_path: str

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.artifact_id
        ):
            raise ValueError("artifact_id must be a 1-128 character opaque identifier")
        if not isinstance(self.sha256, str) or not re.fullmatch(
            r"[a-f0-9]{64}", self.sha256
        ):
            raise ValueError("sha256 must be a lowercase 64-character SHA-256 digest")
        if type(self.size_bytes) is not int or not 0 <= self.size_bytes <= 100 * 1024**2:
            raise ValueError("size_bytes must be an integer between 0 and 100 MiB")
        if (
            not isinstance(self.guest_path, str)
            or not self.guest_path
            or self.guest_path.strip() != self.guest_path
            or len(self.guest_path) > 512
            or "\x00" in self.guest_path
            or "\\" in self.guest_path
        ):
            raise ValueError("guest_path must be a relative POSIX file path of at most 512 characters")
        path = PurePosixPath(self.guest_path)
        if (
            path.is_absolute()
            or path.as_posix() != self.guest_path
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("guest_path must be canonical and remain beneath the guest output root")


@dataclass(frozen=True)
class ExecutionSpec:
    """Validated benchmark request; commands are argv, never shell strings."""

    run_id: str
    task_id: str
    command_id: str
    argv: tuple[str, ...]
    timeout_seconds: int
    requirements: ExecutionRequirements
    limits: ExecutionLimits
    inputs: tuple[ExecutionInput, ...] = ()
    max_output_bytes_per_stream: int = 1024 * 1024

    def __post_init__(self) -> None:
        for name in ("run_id", "task_id", "command_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value) > 128:
                raise ValueError(f"{name} must be a non-empty string of at most 128 characters")
            if "\x00" in value:
                raise ValueError(f"{name} must not contain NUL characters")
        if not isinstance(self.argv, tuple) or not self.argv or len(self.argv) > 64:
            raise ValueError("argv must be a tuple containing between 1 and 64 arguments")
        if any(
            not isinstance(part, str) or not part or "\x00" in part or len(part) > 4096
            for part in self.argv
        ):
            raise ValueError("argv entries must be non-empty strings of at most 4096 characters")
        if sum(map(len, self.argv)) > 16384:
            raise ValueError("argv exceeds the 16384-character aggregate limit")
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be an integer between 1 and 3600")
        if (
            type(self.max_output_bytes_per_stream) is not int
            or not 1 <= self.max_output_bytes_per_stream <= 10 * 1024 * 1024
        ):
            raise ValueError("max_output_bytes_per_stream must be between 1 byte and 10 MiB")
        if not isinstance(self.requirements, ExecutionRequirements):
            raise TypeError("requirements must be an ExecutionRequirements instance")
        if not isinstance(self.limits, ExecutionLimits):
            raise TypeError("limits must be an ExecutionLimits instance")
        if not isinstance(self.inputs, tuple) or any(
            not isinstance(item, ExecutionInput) for item in self.inputs
        ):
            raise TypeError("inputs must be a tuple of ExecutionInput instances")
        if len(self.inputs) > 64:
            raise ValueError("execution input manifest cannot contain more than 64 artifacts")
        artifact_ids = [item.artifact_id for item in self.inputs]
        guest_paths = [item.guest_path for item in self.inputs]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("execution input artifact_id values must be unique")
        if len(guest_paths) != len(set(guest_paths)):
            raise ValueError("execution input guest_path values must be unique")
        sorted_paths = sorted(guest_paths)
        if any(
            following.startswith(current + "/")
            for index, current in enumerate(sorted_paths)
            for following in sorted_paths[index + 1 :]
        ):
            raise ValueError("execution input guest paths must not have file/directory conflicts")
        if sum(item.size_bytes for item in self.inputs) > self.limits.max_input_bytes:
            raise ValueError("execution inputs exceed the configured max_input_bytes limit")
        if self.requirements != ExecutionRequirements.for_benchmark():
            raise ValueError(
                "benchmark execution specs must retain every mandatory VM isolation requirement"
            )


    @classmethod
    def from_manifest(cls, manifest: dict[str, object]) -> ExecutionSpec:
        """Reconstruct and fully validate a versioned JSON execution manifest."""
        expected_fields = {
            "schema_version",
            "run_id",
            "task_id",
            "command_id",
            "argv",
            "timeout_seconds",
            "requirements",
            "limits",
            "inputs",
            "max_output_bytes_per_stream",
        }
        if not isinstance(manifest, dict) or set(manifest) != expected_fields:
            raise ValueError("execution manifest has an unsupported schema")
        if manifest["schema_version"] != "1.0":
            raise ValueError("unsupported execution manifest schema_version")

        requirement_fields = {
            "minimum_isolation",
            "network_isolated",
            "immutable_guest_image",
            "isolated_storage",
            "bounded_input_output",
            "resource_limits",
            "cleanup_verification",
            "host_docker_socket_isolated",
        }
        requirements_data = manifest["requirements"]
        if (
            not isinstance(requirements_data, dict)
            or set(requirements_data) != requirement_fields
        ):
            raise ValueError("execution manifest requirements are invalid")
        requirements = ExecutionRequirements(
            minimum_isolation=IsolationLevel(requirements_data["minimum_isolation"]),
            network_isolated=requirements_data["network_isolated"],
            immutable_guest_image=requirements_data["immutable_guest_image"],
            isolated_storage=requirements_data["isolated_storage"],
            bounded_input_output=requirements_data["bounded_input_output"],
            resource_limits=requirements_data["resource_limits"],
            cleanup_verification=requirements_data["cleanup_verification"],
            host_docker_socket_isolated=requirements_data["host_docker_socket_isolated"],
        )

        limit_fields = {
            "vcpu_count",
            "memory_bytes",
            "disk_bytes",
            "max_processes",
            "max_input_bytes",
            "max_output_bytes_total",
        }
        limits_data = manifest["limits"]
        if not isinstance(limits_data, dict) or set(limits_data) != limit_fields:
            raise ValueError("execution manifest limits are invalid")
        limits = ExecutionLimits(**limits_data)

        inputs_data = manifest["inputs"]
        input_fields = {"artifact_id", "sha256", "size_bytes", "guest_path"}
        if not isinstance(inputs_data, list) or any(
            not isinstance(item, dict) or set(item) != input_fields
            for item in inputs_data
        ):
            raise ValueError("execution manifest inputs are invalid")
        inputs = tuple(ExecutionInput(**item) for item in inputs_data)

        argv = manifest["argv"]
        if not isinstance(argv, list):
            raise TypeError("execution manifest argv must be a list")
        execution_spec = cls(
            run_id=manifest["run_id"],
            task_id=manifest["task_id"],
            command_id=manifest["command_id"],
            argv=tuple(argv),
            timeout_seconds=manifest["timeout_seconds"],
            requirements=requirements,
            limits=limits,
            inputs=inputs,
            max_output_bytes_per_stream=manifest["max_output_bytes_per_stream"],
        )
        if execution_spec.to_manifest() != manifest:
            raise ValueError("execution manifest is not in canonical normalized form")
        return execution_spec

    def to_manifest(self) -> dict[str, object]:
        """Return a fresh, versioned JSON-compatible representation of this run."""
        return {
            "schema_version": "1.0",
            "run_id": self.run_id,
            "task_id": self.task_id,
            "command_id": self.command_id,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "requirements": {
                "minimum_isolation": self.requirements.minimum_isolation.value,
                "network_isolated": self.requirements.network_isolated,
                "immutable_guest_image": self.requirements.immutable_guest_image,
                "isolated_storage": self.requirements.isolated_storage,
                "bounded_input_output": self.requirements.bounded_input_output,
                "resource_limits": self.requirements.resource_limits,
                "cleanup_verification": self.requirements.cleanup_verification,
                "host_docker_socket_isolated": self.requirements.host_docker_socket_isolated,
            },
            "limits": {
                "vcpu_count": self.limits.vcpu_count,
                "memory_bytes": self.limits.memory_bytes,
                "disk_bytes": self.limits.disk_bytes,
                "max_processes": self.limits.max_processes,
                "max_input_bytes": self.limits.max_input_bytes,
                "max_output_bytes_total": self.limits.max_output_bytes_total,
            },
            "inputs": [
                {
                    "artifact_id": item.artifact_id,
                    "sha256": item.sha256,
                    "size_bytes": item.size_bytes,
                    "guest_path": item.guest_path,
                }
                for item in self.inputs
            ],
            "max_output_bytes_per_stream": self.max_output_bytes_per_stream,
        }

    @property
    def manifest_sha256(self) -> str:
        """Return the SHA-256 digest of the canonical versioned execution manifest."""
        canonical = json.dumps(
            self.to_manifest(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return hashlib.sha256(canonical).hexdigest()



@dataclass(frozen=True)
class BackendResult:
    """Bounded result, output artifact manifest, usage metrics, and cleanup status.

    Resource usage and artifact digests are reported by the backend. The policy gate
    checks metadata and byte totals, but cannot independently measure guest usage or
    verify artifact bytes; deployment review must establish that trusted host-side
    collection performs those checks.
    """

    status: ExecutionStatus
    returncode: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    duration_seconds: float
    cleanup_confirmed: bool
    allocated_vcpu_count: int
    peak_memory_bytes: int
    peak_disk_bytes: int
    peak_processes: int
    input_bytes_staged: int
    execution_spec_sha256: str
    outputs: tuple[ExecutionOutput, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.status, ExecutionStatus):
            raise TypeError("status must be an ExecutionStatus")
        if self.returncode is not None and type(self.returncode) is not int:
            raise TypeError("returncode must be an integer or None")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("stdout and stderr must be strings")
        for stream_name, stream_value in (
            ("stdout", self.stdout),
            ("stderr", self.stderr),
        ):
            if len(stream_value.encode("utf-8", errors="surrogateescape")) > 10 * 1024 * 1024:
                raise ValueError(
                    f"{stream_name} exceeds the absolute 10 MiB backend result limit"
                )
        if type(self.stdout_truncated) is not bool or type(self.stderr_truncated) is not bool:
            raise TypeError("truncation flags must be booleans")
        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, (int, float))
            or not math.isfinite(self.duration_seconds)
            or self.duration_seconds < 0
        ):
            raise ValueError("duration_seconds must be a finite non-negative number")
        if self.status in {ExecutionStatus.COMPLETED, ExecutionStatus.FAILED} and self.returncode is None:
            raise ValueError("completed and failed results require a returncode")
        if self.status is ExecutionStatus.COMPLETED and self.returncode != 0:
            raise ValueError("completed results require a zero returncode")
        if self.status is ExecutionStatus.FAILED and self.returncode == 0:
            raise ValueError("failed results require a non-zero returncode")
        if self.status is ExecutionStatus.TIMED_OUT and self.returncode == 0:
            raise ValueError("timed-out results cannot have a zero returncode")
        if self.status is ExecutionStatus.BLOCKED and self.returncode is not None:
            raise ValueError("blocked results cannot have a process returncode")
        if type(self.cleanup_confirmed) is not bool:
            raise TypeError("cleanup_confirmed must be a boolean")
        if not isinstance(self.execution_spec_sha256, str) or not re.fullmatch(
            r"[a-f0-9]{64}", self.execution_spec_sha256
        ):
            raise ValueError("execution_spec_sha256 must be a lowercase 64-character SHA-256 digest")
        for field in (
            "allocated_vcpu_count",
            "peak_memory_bytes",
            "peak_disk_bytes",
            "peak_processes",
            "input_bytes_staged",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field} must be a non-negative integer")
        if (
            self.status in {
                ExecutionStatus.COMPLETED,
                ExecutionStatus.FAILED,
                ExecutionStatus.TIMED_OUT,
            }
            and self.allocated_vcpu_count < 1
        ):
            raise ValueError("allocated_vcpu_count must be at least one for executed results")
        if not isinstance(self.outputs, tuple) or any(
            not isinstance(item, ExecutionOutput) for item in self.outputs
        ):
            raise TypeError("outputs must be a tuple of ExecutionOutput instances")
        if len(self.outputs) > 64:
            raise ValueError("execution output manifest cannot contain more than 64 artifacts")
        output_ids = [item.artifact_id for item in self.outputs]
        output_paths = [item.guest_path for item in self.outputs]
        if len(output_ids) != len(set(output_ids)):
            raise ValueError("execution output artifact_id values must be unique")
        if len(output_paths) != len(set(output_paths)):
            raise ValueError("execution output guest_path values must be unique")
        sorted_output_paths = sorted(output_paths)
        if any(
            following.startswith(current + "/")
            for index, current in enumerate(sorted_output_paths)
            for following in sorted_output_paths[index + 1 :]
        ):
            raise ValueError("execution output guest paths must not have file/directory conflicts")


class ExecutionBackend(Protocol):
    """Interface implemented by concrete, independently reviewed execution backends."""

    @property
    def capabilities(self) -> BackendCapabilities:
        """Return deployment capability claims, independently evidenced by the operator."""
        ...

    def execute(self, spec: ExecutionSpec) -> BackendResult:
        """Stage verified inputs, execute, and collect only bounded output artifacts."""
        ...


class BackendContractError(RuntimeError):
    """Raised when a backend returns a result outside the declared contract."""


class BackendAttestationError(BackendContractError):
    """Execution completed, but the backend's reviewed capability claims changed."""

    def __init__(self, result: BackendResult, cause: Exception) -> None:
        self.result = result
        self.cause = cause
        super().__init__(
            f"Execution completed but backend capability attestation changed: {cause}"
        )


class BackendExecutionError(RuntimeError):
    """Raised when backend execution fails without a verifiable cleanup result.

    The caller must treat the disposable environment as potentially still alive
    and quarantine it through an independently verified operational procedure.
    The policy layer cannot perform provider-specific cleanup itself.
    """

    cleanup_confirmed = False

    def __init__(self, cause: Exception) -> None:
        self.cause = cause
        super().__init__(
            "Execution backend raised before confirming cleanup; treat the run as "
            "unconfirmed and quarantine its environment."
        )


class BackendCapabilityError(RuntimeError):
    """Raised before execution when required isolation controls are unavailable."""

    def __init__(self, missing: tuple[str, ...]) -> None:
        self.missing = missing
        super().__init__("Execution blocked; backend lacks required capabilities: " + ", ".join(missing))


class BackendCleanupError(BackendContractError):
    """Raised when backend cleanup cannot be positively confirmed."""

    def __init__(self, result: BackendResult) -> None:
        self.result = result
        super().__init__(
            "Execution result cannot be accepted because backend cleanup is unconfirmed"
        )


def execute_with_policy(
    backend: ExecutionBackend,
    spec: ExecutionSpec,
    *,
    security_review: SecurityReviewApproval | None = None,
    review_verifier: IndependentReviewVerifier | None = None,
    software_commit_sha: str = "",
) -> BackendResult:
    """Public low-level policy entry point; callers cannot inject guard callbacks."""
    return _execute_with_policy(
        backend,
        spec,
        security_review=security_review,
        review_verifier=review_verifier,
        software_commit_sha=software_commit_sha,
    )


def _execute_with_policy(
    backend: ExecutionBackend,
    spec: ExecutionSpec,
    *,
    security_review: SecurityReviewApproval | None = None,
    review_verifier: IndependentReviewVerifier | None = None,
    software_commit_sha: str = "",
    _before_execute: Callable[[], None] | None = None,
    _after_execute: Callable[[BackendResult], None] | None = None,
) -> BackendResult:
    """Internal runner implementation with trusted, non-backend guard callbacks."""
    from .security import verify_independent_review

    try:
        capabilities = backend.capabilities
    except Exception as exc:
        raise BackendContractError(
            "Backend capability claims are unavailable during preflight"
        ) from exc
    if not isinstance(capabilities, BackendCapabilities):
        raise BackendContractError("Backend must return a BackendCapabilities instance")
    missing = capabilities.missing_requirements(spec.requirements)
    if missing:
        raise BackendCapabilityError(missing)
    verify_independent_review(
        security_review,
        review_verifier,
        spec=spec,
        capabilities=capabilities,
        software_commit_sha=software_commit_sha,
    )
    # The independent verifier is an injected boundary and may take time. Re-read
    # dynamic backend claims after it returns so a capability change during review
    # cannot authorize dispatch using a stale preflight snapshot.
    try:
        current_capabilities = backend.capabilities
    except Exception as exc:
        raise BackendContractError(
            "Backend capability claims became unavailable before execution"
        ) from exc
    if current_capabilities != capabilities:
        raise BackendCapabilityError(
            ("backend capabilities changed after independent review verification",)
        )

    if _before_execute is not None:
        _before_execute()
    try:
        result = backend.execute(spec)
    except Exception as exc:
        raise BackendExecutionError(exc) from exc
    if not isinstance(result, BackendResult):
        raise BackendContractError("Backend must return a BackendResult instance")
    if _after_execute is not None:
        _after_execute(result)
    if result.execution_spec_sha256 != spec.manifest_sha256:
        raise BackendContractError(
            "Backend result execution_spec_sha256 does not match the approved specification"
        )
    if (
        result.status in {ExecutionStatus.COMPLETED, ExecutionStatus.FAILED}
        and result.duration_seconds > spec.timeout_seconds
    ):
        raise BackendContractError(
            "Backend result duration_seconds exceeds the approved execution timeout"
        )
    if len(result.stdout.encode("utf-8", errors="surrogateescape")) > spec.max_output_bytes_per_stream:
        raise BackendContractError("Backend stdout exceeds the configured output limit")
    if len(result.stderr.encode("utf-8", errors="surrogateescape")) > spec.max_output_bytes_per_stream:
        raise BackendContractError("Backend stderr exceeds the configured output limit")
    total_output_bytes = (
        len(result.stdout.encode("utf-8", errors="surrogateescape"))
        + len(result.stderr.encode("utf-8", errors="surrogateescape"))
        + sum(item.size_bytes for item in result.outputs)
    )
    if total_output_bytes > spec.limits.max_output_bytes_total:
        raise BackendContractError("Backend output exceeds the configured aggregate limit")
    # These are backend-reported measurements; deployment review must verify their provenance.
    expected_input_bytes = sum(item.size_bytes for item in spec.inputs)
    if result.input_bytes_staged != expected_input_bytes:
        raise BackendContractError(
            "Backend input_bytes_staged does not match the approved input manifest"
        )
    observed_usage = {
        "allocated_vcpu_count": (result.allocated_vcpu_count, spec.limits.vcpu_count),
        "peak_memory_bytes": (result.peak_memory_bytes, spec.limits.memory_bytes),
        "peak_disk_bytes": (result.peak_disk_bytes, spec.limits.disk_bytes),
        "peak_processes": (result.peak_processes, spec.limits.max_processes),
    }
    for field, (observed, limit) in observed_usage.items():
        if observed > limit:
            raise BackendContractError(
                f"Backend reported {field}={observed}, exceeding configured limit {limit}"
            )
    if not result.cleanup_confirmed:
        raise BackendCleanupError(result)
    try:
        current_capabilities = backend.capabilities
    except Exception as exc:
        raise BackendAttestationError(
            result,
            RuntimeError("backend capability claims became unavailable after execution"),
        ) from exc
    if current_capabilities != capabilities:
        raise BackendAttestationError(
            result,
            RuntimeError("backend capability claims changed during execution"),
        )
    return result
