"""Provider-neutral, fail-closed execution backend contracts.

This module defines requirements and validation only. It does not provision VMs,
start containers, execute commands, or provide a fallback execution path.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Protocol


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
    outputs: tuple[ExecutionOutput, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.status, ExecutionStatus):
            raise TypeError("status must be an ExecutionStatus")
        if self.returncode is not None and type(self.returncode) is not int:
            raise TypeError("returncode must be an integer or None")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("stdout and stderr must be strings")
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
        if type(self.cleanup_confirmed) is not bool:
            raise TypeError("cleanup_confirmed must be a boolean")
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
    backend: ExecutionBackend, spec: ExecutionSpec
) -> BackendResult:
    """Verify backend capabilities, execute once, and reject unsafe results."""
    capabilities = backend.capabilities
    if not isinstance(capabilities, BackendCapabilities):
        raise BackendContractError("Backend must return a BackendCapabilities instance")
    missing = capabilities.missing_requirements(spec.requirements)
    if missing:
        raise BackendCapabilityError(missing)

    result = backend.execute(spec)
    if not isinstance(result, BackendResult):
        raise BackendContractError("Backend must return a BackendResult instance")
    if len(result.stdout.encode("utf-8")) > spec.max_output_bytes_per_stream:
        raise BackendContractError("Backend stdout exceeds the configured output limit")
    if len(result.stderr.encode("utf-8")) > spec.max_output_bytes_per_stream:
        raise BackendContractError("Backend stderr exceeds the configured output limit")
    total_output_bytes = (
        len(result.stdout.encode("utf-8"))
        + len(result.stderr.encode("utf-8"))
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
    return result
