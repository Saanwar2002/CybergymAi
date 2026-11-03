"""Provider-neutral, fail-closed execution backend contracts.

This module defines requirements and validation only. It does not provision VMs,
start containers, execute commands, or provide a fallback execution path.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
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
class ExecutionSpec:
    """Validated benchmark request; commands are argv, never shell strings."""

    run_id: str
    task_id: str
    command_id: str
    argv: tuple[str, ...]
    timeout_seconds: int
    requirements: ExecutionRequirements
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
        if self.requirements != ExecutionRequirements.for_benchmark():
            raise ValueError(
                "benchmark execution specs must retain every mandatory VM isolation requirement"
            )


@dataclass(frozen=True)
class BackendResult:
    """Bounded execution result and explicit cleanup attestation."""

    status: ExecutionStatus
    returncode: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    duration_seconds: float
    cleanup_confirmed: bool

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


class ExecutionBackend(Protocol):
    """Interface implemented by concrete, independently reviewed execution backends."""

    @property
    def capabilities(self) -> BackendCapabilities:
        """Return deployment capability claims, independently evidenced by the operator."""
        ...

    def execute(self, spec: ExecutionSpec) -> BackendResult:
        """Execute one approved specification and report cleanup status."""
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
    if not result.cleanup_confirmed:
        raise BackendCleanupError(result)
    return result
