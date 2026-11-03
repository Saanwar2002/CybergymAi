"""Single entry point for benchmark execution; never falls back to local containers."""
from __future__ import annotations

from .base import (
    BackendResult,
    ExecutionBackend,
    ExecutionRequirements,
    ExecutionSpec,
    execute_with_policy,
)


class BenchmarkBackendUnavailable(RuntimeError):
    """Raised when no explicitly supplied benchmark-capable backend is available."""


def execute_benchmark(
    spec: ExecutionSpec,
    *,
    backend: ExecutionBackend | None = None,
) -> BackendResult:
    """Execute a benchmark specification through an explicitly injected safe backend.

    There is deliberately no default backend, Docker fallback, or provider discovery.
    The caller must supply a backend whose declared capabilities satisfy the complete
    disposable-VM policy. This function is a policy integration seam, not a VM provider.
    """
    if not isinstance(spec, ExecutionSpec):
        raise TypeError("spec must be an ExecutionSpec instance")
    if spec.requirements != ExecutionRequirements.for_benchmark():
        raise ValueError("benchmark execution requires the complete mandatory VM policy")
    if backend is None:
        raise BenchmarkBackendUnavailable(
            "Benchmark execution is disabled: no disposable-VM backend is configured."
        )
    return execute_with_policy(backend, spec)
