"""Single entry point for benchmark execution; never falls back to local containers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .base import (
    BackendResult,
    ExecutionBackend,
    ExecutionRequirements,
    ExecutionSpec,
    execute_with_policy,
)
from .reporting import BenchmarkReportPublicationError, write_benchmark_run_report


@dataclass(frozen=True)
class BenchmarkRun:
    """Validated backend result paired with its atomically published audit report."""

    result: BackendResult
    report_path: Path


class BenchmarkReportPersistenceError(RuntimeError):
    """Raised when execution succeeded but its audit report could not be persisted."""

    def __init__(
        self,
        result: BackendResult,
        cause: Exception,
        *,
        report_path: Path | None = None,
    ) -> None:
        self.result = result
        self.cause = cause
        self.report_path = report_path
        self.publication_uncertain = report_path is not None
        super().__init__(f"Benchmark execution completed but report persistence failed: {cause}")


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
    disposable-VM policy. This checks declarations only; it cannot verify the actual
    VM deployment, authenticate the backend, or substitute for independent review.
    This function is a policy integration seam, not a VM provider.
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


def execute_benchmark_and_report(
    spec: ExecutionSpec,
    *,
    backend: ExecutionBackend | None = None,
    output_dir: str | Path = "artifacts/benchmark-runs",
) -> BenchmarkRun:
    """Execute through the mandatory VM policy and atomically persist the result.

    If report persistence fails after execution, the raised exception retains the
    validated backend result so callers do not lose the execution outcome.
    """
    result = execute_benchmark(spec, backend=backend)
    # The same immutable declaration checked before execution is recorded alongside
    # the result so downstream review can inspect what the backend claimed.
    assert backend is not None
    try:
        report_path = write_benchmark_run_report(
            spec,
            result,
            backend_capabilities=backend.capabilities,
            output_dir=output_dir,
        )
    except Exception as exc:
        # Execution has already happened and cleanup was confirmed. Preserve the
        # validated outcome even for unexpected serializer/filesystem failures.
        # A parent-directory fsync failure occurs after atomic publication; retain
        # the visible path while marking its crash durability as uncertain.
        report_path = (
            exc.report_path
            if isinstance(exc, BenchmarkReportPublicationError)
            else None
        )
        raise BenchmarkReportPersistenceError(
            result, exc, report_path=report_path
        ) from exc
    return BenchmarkRun(result=result, report_path=report_path)
