"""Execution backend contracts; concrete VM providers are intentionally separate."""

from .base import (
    BackendCapabilities,
    BackendCapabilityError,
    BackendCleanupError,
    BackendContractError,
    BackendExecutionError,
    BackendResult,
    ExecutionBackend,
    ExecutionInput,
    ExecutionLimits,
    ExecutionOutput,
    ExecutionRequirements,
    ExecutionSpec,
    ExecutionStatus,
    IsolationLevel,
    execute_with_policy,
)
from .reporting import BenchmarkReportPublicationError
from .runner import (
    BenchmarkBackendUnavailable,
    BenchmarkReportPersistenceError,
    BenchmarkRun,
    execute_benchmark,
    execute_benchmark_and_report,
)

__all__ = [
    "BackendCapabilities",
    "BackendCapabilityError",
    "BackendCleanupError",
    "BackendContractError",
    "BackendExecutionError",
    "BackendResult",
    "BenchmarkBackendUnavailable",
    "BenchmarkReportPublicationError",
    "BenchmarkReportPersistenceError",
    "BenchmarkRun",
    "ExecutionBackend",
    "ExecutionInput",
    "ExecutionLimits",
    "ExecutionOutput",
    "ExecutionRequirements",
    "ExecutionSpec",
    "ExecutionStatus",
    "IsolationLevel",
    "execute_benchmark",
    "execute_benchmark_and_report",
    "execute_with_policy",
]
