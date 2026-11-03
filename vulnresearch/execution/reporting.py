"""Atomic, bounded audit reports for provider-neutral benchmark executions."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path

from .._filesystem import fsync_directory
from .base import BackendResult, ExecutionSpec

_MAX_EVIDENCE_STREAM_BYTES = 5 * 1024 * 1024


class BenchmarkReportPublicationError(OSError):
    """Report is visible, but its directory entry durability could not be confirmed."""

    def __init__(self, report_path: Path, cause: OSError) -> None:
        self.report_path = report_path
        self.cause = cause
        super().__init__(
            f"Benchmark report was published at {report_path}, but parent-directory "
            f"durability is uncertain: {cause}"
        )


def _write_bytes(directory: Path, name: str, content: bytes) -> None:
    descriptor = os.open(
        directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _stream_artifact(
    directory: Path, name: str, content: str, already_truncated: bool
) -> dict[str, object]:
    encoded = content.encode("utf-8", errors="surrogateescape")
    bounded = encoded[:_MAX_EVIDENCE_STREAM_BYTES]
    truncated = already_truncated or len(encoded) > len(bounded)
    filename = f"{name}.txt"
    _write_bytes(directory, filename, bounded)
    return {
        "path": filename,
        "sha256": hashlib.sha256(bounded).hexdigest(),
        "size_bytes": len(bounded),
        "truncated": truncated,
    }


def write_benchmark_run_report(
    spec: ExecutionSpec,
    result: BackendResult,
    output_dir: str | Path = "artifacts/benchmark-runs",
) -> Path:
    """Atomically persist the approved manifest and bounded backend result metadata.

    The stdout/stderr evidence files are capped at 5 MiB each to fit the existing
    evidence-bundle artifact limit. Truncation is reflected in their metadata.
    Output artifact payloads remain in the backend's trusted collection layer;
    this report records their digest/size/path metadata only.
    """
    if not isinstance(spec, ExecutionSpec):
        raise TypeError("spec must be an ExecutionSpec instance")
    if not isinstance(result, BackendResult):
        raise TypeError("result must be a BackendResult instance")
    if result.execution_spec_sha256 != spec.manifest_sha256:
        raise ValueError("backend result does not match the approved execution specification")
    if not result.cleanup_confirmed:
        raise ValueError("cannot publish a benchmark report with unconfirmed cleanup")
    if result.input_bytes_staged != sum(item.size_bytes for item in spec.inputs):
        raise ValueError("backend result input byte count does not match the approved manifest")
    observed_usage = {
        "allocated_vcpu_count": (result.allocated_vcpu_count, spec.limits.vcpu_count),
        "peak_memory_bytes": (result.peak_memory_bytes, spec.limits.memory_bytes),
        "peak_disk_bytes": (result.peak_disk_bytes, spec.limits.disk_bytes),
        "peak_processes": (result.peak_processes, spec.limits.max_processes),
    }
    for field, (observed, limit) in observed_usage.items():
        if observed > limit:
            raise ValueError(
                f"backend result {field} exceeds the approved execution limit"
            )

    stdout_bytes = result.stdout.encode("utf-8", errors="surrogateescape")
    stderr_bytes = result.stderr.encode("utf-8", errors="surrogateescape")
    if (
        len(stdout_bytes) > spec.max_output_bytes_per_stream
        or len(stderr_bytes) > spec.max_output_bytes_per_stream
    ):
        raise ValueError("backend result exceeds the approved per-stream output limit")
    total_output_bytes = (
        len(stdout_bytes)
        + len(stderr_bytes)
        + sum(item.size_bytes for item in result.outputs)
    )
    if total_output_bytes > spec.limits.max_output_bytes_total:
        raise ValueError("backend result exceeds the approved aggregate output limit")

    parent = Path(output_dir).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    run_directory = parent / uuid.uuid4().hex

    with tempfile.TemporaryDirectory(prefix=".benchmark-", dir=parent) as staging:
        staging_directory = Path(staging)
        stdout = _stream_artifact(
            staging_directory, "stdout", result.stdout, result.stdout_truncated
        )
        stderr = _stream_artifact(
            staging_directory, "stderr", result.stderr, result.stderr_truncated
        )
        report = {
            "schema_version": "1.0",
            "run_id": spec.run_id,
            "task_id": spec.task_id,
            "execution_spec_sha256": spec.manifest_sha256,
            "execution_spec": spec.to_manifest(),
            "status": (
                "succeeded"
                if result.status.value == "completed"
                else "failed"
            ),
            "backend_status": result.status.value,
            "exit_code": result.returncode,
            "duration_seconds": result.duration_seconds,
            "cleanup_confirmed": result.cleanup_confirmed,
            "resource_usage": {
                "allocated_vcpu_count": result.allocated_vcpu_count,
                "peak_memory_bytes": result.peak_memory_bytes,
                "peak_disk_bytes": result.peak_disk_bytes,
                "peak_processes": result.peak_processes,
                "input_bytes_staged": result.input_bytes_staged,
            },
            "artifacts": {"stdout": stdout, "stderr": stderr},
            "output_artifacts": [
                {
                    "artifact_id": item.artifact_id,
                    "sha256": item.sha256,
                    "size_bytes": item.size_bytes,
                    "guest_path": item.guest_path,
                }
                for item in result.outputs
            ],
        }
        encoded_report = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        _write_bytes(staging_directory, "report.json", encoded_report)
        # Persist all staged directory entries before making the run visible.
        fsync_directory(staging_directory)
        os.rename(staging_directory, run_directory)
        # Persist the atomic publication itself before reporting success. If this
        # fails, the report is already visible but its crash durability is uncertain.
        try:
            fsync_directory(parent)
        except OSError as exc:
            raise BenchmarkReportPublicationError(
                run_directory / "report.json", exc
            ) from exc

    return run_directory / "report.json"
