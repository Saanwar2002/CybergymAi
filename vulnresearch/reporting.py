"""Local run report and bounded artifact persistence."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ._filesystem import fsync_directory
from .sandbox import SandboxResult
from .task import ResearchTask

MAX_REPORT_STREAM_BYTES = 1024 * 1024


class RunReportPublicationError(OSError):
    """Local run report is visible, but parent-directory durability is uncertain."""

    def __init__(self, report_path: Path, cause: OSError) -> None:
        self.report_path = report_path
        self.cause = cause
        super().__init__(
            f"Run report was published at {report_path}, but parent-directory "
            f"durability is uncertain: {cause}"
        )


def _write_artifact(directory: Path, name: str, content: str, truncated: bool) -> dict[str, object]:
    encoded = content.encode("utf-8", errors="surrogateescape")
    data = encoded[:MAX_REPORT_STREAM_BYTES]
    was_truncated = truncated or len(encoded) > len(data)
    path = directory / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return {
        "path": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "truncated": was_truncated,
    }


def write_run_report(
    task: ResearchTask,
    result: SandboxResult,
    output_dir: str | Path = "artifacts/runs",
) -> Path:
    """Atomically publish a JSON run record and bounded stdout/stderr artifacts.

    All files are assembled in a private staging directory. The final run
    directory becomes visible only after every artifact and the report have
    been written successfully.
    """
    run_id = uuid.uuid4().hex
    created_at = datetime.now(UTC)
    started_at = created_at - timedelta(seconds=result.duration_seconds)
    parent = Path(output_dir).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    directory = parent / run_id

    with tempfile.TemporaryDirectory(prefix=f".{run_id}.", dir=parent) as staging:
        staging_directory = Path(staging)
        stdout = _write_artifact(
            staging_directory, "stdout.txt", result.stdout, result.stdout_truncated
        )
        stderr = _write_artifact(
            staging_directory, "stderr.txt", result.stderr, result.stderr_truncated
        )
        record = {
            "schema_version": "1.0",
            "run_id": run_id,
            "task_id": task.task_id,
            "task_name": task.name,
            "status": "succeeded" if result.returncode == 0 else "failed",
            "execution_profile": task.execution_profile,
            "started_at": started_at.isoformat(),
            "completed_at": created_at.isoformat(),
            "duration_seconds": round(result.duration_seconds, 6),
            "exit_code": result.returncode,
            "artifacts": {"stdout": stdout, "stderr": stderr},
        }
        report_path = staging_directory / "report.json"
        encoded_report = (json.dumps(record, indent=2) + "\n").encode("utf-8")
        descriptor = os.open(
            report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded_report)
            stream.flush()
            os.fsync(stream.fileno())

        # Persist staged entries before the same-filesystem atomic rename.
        fsync_directory(staging_directory)
        os.rename(staging_directory, directory)
        # Persist the published run-directory entry before reporting success. If
        # this fails, the complete report is visible but crash durability is uncertain.
        try:
            fsync_directory(parent)
        except OSError as exc:
            raise RunReportPublicationError(
                directory / "report.json", exc
            ) from exc

    return directory / "report.json"
