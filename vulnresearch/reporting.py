"""Local run report and bounded artifact persistence."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .sandbox import SandboxResult
from .task import ResearchTask

_MAX_REPORT_STREAM_BYTES = 1024 * 1024


def _write_artifact(directory: Path, name: str, content: str, truncated: bool) -> dict[str, object]:
    encoded = content.encode("utf-8", errors="surrogateescape")
    data = encoded[:_MAX_REPORT_STREAM_BYTES]
    was_truncated = truncated or len(encoded) > len(data)
    path = directory / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
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

        # The staging directory is a sibling of the destination, so rename is
        # atomic on the same filesystem. os.rename also refuses to replace an
        # existing non-empty run directory.
        os.rename(staging_directory, directory)

    return directory / "report.json"
