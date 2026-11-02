"""Local run report and bounded artifact persistence."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .sandbox import SandboxResult
from .task import ResearchTask


def _write_artifact(directory: Path, name: str, content: str, truncated: bool) -> dict[str, object]:
    data = content.encode("utf-8")
    path = directory / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    return {
        "path": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "truncated": truncated,
    }


def write_run_report(
    task: ResearchTask,
    result: SandboxResult,
    output_dir: str | Path = "artifacts/runs",
) -> Path:
    """Persist a JSON run record and bounded stdout/stderr artifacts."""
    run_id = uuid.uuid4().hex
    created_at = datetime.now(UTC)
    started_at = created_at - timedelta(seconds=result.duration_seconds)
    directory = Path(output_dir).resolve() / run_id
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    stdout = _write_artifact(directory, "stdout.txt", result.stdout, result.stdout_truncated)
    stderr = _write_artifact(directory, "stderr.txt", result.stderr, result.stderr_truncated)
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
    report_path = directory / "report.json"
    encoded_report = (json.dumps(record, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(
        report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded_report)
    return report_path
