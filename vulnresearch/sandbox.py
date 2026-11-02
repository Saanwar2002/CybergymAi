"""Opt-in Docker execution with conservative isolation defaults."""
from __future__ import annotations

import subprocess
from pathlib import Path

from .task import ResearchTask


class SandboxError(RuntimeError):
    pass


def run_task(task: ResearchTask) -> subprocess.CompletedProcess[str]:
    workspace = Path(task.workspace).resolve()
    if not workspace.is_dir():
        raise SandboxError(f"Workspace does not exist or is not a directory: {workspace}")
    if not Path("/var/run/docker.sock").exists():
        raise SandboxError("Docker socket not found; install/start Docker before execution.")
    command = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--memory", "1g", "--cpus", "1",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "-v", f"{workspace}:/workspace:ro", "-w", "/workspace",
        "python:3.11-slim", *task.command,
    ]
    try:
        return subprocess.run(command, capture_output=True, text=True,
                              timeout=task.timeout_seconds, check=False)
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(f"Task exceeded {task.timeout_seconds}s timeout") from exc
    except FileNotFoundError as exc:
        raise SandboxError("Docker CLI is not installed or unavailable on PATH.") from exc
