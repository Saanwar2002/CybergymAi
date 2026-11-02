"""Fail-closed Docker execution for approved local fixtures."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from .policy.scope import authorize_task
from .task import ResearchTask


class SandboxError(RuntimeError):
    """Raised when a safe sandbox cannot be prepared or completed."""


_IMAGE_PATTERN = re.compile(r"python:3\.11-slim@sha256:[0-9a-f]{64}\Z")


def build_docker_command(
    task: ResearchTask, *, image: str, workspace: str | Path | None = None
) -> list[str]:
    """Build a restrictive Docker command without executing it."""
    decision = authorize_task(task)
    if not decision.allowed:
        raise SandboxError(f"Task blocked by policy: {decision.reason}")
    if not _IMAGE_PATTERN.fullmatch(image):
        raise SandboxError(
            "Sandbox image must be an approved python:3.11-slim image pinned by sha256 digest."
        )
    resolved_workspace = Path(workspace or task.workspace).resolve()
    if not resolved_workspace.is_dir():
        raise SandboxError(
            f"Workspace does not exist or is not a directory: {resolved_workspace}"
        )
    return [
        "docker",
        "run",
        "--rm",
        "--init",
        "--network",
        "none",
        "--ipc",
        "private",
        "--read-only",
        "--user",
        "65534:65534",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "64",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "--ulimit",
        "nofile=1024:1024",
        "--ulimit",
        "fsize=10485760:10485760",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "-v",
        f"{resolved_workspace}:/workspace:ro",
        "-w",
        "/workspace",
        image,
        *task.command,
    ]


def run_task(task: ResearchTask) -> subprocess.CompletedProcess[str]:
    """Run one approved command in an offline, non-root, read-only container."""
    image = os.getenv("VULNRESEARCH_SANDBOX_IMAGE", "")
    command = build_docker_command(task, image=image)
    if not Path("/var/run/docker.sock").exists():
        raise SandboxError("Docker socket not found; install/start Docker before execution.")
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=task.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(f"Task exceeded {task.timeout_seconds}s timeout") from exc
    except FileNotFoundError as exc:
        raise SandboxError("Docker CLI is not installed or unavailable on PATH.") from exc
