"""Fail-closed Docker execution for approved local fixtures."""
from __future__ import annotations

import math
import os
import re
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .policy.scope import authorize_task
from .task import ResearchTask


class SandboxError(RuntimeError):
    """Raised when a safe sandbox cannot be prepared or completed."""


@dataclass(frozen=True)
class SandboxResult:
    """Execution result with bounded, reversibly decoded output."""

    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    duration_seconds: float

    def __post_init__(self) -> None:
        if type(self.returncode) is not int:
            raise TypeError("returncode must be an integer")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("stdout and stderr must be strings")
        if type(self.stdout_truncated) is not bool or type(self.stderr_truncated) is not bool:
            raise TypeError("output truncation flags must be booleans")
        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, (int, float))
            or not math.isfinite(self.duration_seconds)
            or self.duration_seconds < 0
        ):
            raise ValueError("duration_seconds must be a finite non-negative number")


_IMAGE_PATTERN = re.compile(r"python:3\.11-slim@sha256:[0-9a-f]{64}\Z")
_MAX_OUTPUT_BYTES = 1024 * 1024
_READER_JOIN_TIMEOUT_SECONDS = 5


def _read_bounded(stream: BinaryIO, limit: int) -> tuple[bytes, bool]:
    """Drain a pipe fully while retaining at most limit bytes."""
    output = bytearray()
    truncated = False
    while chunk := stream.read(8192):
        remaining = limit - len(output)
        if remaining > 0:
            output.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True
    return bytes(output), truncated


def _capture_stream(
    captured: dict[str, tuple[bytes, bool]],
    errors: dict[str, Exception],
    name: str,
    stream: BinaryIO,
) -> None:
    """Drain one output pipe and retain any reader failure for the caller."""
    try:
        captured[name] = _read_bounded(stream, _MAX_OUTPUT_BYTES)
    except (OSError, ValueError) as exc:
        errors[name] = exc


def build_docker_command(
    task: ResearchTask,
    *,
    image: str,
    workspace: str | Path | None = None,
    container_name: str | None = None,
) -> list[str]:
    """Build a restrictive Docker command without executing it."""
    decision = authorize_task(task)
    if not decision.allowed:
        raise SandboxError(f"Task blocked by policy: {decision.reason}")
    if not _IMAGE_PATTERN.fullmatch(image):
        raise SandboxError(
            "Sandbox image must be an approved python:3.11-slim image pinned by sha256 digest."
        )
    if container_name is not None and not re.fullmatch(
        r"vulnresearch-[0-9a-f]{32}", container_name
    ):
        raise SandboxError("Container name must use the generated vulnresearch UUID format.")
    try:
        authorized_workspace = Path(task.workspace).resolve(strict=True)
        resolved_workspace = (
            Path(workspace).resolve(strict=True) if workspace is not None
            else authorized_workspace
        )
    except (OSError, RuntimeError) as exc:
        raise SandboxError("Approved workspace cannot be resolved safely.") from exc
    if resolved_workspace != authorized_workspace:
        raise SandboxError(
            "Workspace override must exactly match the task's approved workspace."
        )
    if not resolved_workspace.is_dir():
        raise SandboxError(
            f"Workspace does not exist or is not a directory: {resolved_workspace}"
        )
    return [
        "docker",
        "run",
        "--rm",
        *(["--name", container_name] if container_name is not None else []),
        "--pull",
        "never",
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
        "--memory-swap",
        "512m",
        "--cpus",
        "1",
        "--ulimit",
        "nofile=1024:1024",
        "--ulimit",
        "fsize=10485760:10485760",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=65534,gid=65534",
        "-v",
        f"{resolved_workspace}:/workspace:ro",
        "-w",
        "/workspace",
        image,
        *task.command,
    ]



def _is_explicit_container_not_found(stderr: str, container_name: str) -> bool:
    """Accept only an exact Docker not-found response for this container."""
    message = stderr.strip()
    return message in {
        f"Error: No such object: {container_name}",
        f"Error: No such object: /{container_name}",
        f"Error: No such container: {container_name}",
        f"Error: No such container: /{container_name}",
        f"Error response from daemon: No such container: {container_name}",
        f"Error response from daemon: No such container: /{container_name}",
    }


def _force_remove_container(container_name: str) -> str | None:
    """Stop and remove a timed-out container; return an error if cleanup is uncertain."""
    try:
        result = subprocess.run(
            ["docker", "rm", "--force", container_name],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)
    if result.returncode == 0 or _is_explicit_container_not_found(result.stderr, container_name):
        return None
    return result.stderr.strip() or f"docker rm exited with status {result.returncode}"


def _confirm_container_removed(container_name: str) -> str | None:
    """Confirm normal-exit cleanup; force-remove a container if it still exists."""
    inspect_command = [
        "docker",
        "inspect",
        "--type",
        "container",
        container_name,
    ]
    try:
        inspected = subprocess.run(
            inspect_command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)

    if inspected.returncode != 0:
        if _is_explicit_container_not_found(inspected.stderr, container_name):
            return None
        return inspected.stderr.strip() or (
            f"docker inspect exited with status {inspected.returncode}"
        )

    cleanup_error = _force_remove_container(container_name)
    if cleanup_error:
        return cleanup_error
    try:
        verified = subprocess.run(
            inspect_command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)
    if verified.returncode != 0 and (
        "No such object" in verified.stderr or "No such container" in verified.stderr
    ):
        return None
    if verified.returncode == 0:
        return "container still exists after forced removal"
    return verified.stderr.strip() or (
        f"docker inspect exited with status {verified.returncode}"
    )


def _join_output_readers(readers: list[threading.Thread]) -> bool:
    """Wait a bounded total time for both output-draining threads to finish."""
    deadline = time.monotonic() + _READER_JOIN_TIMEOUT_SECONDS
    for reader in readers:
        if reader.ident is not None:
            reader.join(timeout=max(0, deadline - time.monotonic()))
    return all(not reader.is_alive() for reader in readers)


def _stop_docker_cli(
    process: subprocess.Popen[bytes],
    *,
    initial_signal: int | None = None,
    initial_wait_seconds: int = 0,
) -> str | None:
    """Stop and reap the Docker CLI before container cleanup is verified."""
    if initial_signal is not None:
        try:
            process.send_signal(initial_signal)
        except ProcessLookupError:
            pass
        except OSError:
            pass
        try:
            process.wait(timeout=initial_wait_seconds)
        except (OSError, subprocess.TimeoutExpired):
            pass
        else:
            return None

    try:
        process.terminate()
    except ProcessLookupError:
        pass
    except OSError:
        pass
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass
    else:
        return None

    try:
        process.kill()
    except ProcessLookupError:
        pass
    except OSError as exc:
        kill_error = str(exc)
    else:
        kill_error = None
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired) as exc:
        detail = f"Docker CLI did not exit within the bounded wait after kill: {exc}"
        if kill_error:
            detail = f"Docker CLI kill failed: {kill_error}; {detail}"
        return detail
    return None


def _cleanup_unexpected_run(
    process: subprocess.Popen[bytes],
    container_name: str,
    readers: list[threading.Thread],
) -> str | None:
    """Stop the Docker CLI, then confirm container removal after an unexpected exit."""
    errors: list[str] = []
    # Stop and reap the CLI before inspecting/removing the container. If cleanup
    # runs first, a still-running CLI can create the container afterward.
    cli_shutdown_error = _stop_docker_cli(process)
    if cli_shutdown_error:
        errors.append(f"Docker CLI shutdown: {cli_shutdown_error}")

    cleanup_error = _confirm_container_removed(container_name)
    if cleanup_error:
        errors.append(f"container cleanup: {cleanup_error}")

    if not _join_output_readers(readers):
        errors.append("sandbox output reader did not stop")

    return "; ".join(errors) or None


def run_task(task: ResearchTask) -> SandboxResult:
    """Run one approved command and retain bounded output from the container."""
    image = os.getenv("VULNRESEARCH_SANDBOX_IMAGE", "")
    container_name = f"vulnresearch-{uuid.uuid4().hex}"
    command = build_docker_command(task, image=image, container_name=container_name)
    if not Path("/var/run/docker.sock").exists():
        raise SandboxError("Docker socket not found; install/start Docker before execution.")

    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdout is None or process.stderr is None:
            cleanup_error = _cleanup_unexpected_run(process, container_name, [])
            message = "Could not capture sandbox output."
            if cleanup_error:
                message += f" Container cleanup could not be confirmed: {cleanup_error}"
            raise SandboxError(message)
        captured: dict[str, tuple[bytes, bool]] = {}
        reader_errors: dict[str, Exception] = {}
        readers = [
            threading.Thread(
                target=_capture_stream,
                args=(captured, reader_errors, "stdout", process.stdout),
                daemon=True,
            ),
            threading.Thread(
                target=_capture_stream,
                args=(captured, reader_errors, "stderr", process.stderr),
                daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()
        try:
            returncode = process.wait(timeout=task.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            # Ask Docker to stop the workload, then stop/reap the CLI before
            # verifying container removal so it cannot create a late container.
            cli_shutdown_error = _stop_docker_cli(
                process,
                initial_signal=signal.SIGINT,
                initial_wait_seconds=5,
            )
            # The CLI is now stopped or shutdown has failed closed; only then
            # force-remove and verify the container.
            cleanup_error = _confirm_container_removed(container_name)
            readers_stopped = _join_output_readers(readers)
            timeout_message = f"Task exceeded {task.timeout_seconds}s timeout"
            if cli_shutdown_error:
                timeout_message += f"; {cli_shutdown_error}"
            if not readers_stopped:
                timeout_message += "; output capture readers did not stop"
            if reader_errors:
                details = "; ".join(
                    f"{name}: {error}" for name, error in reader_errors.items()
                )
                timeout_message += f"; output capture failed: {details}"
            if cleanup_error:
                timeout_message += f"; container cleanup could not be confirmed: {cleanup_error}"
            raise SandboxError(timeout_message) from exc
        readers_stopped = _join_output_readers(readers)
        cleanup_error = _confirm_container_removed(container_name)
        if not readers_stopped:
            raise SandboxError(
                "Sandbox output readers did not stop within the bounded wait after execution."
            )
        if cleanup_error:
            raise SandboxError(
                "Container cleanup could not be confirmed after execution: "
                f"{cleanup_error}"
            )
        if reader_errors:
            details = "; ".join(
                f"{name}: {error}" for name, error in reader_errors.items()
            )
            first_error = next(iter(reader_errors.values()))
            raise SandboxError(f"Sandbox output capture failed: {details}") from first_error
        if set(captured) != {"stdout", "stderr"}:
            raise SandboxError("Sandbox output capture failed before both streams were read.")
        stdout, stdout_truncated = captured["stdout"]
        stderr, stderr_truncated = captured["stderr"]
        return SandboxResult(
            returncode=returncode,
            # surrogateescape preserves arbitrary process bytes through the
            # string-based result model; the report writer reverses this encoding.
            stdout=stdout.decode("utf-8", errors="surrogateescape"),
            stderr=stderr.decode("utf-8", errors="surrogateescape"),
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            duration_seconds=time.monotonic() - started,
        )
    except FileNotFoundError as exc:
        if "process" in locals():
            cleanup_error = _cleanup_unexpected_run(
                process, container_name, locals().get("readers", [])
            )
            if cleanup_error:
                raise SandboxError(
                    "Sandbox run failed and cleanup could not be confirmed: "
                    f"{cleanup_error}"
                ) from exc
        raise SandboxError("Docker CLI is not installed or unavailable on PATH.") from exc
    except SandboxError:
        raise
    except BaseException as exc:
        if "process" not in locals():
            raise
        cleanup_error = _cleanup_unexpected_run(
            process, container_name, locals().get("readers", [])
        )
        if cleanup_error:
            raise SandboxError(
                "Sandbox run was interrupted and cleanup could not be confirmed: "
                f"{cleanup_error}"
            ) from exc
        raise
