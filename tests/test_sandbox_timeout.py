import io
import subprocess
from pathlib import Path

import pytest

from vulnresearch import sandbox
from vulnresearch.sandbox import SandboxError
from vulnresearch.task import ResearchTask


class _TimedOutDockerProcess:
    def __init__(self, command):
        self.command = command
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.wait_calls = 0
        self.signals = []

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.wait_calls == 1:
            raise subprocess.TimeoutExpired(self.command, timeout)
        return 0

    def send_signal(self, sig):
        self.signals.append(sig)

    def terminate(self):
        raise AssertionError("the Docker CLI should exit after container cleanup")

    def kill(self):
        raise AssertionError("the Docker CLI should exit after container cleanup")


def _task(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manifest = tmp_path / "task.json"
    manifest.write_text(
        """{
          "schema_version": "1.0",
          "task_id": "timeout-fixture",
          "name": "timeout fixture",
          "description": "harmless local fixture",
          "source": {"kind": "local_fixture", "reference": "fixture"},
          "authorization": {
            "status": "approved",
            "scope": "local_fixture_only",
            "approved_by": "test",
            "approval_reference": "timeout-test"
          },
          "workspace": "workspace",
          "execution_profile": "offline_readonly",
          "commands": [{"argv": ["python", "-c", "pass"], "timeout_seconds": 1}]
        }""",
        encoding="utf-8",
    )
    return ResearchTask.from_file(manifest, workspace_root=tmp_path)


@pytest.mark.parametrize(
    ("cleanup_returncode", "cleanup_stderr", "expected_error"),
    [
        (0, "", None),
        (1, "Error: No such container", None),
        (1, "permission denied", "container cleanup could not be confirmed"),
    ],
)
def test_timeout_attempts_force_container_removal(
    tmp_path, monkeypatch, cleanup_returncode, cleanup_stderr, expected_error
):
    task = _task(tmp_path)
    monkeypatch.setenv(
        "VULNRESEARCH_SANDBOX_IMAGE",
        "python:3.11-slim@sha256:" + "a" * 64,
    )
    original_exists = Path.exists

    def fake_exists(path):
        if path == Path("/var/run/docker.sock"):
            return True
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", fake_exists)
    process = _TimedOutDockerProcess([])
    monkeypatch.setattr(sandbox.subprocess, "Popen", lambda command, **kwargs: (
        setattr(process, "command", command) or process
    ))
    cleanup_calls = []

    def fake_run(command, **kwargs):
        cleanup_calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command, cleanup_returncode, stdout="", stderr=cleanup_stderr
        )

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)

    with pytest.raises(SandboxError) as error:
        sandbox.run_task(task)

    assert "Task exceeded 1s timeout" in str(error.value)
    assert process.signals
    assert len(cleanup_calls) == 1
    cleanup_command, cleanup_kwargs = cleanup_calls[0]
    assert cleanup_command[:3] == ["docker", "rm", "--force"]
    assert cleanup_command[3] == process.command[process.command.index("--name") + 1]
    assert cleanup_kwargs["timeout"] == 5
    if expected_error:
        assert expected_error in str(error.value)
    else:
        assert expected_error is None
