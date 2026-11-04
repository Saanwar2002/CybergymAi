import io
import subprocess
import threading
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
        (1, "not_found", None),
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
        if command[1] == "inspect":
            assert process.wait_calls >= 2
            if len(cleanup_calls) == 1:
                return subprocess.CompletedProcess(
                    command, 0, stdout="container-id", stderr=""
                )
            return subprocess.CompletedProcess(
                command,
                1,
                stdout="",
                stderr=f"Error: No such container: {command[-1]}",
            )
        stderr = (
            f"Error: No such container: {command[-1]}"
            if cleanup_stderr == "not_found"
            else cleanup_stderr
        )
        return subprocess.CompletedProcess(
            command, cleanup_returncode, stdout="", stderr=stderr
        )

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)

    with pytest.raises(SandboxError) as error:
        sandbox.run_task(task)

    assert "Task exceeded 1s timeout" in str(error.value)
    assert process.signals
    expected_calls = 2 if expected_error else 3
    assert len(cleanup_calls) == expected_calls
    cleanup_command, cleanup_kwargs = cleanup_calls[1]
    assert cleanup_command[:3] == ["docker", "rm", "--force"]
    assert cleanup_command[3] == process.command[process.command.index("--name") + 1]
    assert cleanup_kwargs["timeout"] == 5
    assert cleanup_calls[0][0][1] == "inspect"
    if not expected_error:
        assert cleanup_calls[2][0][1] == "inspect"
    if expected_error:
        assert expected_error in str(error.value)
    else:
        assert expected_error is None


@pytest.mark.parametrize(
    "failure",
    [KeyboardInterrupt(), RuntimeError("unexpected Docker wait failure")],
    ids=["keyboard-interrupt", "unexpected-wait-error"],
)
def test_unexpected_sandbox_exit_verifies_container_removal_and_stops_cli(
    tmp_path, monkeypatch, failure
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

    class InterruptingDockerProcess:
        def __init__(self):
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.wait_calls = 0
            self.terminated = False
            self.events = []

        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise failure
            return 0

        def terminate(self):
            self.terminated = True
            self.events.append("terminate")

        def kill(self):
            raise AssertionError("the Docker CLI should stop after terminate")

    process = InterruptingDockerProcess()
    commands = []

    def fake_popen(command, **kwargs):
        commands.append(command)
        return process

    monkeypatch.setattr(sandbox.subprocess, "Popen", fake_popen)
    cleanup_calls = []

    def confirm_removed(name):
        process.events.append("cleanup")
        cleanup_calls.append(name)

    monkeypatch.setattr(sandbox, "_confirm_container_removed", confirm_removed)

    with pytest.raises(type(failure)) as error:
        sandbox.run_task(task)

    assert str(error.value) == str(failure)
    assert process.terminated
    assert process.wait_calls == 2
    assert process.events == ["terminate", "cleanup"]
    assert len(cleanup_calls) == 1
    assert cleanup_calls[0] == commands[0][commands[0].index("--name") + 1]


@pytest.mark.parametrize(
    "stderr",
    [
        "Error: permission denied; No such container: vulnresearch-" + "a" * 32,
        "Error: No such container: vulnresearch-" + "a" * 32 + "; daemon unavailable",
    ],
)
def test_container_cleanup_does_not_accept_not_found_substrings_as_proof(
    monkeypatch, stderr
):
    container_name = "vulnresearch-" + "a" * 32

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr=stderr)

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)

    assert sandbox._confirm_container_removed(container_name) == stderr


def test_force_remove_does_not_accept_ambiguous_not_found_substring(monkeypatch):
    container_name = "vulnresearch-" + "b" * 32
    stderr = f"permission denied: No such container: {container_name}"

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr=stderr)

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)

    assert sandbox._force_remove_container(container_name) == stderr


def test_post_removal_inspection_rejects_ambiguous_not_found_substring(monkeypatch):
    container_name = "vulnresearch-" + "d" * 32
    stderr = f"permission denied; No such container: {container_name}"
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[1] == "inspect" and len(calls) == 1:
            return subprocess.CompletedProcess(
                command, 0, stdout="container-id", stderr=""
            )
        if command[1] == "rm":
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr=stderr)

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)

    assert sandbox._confirm_container_removed(container_name) == stderr
    assert [command[1] for command in calls] == ["inspect", "rm", "inspect"]


def test_timeout_cleanup_rejects_container_that_remains_after_successful_rm(monkeypatch):
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[1] == "rm":
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="container-id", stderr="")

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)

    error = sandbox._confirm_container_removed("vulnresearch-" + "c" * 32)

    assert error == "container still exists after forced removal"
    assert [command[1] for command in commands] == ["inspect", "rm", "inspect"]


def test_join_output_readers_has_a_bounded_total_wait(monkeypatch):
    monkeypatch.setattr(sandbox, "_READER_JOIN_TIMEOUT_SECONDS", 0.01)
    release = threading.Event()
    reader = threading.Thread(target=release.wait)
    reader.start()

    assert not sandbox._join_output_readers([reader])

    release.set()
    reader.join(timeout=1)
    assert not reader.is_alive()


def test_timeout_does_not_wait_forever_for_blocked_output_readers(
    tmp_path, monkeypatch
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
    monkeypatch.setattr(sandbox, "_READER_JOIN_TIMEOUT_SECONDS", 0.01)
    release = threading.Event()

    class BlockingStream:
        def read(self, _size):
            release.wait(timeout=1)
            return b""

    process = _TimedOutDockerProcess([])
    process.stdout = BlockingStream()
    process.stderr = BlockingStream()
    monkeypatch.setattr(
        sandbox.subprocess,
        "Popen",
        lambda command, **kwargs: (
            setattr(process, "command", command) or process
        ),
    )
    monkeypatch.setattr(sandbox, "_confirm_container_removed", lambda _name: None)

    try:
        with pytest.raises(SandboxError, match="output capture readers did not stop"):
            sandbox.run_task(task)
    finally:
        release.set()


def test_unexpected_cleanup_kills_cli_after_wait_error_before_verifying_container(
    tmp_path, monkeypatch
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

    class WaitErrorDockerProcess:
        def __init__(self):
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.wait_calls = 0
            self.events = []

        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise RuntimeError("initial Docker wait failed")
            if self.wait_calls == 2:
                raise OSError("waitpid failed")
            return 0

        def terminate(self):
            self.events.append("terminate")

        def kill(self):
            self.events.append("kill")

    process = WaitErrorDockerProcess()
    monkeypatch.setattr(
        sandbox.subprocess, "Popen", lambda *args, **kwargs: process
    )

    def confirm_removed(_name):
        process.events.append("cleanup")

    monkeypatch.setattr(sandbox, "_confirm_container_removed", confirm_removed)

    with pytest.raises(RuntimeError, match="initial Docker wait failed"):
        sandbox.run_task(task)

    assert process.events == ["terminate", "kill", "cleanup"]
    assert process.wait_calls == 3


def test_unexpected_sandbox_exit_fails_closed_if_container_remains(
    tmp_path, monkeypatch
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

    class FailingDockerProcess:
        stdout = io.BytesIO()
        stderr = io.BytesIO()

        def __init__(self):
            self.wait_calls = 0
            self.terminated = False

        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise RuntimeError("unexpected wait failure")
            return 0

        def terminate(self):
            self.terminated = True

    process = FailingDockerProcess()
    monkeypatch.setattr(
        sandbox.subprocess, "Popen", lambda *args, **kwargs: process
    )
    monkeypatch.setattr(
        sandbox,
        "_confirm_container_removed",
        lambda _name: "container still exists after forced removal",
    )

    with pytest.raises(SandboxError, match="cleanup could not be confirmed"):
        sandbox.run_task(task)

    assert process.terminated
    assert process.wait_calls == 2


def test_timeout_bounds_final_docker_cli_wait_after_kill(tmp_path, monkeypatch):
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

    class PermanentlyHungDockerProcess:
        stdout = io.BytesIO()
        stderr = io.BytesIO()

        def __init__(self):
            self.wait_timeouts = []
            self.killed = False

        def wait(self, timeout=None):
            self.wait_timeouts.append(timeout)
            raise subprocess.TimeoutExpired("docker run", timeout)

        def send_signal(self, _signal):
            pass

        def terminate(self):
            pass

        def kill(self):
            self.killed = True

    process = PermanentlyHungDockerProcess()
    monkeypatch.setattr(
        sandbox.subprocess, "Popen", lambda *args, **kwargs: process
    )
    cleanup_states = []
    monkeypatch.setattr(
        sandbox,
        "_confirm_container_removed",
        lambda _name: cleanup_states.append(process.killed),
    )

    with pytest.raises(
        SandboxError,
        match="Docker CLI did not exit within the bounded wait after kill",
    ):
        sandbox.run_task(task)

    assert process.killed
    assert process.wait_timeouts == [1, 5, 2, 2]
    assert cleanup_states == [True]
    assert all(timeout is not None for timeout in process.wait_timeouts)


def test_normal_exit_does_not_wait_forever_for_blocked_output_readers(
    tmp_path, monkeypatch
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
    monkeypatch.setattr(sandbox, "_READER_JOIN_TIMEOUT_SECONDS", 0.01)
    release = threading.Event()

    class BlockingStream:
        def read(self, _size):
            release.wait(timeout=1)
            return b""

    class CompletedDockerProcess:
        stdout = BlockingStream()
        stderr = BlockingStream()

        def wait(self, timeout=None):
            return 0

    process = CompletedDockerProcess()
    monkeypatch.setattr(
        sandbox.subprocess, "Popen", lambda *args, **kwargs: process
    )
    cleanup_calls = []
    monkeypatch.setattr(
        sandbox,
        "_confirm_container_removed",
        lambda name: cleanup_calls.append(name),
    )

    try:
        with pytest.raises(
            SandboxError,
            match="output readers did not stop within the bounded wait",
        ):
            sandbox.run_task(task)
    finally:
        release.set()

    assert len(cleanup_calls) == 1


def test_output_reader_oserror_is_reported_as_sandbox_error(tmp_path, monkeypatch):
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

    class BrokenStream:
        def read(self, _size):
            raise OSError("simulated pipe read failure")

    class CompletedDockerProcess:
        stdout = BrokenStream()
        stderr = io.BytesIO()

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(
        sandbox.subprocess,
        "Popen",
        lambda *args, **kwargs: CompletedDockerProcess(),
    )
    cleanup_calls = []
    monkeypatch.setattr(
        sandbox,
        "_confirm_container_removed",
        lambda name: cleanup_calls.append(name),
    )

    with pytest.raises(
        SandboxError,
        match="Sandbox output capture failed: stdout: simulated pipe read failure",
    ):
        sandbox.run_task(task)

    assert len(cleanup_calls) == 1
