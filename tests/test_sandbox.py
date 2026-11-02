import json

import pytest

from vulnresearch.sandbox import SandboxError, build_docker_command
from vulnresearch.task import ResearchTask


def manifest(workspace="."):
    return {
        "schema_version": "1.0",
        "task_id": "fixture-001",
        "name": "fixture",
        "description": "safe local fixture",
        "source": {"kind": "local_fixture", "reference": "fixture"},
        "authorization": {
            "status": "approved",
            "scope": "local_fixture_only",
            "approved_by": "developer",
            "approval_reference": "test",
        },
        "workspace": workspace,
        "execution_profile": "offline_readonly",
        "commands": [{"argv": ["python", "-c", "print('ok')"]}],
    }


def load_task(tmp_path, data=None):
    path = tmp_path / "task.json"
    path.write_text(json.dumps(data or manifest()), encoding="utf-8")
    return ResearchTask.from_file(path, workspace_root=tmp_path)


def test_docker_command_enforces_offline_non_root_readonly_profile(tmp_path):
    task = load_task(tmp_path)
    image = "python:3.11-slim@sha256:" + "a" * 64
    command = build_docker_command(task, image=image)
    assert "--network" in command
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--user") + 1] == "65534:65534"
    assert command[command.index("--read-only") - 1] == "--ipc"
    assert "no-new-privileges:true" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--pids-limit") + 1] == "64"
    assert command[command.index("--memory") + 1] == "512m"
    assert command[-3:] == ["python", "-c", "print('ok')"]


def test_docker_command_rejects_mutable_or_unapproved_image(tmp_path):
    task = load_task(tmp_path)
    with pytest.raises(SandboxError, match="pinned by sha256"):
        build_docker_command(task, image="python:3.11-slim")


def test_docker_command_rejects_unapproved_task(tmp_path):
    data = manifest()
    data["authorization"]["status"] = "pending"
    task = load_task(tmp_path, data)
    image = "python:3.11-slim@sha256:" + "a" * 64
    with pytest.raises(SandboxError, match="blocked by policy"):
        build_docker_command(task, image=image)
