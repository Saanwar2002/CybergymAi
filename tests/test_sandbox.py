import json
from dataclasses import replace

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
    assert command[command.index("--pull") + 1] == "never"
    assert "--network" in command
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--user") + 1] == "65534:65534"
    assert "--read-only" in command
    assert command[command.index("--ipc") + 1] == "private"
    assert "no-new-privileges:true" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--pids-limit") + 1] == "64"
    assert command[command.index("--memory") + 1] == "512m"
    assert command[command.index("--memory-swap") + 1] == "512m"
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


def test_docker_command_accepts_only_generated_container_names(tmp_path):
    task = load_task(tmp_path)
    image = "python:3.11-slim@sha256:" + "a" * 64
    name = "vulnresearch-" + "b" * 32
    command = build_docker_command(task, image=image, container_name=name)
    assert command[command.index("--name") + 1] == name

    with pytest.raises(SandboxError, match="generated vulnresearch UUID"):
        build_docker_command(task, image=image, container_name="user-controlled-name")


def test_docker_command_rejects_workspace_outside_trusted_root(tmp_path):
    task = load_task(tmp_path)
    outside = tmp_path.parent / "outside-workspace"
    outside.mkdir()
    forged_task = replace(task, workspace=str(outside))
    image = "python:3.11-slim@sha256:" + "a" * 64

    with pytest.raises(SandboxError, match="workspace escapes"):
        build_docker_command(forged_task, image=image)


def test_docker_command_rejects_task_without_trusted_workspace_root(tmp_path):
    task = load_task(tmp_path)
    forged_task = replace(task, workspace_root=None)
    image = "python:3.11-slim@sha256:" + "a" * 64

    with pytest.raises(SandboxError, match="trusted workspace root"):
        build_docker_command(forged_task, image=image)



def test_docker_command_rejects_workspace_override_outside_trusted_root(tmp_path):
    task = load_task(tmp_path)
    outside = tmp_path.parent / "outside-workspace"
    outside.mkdir()
    image = "python:3.11-slim@sha256:" + "a" * 64

    with pytest.raises(SandboxError, match="override must exactly match"):
        build_docker_command(task, image=image, workspace=outside)


def test_docker_command_rejects_different_workspace_inside_trusted_root(tmp_path):
    task = load_task(tmp_path)
    nested = tmp_path / "nested-workspace"
    nested.mkdir()
    image = "python:3.11-slim@sha256:" + "a" * 64

    with pytest.raises(SandboxError, match="override must exactly match"):
        build_docker_command(task, image=image, workspace=nested)


def test_docker_command_accepts_only_the_manifest_approved_workspace(tmp_path):
    task = load_task(tmp_path)
    image = "python:3.11-slim@sha256:" + "a" * 64

    command = build_docker_command(task, image=image, workspace=task.workspace)

    assert f"{task.workspace}:/workspace:ro" in command
