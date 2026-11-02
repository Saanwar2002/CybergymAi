import json

import pytest

from vulnresearch.policy.scope import authorize_task
from vulnresearch.task import ResearchTask


def manifest(workspace="."):
    return {
        "schema_version": "1.0",
        "task_id": "fixture-001",
        "name": "fixture",
        "description": "safe local fixture",
        "source": {"kind": "local_fixture", "reference": "tests/fixtures"},
        "authorization": {
            "status": "approved",
            "scope": "local_fixture_only",
            "approved_by": "developer",
            "approval_reference": "local-test",
        },
        "workspace": workspace,
        "execution_profile": "offline_readonly",
        "commands": [{"id": "smoke", "argv": ["python", "-c", "print('ok')"],
                      "timeout_seconds": 10}],
    }


def write_manifest(tmp_path, data):
    path = tmp_path / "task.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_loads_valid_task_and_policy_allows_local_fixture(tmp_path):
    task = ResearchTask.from_file(write_manifest(tmp_path, manifest()), workspace_root=tmp_path)
    assert task.task_id == "fixture-001"
    assert task.timeout_seconds == 10
    assert authorize_task(task).allowed


def test_rejects_empty_argv(tmp_path):
    data = manifest()
    data["commands"][0]["argv"] = []
    with pytest.raises(ValueError, match="non-empty"):
        ResearchTask.from_file(write_manifest(tmp_path, data), workspace_root=tmp_path)


def test_rejects_excessive_timeout(tmp_path):
    data = manifest()
    data["commands"][0]["timeout_seconds"] = 99999
    with pytest.raises(ValueError, match="between 1 and 3600"):
        ResearchTask.from_file(write_manifest(tmp_path, data), workspace_root=tmp_path)


def test_rejects_workspace_traversal(tmp_path):
    (tmp_path.parent / "outside").mkdir(exist_ok=True)
    data = manifest("../outside")
    with pytest.raises(ValueError, match="escapes"):
        ResearchTask.from_file(write_manifest(tmp_path, data), workspace_root=tmp_path)


def test_rejects_absolute_workspace(tmp_path):
    data = manifest(str(tmp_path))
    with pytest.raises(ValueError, match="relative path"):
        ResearchTask.from_file(write_manifest(tmp_path, data), workspace_root=tmp_path)


def test_policy_blocks_unapproved_task(tmp_path):
    data = manifest()
    data["authorization"]["status"] = "pending"
    task = ResearchTask.from_file(write_manifest(tmp_path, data), workspace_root=tmp_path)
    decision = authorize_task(task)
    assert not decision.allowed
    assert "not approved" in decision.reason


def test_policy_blocks_remote_scope(tmp_path):
    data = manifest()
    data["authorization"]["scope"] = "external_target"
    task = ResearchTask.from_file(write_manifest(tmp_path, data), workspace_root=tmp_path)
    assert not authorize_task(task).allowed


def test_rejects_boolean_timeout(tmp_path):
    data = manifest()
    data["commands"][0]["timeout_seconds"] = True
    with pytest.raises(ValueError, match="integer"):
        ResearchTask.from_file(write_manifest(tmp_path, data), workspace_root=tmp_path)
