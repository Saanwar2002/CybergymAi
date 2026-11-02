import json
import re

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

@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data.update({"unexpected": "ignored"}), "Unknown task manifest fields"),
        (lambda data: data["source"].update({"download_url": "https://example.invalid"}),
         "source must contain only"),
        (lambda data: data["authorization"].update({"is_verified": True}),
         "authorization must contain only"),
        (lambda data: data["commands"][0].update({"shell": True}),
         "commands[0] contains unknown fields"),
        (lambda data: data["commands"][0].update({"id": ""}),
         "commands[0].id must be a non-empty string"),
    ],
)
def test_rejects_unknown_or_malformed_security_fields(tmp_path, mutate, message):
    data = manifest()
    mutate(data)
    with pytest.raises(ValueError, match=re.escape(message)):
        ResearchTask.from_file(write_manifest(tmp_path, data), workspace_root=tmp_path)


@pytest.mark.parametrize(
    ("needle", "replacement", "duplicate_key"),
    [
        ('"status": "approved"', '"status": "pending", "status": "approved"', "status"),
        ('"workspace": "."', '"workspace": "../outside", "workspace": "."', "workspace"),
    ],
)
def test_rejects_duplicate_json_object_keys(
    tmp_path, needle, replacement, duplicate_key
):
    raw = json.dumps(manifest())
    assert needle in raw
    path = tmp_path / "task.json"
    path.write_text(raw.replace(needle, replacement, 1), encoding="utf-8")

    with pytest.raises(ValueError, match=re.escape(
        f"Duplicate JSON object key: {duplicate_key}"
    )):
        ResearchTask.from_file(path, workspace_root=tmp_path)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data.update({"task_id": "x" * 129}), "task_id must not exceed"),
        (lambda data: data.update({"name": "x" * 257}), "name must not exceed"),
        (lambda data: data.update({"description": "x" * 8001}), "description must not exceed"),
        (lambda data: data.update({"workspace": "x" * 1025}), "workspace must not exceed"),
        (lambda data: data["source"].update({"reference": "x" * 1025}),
         "source.reference must not exceed"),
        (lambda data: data["authorization"].update({"approved_by": "x" * 257}),
         "authorization.approved_by must not exceed"),
        (lambda data: data["commands"][0].update({"argv": ["x" * 4097]}),
         "command arguments exceed"),
        (lambda data: data["commands"][0].update({"argv": ["x" * 4096] * 5}),
         "command arguments exceed"),
        (lambda data: data["commands"][0].update({"id": "x" * 65}),
         "commands[0].id must be a non-empty string"),
    ],
)
def test_rejects_oversized_manifest_text_and_commands(tmp_path, mutate, message):
    data = manifest()
    mutate(data)
    with pytest.raises(ValueError, match=re.escape(message)):
        ResearchTask.from_file(write_manifest(tmp_path, data), workspace_root=tmp_path)
