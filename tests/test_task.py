import json

import pytest

from vulnresearch.task import ResearchTask


def test_loads_valid_task(tmp_path):
    manifest = {
        "name": "fixture", "description": "safe test", "workspace": str(tmp_path),
        "command": ["python", "-c", "print('ok')"], "timeout_seconds": 10,
    }
    path = tmp_path / "task.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    task = ResearchTask.from_file(path)
    assert task.name == "fixture"
    assert task.timeout_seconds == 10


def test_rejects_empty_command(tmp_path):
    path = tmp_path / "task.json"
    path.write_text(json.dumps({
        "name": "x", "description": "y", "workspace": str(tmp_path), "command": []
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="non-empty"):
        ResearchTask.from_file(path)


def test_rejects_excessive_timeout(tmp_path):
    path = tmp_path / "task.json"
    path.write_text(json.dumps({
        "name": "x", "description": "y", "workspace": str(tmp_path),
        "command": ["true"], "timeout_seconds": 99999
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="between 1 and 3600"):
        ResearchTask.from_file(path)
