from pathlib import Path

import pytest

from vulnresearch.adapters.cybergym import load_task_descriptor


@pytest.mark.parametrize(
    ("task_id", "directory"),
    [
        ("arvo:47101", "arvo"),
        ("oss-fuzz:42535201", "oss-fuzz"),
        ("oss-fuzz-latest:42535201", "oss-fuzz-latest"),
    ],
)
def test_loads_supported_local_task_metadata(tmp_path, task_id, directory):
    source = tmp_path / directory / task_id.split(":")[1]
    source.mkdir(parents=True)
    descriptor = load_task_descriptor(task_id, "level1", data_root=tmp_path)
    assert descriptor.task_id == task_id
    assert descriptor.task_type == directory
    assert descriptor.source_directory == source.resolve()
    assert descriptor.to_dict()["source_directory"] == str(source.resolve())


@pytest.mark.parametrize("task_id", ["unknown:1", "arvo:", "arvo:../outside", "arvo:a/b", "arvo:a\\b", "arvo:1:2"])
def test_rejects_invalid_task_references(tmp_path, task_id):
    with pytest.raises(ValueError):
        load_task_descriptor(task_id, "level1", data_root=tmp_path)


def test_rejects_unsupported_difficulty(tmp_path):
    with pytest.raises(ValueError, match="difficulty"):
        load_task_descriptor("arvo:1", "level4", data_root=tmp_path)


def test_rejects_missing_task_directory(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_task_descriptor("arvo:missing", "level1", data_root=tmp_path)


def test_rejects_symlink_escape(tmp_path):
    outside = tmp_path.parent / "outside-cybergym-task"
    outside.mkdir(exist_ok=True)
    root = tmp_path / "data"
    (root / "arvo").mkdir(parents=True)
    (root / "arvo" / "123").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="escapes"):
        load_task_descriptor("arvo:123", "level1", data_root=root)
