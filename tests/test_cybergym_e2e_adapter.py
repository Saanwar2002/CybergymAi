import pytest

from vulnresearch.adapters.cybergym_e2e import load_task_descriptor


def _fixture(root):
    task = root / "projects" / "sample-project" / "arvo_12345"
    task.mkdir(parents=True)
    (task.parent / "project.toml").write_text(
        'name = "Sample Project"\nlanguage = "c++"\nrepo_to_patch = "sample-project"\n',
        encoding="utf-8",
    )
    (task / "config.toml").write_text(
        'task_id = "arvo:12345"\ntarget_prog = "sample-fuzzer"\n'
        'vul_commit = "abc123"\npatch_commit = "secret-ground-truth"\n',
        encoding="utf-8",
    )
    (task / "compile.sh").write_text("echo fixture only", encoding="utf-8")
    return task


def test_loads_only_safe_metadata_for_supported_modes(tmp_path):
    task = _fixture(tmp_path)
    descriptor = load_task_descriptor(
        "sample-project/arvo_12345", "e2e", data_root=tmp_path
    )
    data = descriptor.to_dict()

    assert descriptor.task_id == "arvo:12345"
    assert descriptor.project_name == "Sample Project"
    assert descriptor.target_program == "sample-fuzzer"
    assert descriptor.mode == "e2e"
    assert descriptor.source_directory == task.resolve()
    assert "patch_commit" not in data
    assert "compile.sh" not in data


def test_patch_only_mode_is_supported(tmp_path):
    _fixture(tmp_path)
    descriptor = load_task_descriptor(
        "sample-project/arvo_12345", "patch-only", data_root=tmp_path
    )
    assert descriptor.mode == "patch-only"


@pytest.mark.parametrize(
    ("task_reference", "mode"),
    [
        ("../outside/arvo_12345", "e2e"),
        ("sample-project/../arvo_12345", "e2e"),
        ("sample-project/arvo_12345/extra", "e2e"),
        ("sample-project/arvo_12345", "unknown"),
    ],
)
def test_rejects_unsafe_references_and_modes(tmp_path, task_reference, mode):
    _fixture(tmp_path)
    with pytest.raises(ValueError):
        load_task_descriptor(task_reference, mode, data_root=tmp_path)


def test_rejects_task_config_identifier_mismatch(tmp_path):
    task = _fixture(tmp_path)
    (task / "config.toml").write_text(
        'task_id = "arvo:99999"\ntarget_prog = "sample-fuzzer"\n'
        'vul_commit = "abc123"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="does not match"):
        load_task_descriptor("sample-project/arvo_12345", "e2e", data_root=tmp_path)


def test_rejects_symlink_escape(tmp_path):
    outside = tmp_path.parent / "outside-project"
    outside.mkdir()
    (outside / "project.toml").write_text(
        'name = "Outside"\nlanguage = "c"\n', encoding="utf-8"
    )
    projects = tmp_path / "projects"
    projects.mkdir()
    (projects / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="escapes"):
        load_task_descriptor("linked/arvo_12345", "e2e", data_root=tmp_path)
