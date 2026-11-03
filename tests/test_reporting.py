import hashlib
import json
import stat

import pytest

from vulnresearch import reporting
from vulnresearch.reporting import write_run_report
from vulnresearch.sandbox import SandboxResult
from vulnresearch.task import ResearchTask


def _make_task(tmp_path, task_id):
    return ResearchTask(
        schema_version="1.0",
        task_id=task_id,
        name="durability fixture",
        description="Verify durable report publication",
        source_kind="local_fixture",
        source_reference="fixture",
        authorization_status="approved",
        authorization_scope="local_fixture_only",
        approved_by="developer",
        approval_reference="test",
        workspace=str(tmp_path),
        execution_profile="offline_readonly",
        command=["python", "-c", "print('ok')"],
    )


def _make_result():
    return SandboxResult(
        returncode=0,
        stdout="ok",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.1,
    )


def test_write_run_report_persists_metadata_and_hashed_artifacts(tmp_path):
    task = ResearchTask(
        schema_version="1.0",
        task_id="fixture-001",
        name="fixture",
        description="safe fixture",
        source_kind="local_fixture",
        source_reference="fixture",
        authorization_status="approved",
        authorization_scope="local_fixture_only",
        approved_by="developer",
        approval_reference="test",
        workspace=str(tmp_path),
        execution_profile="offline_readonly",
        command=["python", "-c", "print('ok')"],
    )
    result = SandboxResult(
        returncode=0,
        stdout="ok\n",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.25,
    )
    report_path = write_run_report(task, result, tmp_path / "runs")
    record = json.loads(report_path.read_text(encoding="utf-8"))
    assert record["status"] == "succeeded"
    assert record["task_id"] == "fixture-001"
    assert record["duration_seconds"] == 0.25
    assert record["artifacts"]["stdout"]["size_bytes"] == 3
    assert len(record["artifacts"]["stdout"]["sha256"]) == 64
    assert (report_path.parent / "stdout.txt").read_text(encoding="utf-8") == "ok\n"
    assert stat.S_IMODE(report_path.parent.stat().st_mode) == 0o700
    for artifact in (
        report_path,
        report_path.parent / "stdout.txt",
        report_path.parent / "stderr.txt",
    ):
        assert stat.S_IMODE(artifact.stat().st_mode) == 0o600


def test_write_run_report_marks_nonzero_exit_as_failed(tmp_path):
    task = ResearchTask(
        schema_version="1.0",
        task_id="fixture-002",
        name="fixture",
        description="safe fixture",
        source_kind="local_fixture",
        source_reference="fixture",
        authorization_status="approved",
        authorization_scope="local_fixture_only",
        approved_by="developer",
        approval_reference="test",
        workspace=str(tmp_path),
        execution_profile="offline_readonly",
        command=["false"],
    )
    result = SandboxResult(1, "", "failed", False, True, 1.5)
    report_path = write_run_report(task, result, tmp_path / "runs")
    record = json.loads(report_path.read_text(encoding="utf-8"))
    assert record["status"] == "failed"
    assert record["artifacts"]["stderr"]["truncated"]


def test_write_run_report_does_not_publish_partial_run_on_artifact_failure(
    tmp_path, monkeypatch
):
    task = ResearchTask(
        schema_version="1.0",
        task_id="fixture-003",
        name="fixture",
        description="safe fixture",
        source_kind="local_fixture",
        source_reference="fixture",
        authorization_status="approved",
        authorization_scope="local_fixture_only",
        approved_by="developer",
        approval_reference="test",
        workspace=str(tmp_path),
        execution_profile="offline_readonly",
        command=["true"],
    )
    result = SandboxResult(0, "partial", "failure", False, False, 0.1)
    original_write_artifact = reporting._write_artifact

    def fail_on_stderr(directory, name, content, truncated):
        if name == "stderr.txt":
            raise OSError("simulated artifact write failure")
        return original_write_artifact(directory, name, content, truncated)

    monkeypatch.setattr(reporting, "_write_artifact", fail_on_stderr)

    try:
        write_run_report(task, result, tmp_path / "runs")
    except OSError as exc:
        assert str(exc) == "simulated artifact write failure"
    else:
        raise AssertionError("expected the simulated artifact failure")

    runs_directory = tmp_path / "runs"
    assert list(runs_directory.iterdir()) == []


def test_write_run_report_preserves_non_utf8_output_bytes_and_hashes(tmp_path):
    task = ResearchTask(
        schema_version="1.0",
        task_id="fixture-raw-bytes",
        name="raw byte fixture",
        description="Preserve exact output bytes",
        source_kind="local_fixture",
        source_reference="fixture",
        authorization_status="approved",
        authorization_scope="local_fixture_only",
        approved_by="developer",
        approval_reference="test",
        workspace=str(tmp_path),
        execution_profile="offline_readonly",
        command=["python", "-c", "pass"],
    )
    stdout_bytes = b"prefix\xff\x00suffix"
    stderr_bytes = b"diagnostic\x80"
    result = SandboxResult(
        returncode=0,
        stdout=stdout_bytes.decode("utf-8", errors="surrogateescape"),
        stderr=stderr_bytes.decode("utf-8", errors="surrogateescape"),
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.1,
    )

    report_path = write_run_report(task, result, tmp_path / "runs")
    record = json.loads(report_path.read_text(encoding="utf-8"))
    stored_stdout = (report_path.parent / "stdout.txt").read_bytes()
    stored_stderr = (report_path.parent / "stderr.txt").read_bytes()

    assert stored_stdout == stdout_bytes
    assert stored_stderr == stderr_bytes
    assert record["artifacts"]["stdout"]["sha256"] == hashlib.sha256(stdout_bytes).hexdigest()
    assert record["artifacts"]["stderr"]["sha256"] == hashlib.sha256(stderr_bytes).hexdigest()


def test_write_run_report_caps_untrusted_result_streams(tmp_path):
    task = ResearchTask(
        schema_version="1.0",
        task_id="fixture-large-output",
        name="large output fixture",
        description="Bound report persistence",
        source_kind="local_fixture",
        source_reference="fixture",
        authorization_status="approved",
        authorization_scope="local_fixture_only",
        approved_by="developer",
        approval_reference="test",
        workspace=str(tmp_path),
        execution_profile="offline_readonly",
        command=["python", "-c", "pass"],
    )
    result = SandboxResult(
        returncode=0,
        stdout="x" * (1024 * 1024 + 123),
        stderr="y" * (1024 * 1024 + 456),
        stdout_truncated=False,
        stderr_truncated=True,
        duration_seconds=0.1,
    )

    report_path = write_run_report(task, result, tmp_path / "runs")
    record = json.loads(report_path.read_text(encoding="utf-8"))
    stdout_bytes = (report_path.parent / "stdout.txt").read_bytes()
    stderr_bytes = (report_path.parent / "stderr.txt").read_bytes()

    assert len(stdout_bytes) == 1024 * 1024
    assert len(stderr_bytes) == 1024 * 1024
    assert record["artifacts"]["stdout"]["truncated"] is True
    assert record["artifacts"]["stderr"]["truncated"] is True
    assert record["artifacts"]["stdout"]["sha256"] == hashlib.sha256(stdout_bytes).hexdigest()
    assert record["artifacts"]["stderr"]["sha256"] == hashlib.sha256(stderr_bytes).hexdigest()


def test_write_run_report_fsyncs_staging_and_parent_directories(tmp_path, monkeypatch):
    task = _make_task(tmp_path, "fixture-durable-local-report")
    synced = []

    def record_fsync(path):
        synced.append(path)

    monkeypatch.setattr(reporting, "fsync_directory", record_fsync)

    report_path = write_run_report(task, _make_result(), tmp_path / "runs")

    assert report_path.is_file()
    assert len(synced) == 2
    assert synced[0].parent == tmp_path / "runs"
    assert synced[0].name.startswith(".")
    assert synced[1] == tmp_path / "runs"


def test_write_run_report_staging_fsync_failure_publishes_nothing(
    tmp_path, monkeypatch
):
    task = _make_task(tmp_path, "fixture-local-staging-failure")

    def fail_fsync(_path):
        raise OSError("simulated local report staging directory fsync failure")

    monkeypatch.setattr(reporting, "fsync_directory", fail_fsync)

    with pytest.raises(OSError, match="local report staging directory fsync failure"):
        write_run_report(task, _make_result(), tmp_path / "runs")

    assert list((tmp_path / "runs").iterdir()) == []


def test_write_run_report_parent_fsync_failure_leaves_complete_run_visible(
    tmp_path, monkeypatch
):
    task = _make_task(tmp_path, "fixture-local-parent-failure")
    parent = tmp_path / "runs"

    def fail_parent_fsync(path):
        if path == parent:
            raise OSError("simulated local report parent directory fsync failure")

    monkeypatch.setattr(reporting, "fsync_directory", fail_parent_fsync)

    with pytest.raises(
        reporting.RunReportPublicationError,
        match="durability is uncertain",
    ) as error:
        write_run_report(task, _make_result(), parent)

    published = [path for path in parent.iterdir() if path.is_dir()]
    assert len(published) == 1
    assert error.value.report_path == published[0] / "report.json"
    assert error.value.report_path.is_file()
    assert (published[0] / "stdout.txt").read_text(encoding="utf-8") == "ok"
    assert (published[0] / "stderr.txt").is_file()
    assert isinstance(error.value.cause, OSError)
