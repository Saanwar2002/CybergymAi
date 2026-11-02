import json
import stat

from vulnresearch.reporting import write_run_report
from vulnresearch.sandbox import SandboxResult
from vulnresearch.task import ResearchTask


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
