import hashlib
import json
from datetime import datetime

import pytest

from vulnresearch.reporting import write_run_report
from vulnresearch.sandbox import SandboxResult
from vulnresearch.task import ResearchTask
from vulnresearch.workflow.evidence import (
    create_evidence_bundle,
    verify_evidence_bundle,
)
from vulnresearch.workflow.lifecycle import ActorRole, LifecycleState
from vulnresearch.workflow.session import WorkflowSession


def _research_task(tmp_path, task_id):
    return ResearchTask(
        schema_version="1.0",
        task_id=task_id,
        name="harmless fixture regression test",
        description="Local fixture only",
        source_kind="local_fixture",
        source_reference="tests/fixtures",
        authorization_status="approved",
        authorization_scope="local_fixture_only",
        approved_by="test reviewer",
        approval_reference="fixture-test",
        workspace=str(tmp_path),
        execution_profile="offline_readonly",
        command=["python", "-c", "print('tests passed')"],
    )


def test_complete_harmless_fixture_workflow_round_trips_with_patch_evidence(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "stdout.txt").write_text("fixture reproduced\n", encoding="utf-8")
    (artifacts / "report.json").write_text(
        '{"status":"passed"}\n', encoding="utf-8"
    )
    initial_bundle = create_evidence_bundle(
        "fixture-e2e-001",
        {"stdout": "stdout.txt", "report": "report.json"},
        artifact_root=artifacts,
        output_path=artifacts / "bundles" / "reproduction.json",
    )
    verify_evidence_bundle(initial_bundle, artifact_root=artifacts)
    reproduction_ref = f"bundle:{initial_bundle.relative_to(artifacts).as_posix()}"

    session = WorkflowSession.create(
        "fixture-e2e-001", tmp_path / "audit" / "workflow.jsonl"
    )
    session = session.advance(
        LifecycleState.TRIAGED,
        actor="workflow",
        actor_role=ActorRole.SYSTEM,
    )
    session = session.advance(
        LifecycleState.PLAN_APPROVED,
        actor="researcher",
        actor_role=ActorRole.HUMAN,
        decision_note="Approved the local fixture plan.",
    )
    session = session.advance(
        LifecycleState.REPRODUCTION_ATTEMPTED,
        actor="runner",
        actor_role=ActorRole.SYSTEM,
    )
    session = session.advance(
        LifecycleState.EVIDENCE_REVIEWED,
        actor="reviewer",
        actor_role=ActorRole.HUMAN,
        evidence_refs=[reproduction_ref],
    )

    (artifacts / "fix.patch").write_text(
        "diff --git a/example.py b/example.py\n", encoding="utf-8"
    )
    session = session.propose_patch(
        "fix.patch",
        artifact_root=artifacts,
        bundle_path="bundles/patch-proposal.json",
        actor="agent",
        actor_role=ActorRole.AGENT,
        decision_note="Proposed a defensive fixture-only patch.",
    )

    task = _research_task(tmp_path, "fixture-e2e-001")
    result = SandboxResult(
        returncode=0,
        stdout="tests passed\n",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.2,
    )
    report_path = write_run_report(task, result, artifacts / "runs")
    test_bundle = create_evidence_bundle(
        "fixture-e2e-001",
        {
            "report": report_path.relative_to(artifacts).as_posix(),
            "stdout": (report_path.parent / "stdout.txt").relative_to(artifacts).as_posix(),
            "stderr": (report_path.parent / "stderr.txt").relative_to(artifacts).as_posix(),
        },
        artifact_root=artifacts,
        output_path=artifacts / "bundles" / "patch-test.json",
    )
    session = session.record_patch_test(test_bundle, artifact_root=artifacts)
    test_ref = f"bundle:{test_bundle.relative_to(artifacts).as_posix()}"
    session = session.advance(
        LifecycleState.HUMAN_ACCEPTED,
        actor="maintainer",
        actor_role=ActorRole.HUMAN,
        evidence_refs=[test_ref],
        decision_note="Reviewed the patch-test report and accepted the fixture result.",
    )

    reopened = WorkflowSession.open(session.audit_path)
    assert reopened.record == session.record
    assert reopened.record.state is LifecycleState.HUMAN_ACCEPTED
    assert len(reopened.record.events) == 7
    assert reopened.record.events[-1].evidence_refs == (test_ref,)
    assert datetime.fromisoformat(
        reopened.record.events[-1].occurred_at
    ).utcoffset() is not None


def test_patch_test_bundle_must_match_workflow_task(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    report = artifacts / "report.json"
    report.write_text(
        '{"task_id":"other-task","status":"succeeded","exit_code":0}',
        encoding="utf-8",
    )
    (artifacts / "stdout.txt").write_text("ok", encoding="utf-8")
    (artifacts / "stderr.txt").write_text("", encoding="utf-8")
    bundle = create_evidence_bundle(
        "other-task",
        {"report": "report.json", "stdout": "stdout.txt", "stderr": "stderr.txt"},
        artifact_root=artifacts,
        output_path=artifacts / "bundles" / "other-task.json",
    )
    session = WorkflowSession.create("fixture-expected", tmp_path / "audit.jsonl")
    with pytest.raises(ValueError, match="task_id"):
        session.record_patch_test(bundle, artifact_root=artifacts)


def test_patch_proposal_rejects_non_patch_artifacts(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "notes.txt").write_text("not a patch", encoding="utf-8")
    session = WorkflowSession.create("fixture-invalid-patch", tmp_path / "audit.jsonl")

    with pytest.raises(ValueError, match=".patch or .diff"):
        session.propose_patch(
            "notes.txt",
            artifact_root=artifacts,
            bundle_path="bundles/proposal.json",
            actor="agent",
            actor_role=ActorRole.AGENT,
            decision_note="This must not be accepted as a patch.",
        )


def test_patch_test_requires_report_and_both_log_streams(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "report.json").write_text(
        '{"task_id":"fixture-missing-logs","status":"succeeded","exit_code":0}',
        encoding="utf-8",
    )
    (artifacts / "stdout.txt").write_text("passed", encoding="utf-8")
    bundle = create_evidence_bundle(
        "fixture-missing-logs",
        {"report": "report.json", "stdout": "stdout.txt"},
        artifact_root=artifacts,
        output_path=artifacts / "bundles" / "incomplete.json",
    )
    session = WorkflowSession.create(
        "fixture-missing-logs", tmp_path / "audit.jsonl"
    )

    with pytest.raises(ValueError, match="stdout, and stderr"):
        session.record_patch_test(bundle, artifact_root=artifacts)


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ("path", "path is not relative"),
        ("sha256", "metadata does not match evidence bundle"),
    ],
)
def test_patch_test_rejects_report_log_mismatch(tmp_path, tamper, message):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    stdout = artifacts / "stdout.txt"
    stderr = artifacts / "stderr.txt"
    stdout.write_text("candidate passed\\n", encoding="utf-8")
    stderr.write_text("", encoding="utf-8")
    report_data = {
        "schema_version": "1.0",
        "task_id": "fixture-report-binding",
        "status": "succeeded",
        "exit_code": 0,
        "artifacts": {
            "stdout": {
                "path": "stdout.txt",
                "sha256": hashlib.sha256(stdout.read_bytes()).hexdigest(),
                "size_bytes": stdout.stat().st_size,
                "truncated": False,
            },
            "stderr": {
                "path": "stderr.txt",
                "sha256": hashlib.sha256(stderr.read_bytes()).hexdigest(),
                "size_bytes": stderr.stat().st_size,
                "truncated": False,
            },
        },
    }
    if tamper == "path":
        report_data["artifacts"]["stdout"]["path"] = "../stdout.txt"
    else:
        report_data["artifacts"]["stdout"]["sha256"] = "0" * 64
    (artifacts / "report.json").write_text(
        json.dumps(report_data), encoding="utf-8"
    )
    bundle = create_evidence_bundle(
        "fixture-report-binding",
        {"report": "report.json", "stdout": "stdout.txt", "stderr": "stderr.txt"},
        artifact_root=artifacts,
        output_path=artifacts / "bundles" / "candidate.json",
    )
    session = WorkflowSession.create(
        "fixture-report-binding", tmp_path / "audit.jsonl"
    )

    with pytest.raises(ValueError, match=message):
        session.record_patch_test(bundle, artifact_root=artifacts)
