import hashlib
import json
from datetime import datetime

import pytest

from vulnresearch.execution import (
    BackendResult,
    ExecutionLimits,
    ExecutionRequirements,
    ExecutionSpec,
    ExecutionStatus,
)
from vulnresearch.execution.reporting import write_benchmark_run_report
from vulnresearch.reporting import write_run_report
from vulnresearch.sandbox import SandboxResult
from vulnresearch.task import ResearchTask
from vulnresearch.workflow import session as session_module
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
        ("path", "path must be stdout.txt"),
        ("sha256", "metadata does not match evidence bundle"),
        ("size", "metadata does not match evidence bundle"),
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
        "run_id": "fixture-run-001",
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
    elif tamper == "sha256":
        report_data["artifacts"]["stdout"]["sha256"] = "0" * 64
    else:
        report_data["artifacts"]["stderr"]["size_bytes"] = False
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


def test_patch_test_rejects_duplicate_json_report_keys(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "report.json").write_text(
        '{"task_id":"fixture-duplicate-report","task_id":"fixture-duplicate-report"}',
        encoding="utf-8",
    )
    (artifacts / "stdout.txt").write_text("ok", encoding="utf-8")
    (artifacts / "stderr.txt").write_text("", encoding="utf-8")
    bundle = create_evidence_bundle(
        "fixture-duplicate-report",
        {"report": "report.json", "stdout": "stdout.txt", "stderr": "stderr.txt"},
        artifact_root=artifacts,
        output_path=artifacts / "bundles" / "duplicate-report.json",
    )
    session = WorkflowSession.create(
        "fixture-duplicate-report", tmp_path / "audit.jsonl"
    )

    with pytest.raises(ValueError, match="Duplicate JSON object key"):
        session.record_patch_test(bundle, artifact_root=artifacts)


def test_patch_test_rejects_report_mutated_after_bundle_verification(
    tmp_path, monkeypatch
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "fixture-report-mutated-after-verify"
    report_path = write_run_report(
        _research_task(tmp_path, task_id),
        SandboxResult(0, "passed\\n", "", False, False, 0.1),
        artifacts / "runs",
    )
    bundle = create_evidence_bundle(
        task_id,
        {
            "report": report_path.relative_to(artifacts).as_posix(),
            "stdout": (report_path.parent / "stdout.txt").relative_to(artifacts).as_posix(),
            "stderr": (report_path.parent / "stderr.txt").relative_to(artifacts).as_posix(),
        },
        artifact_root=artifacts,
        output_path=artifacts / "bundles" / "patch-test.json",
    )
    session = WorkflowSession.create(task_id, tmp_path / "audit.jsonl")
    original_verify = session_module.verify_evidence_bundle

    def verify_then_mutate(bundle_path, *, artifact_root):
        manifest = original_verify(bundle_path, artifact_root=artifact_root)
        report_path.write_text(
            '{"task_id":"tampered-after-verification"}', encoding="utf-8"
        )
        return manifest

    monkeypatch.setattr(
        session_module, "verify_evidence_bundle", verify_then_mutate
    )

    with pytest.raises(ValueError, match="report integrity check failed after read"):
        session.record_patch_test(bundle, artifact_root=artifacts)


def _benchmark_report(artifacts, task_id):
    spec = ExecutionSpec(
        run_id="benchmark-run-001",
        task_id=task_id,
        command_id="safe-fixture",
        argv=("python", "-c", "print('benchmark passed')"),
        timeout_seconds=30,
        requirements=ExecutionRequirements.for_benchmark(),
        limits=ExecutionLimits(
            vcpu_count=1,
            memory_bytes=1024 * 1024**2,
            disk_bytes=5 * 1024**3,
            max_processes=256,
            max_input_bytes=64 * 1024**2,
            max_output_bytes_total=2 * 1024**2,
        ),
    )
    result = BackendResult(
        status=ExecutionStatus.COMPLETED,
        returncode=0,
        stdout="benchmark passed\\n",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.2,
        cleanup_confirmed=True,
        allocated_vcpu_count=1,
        peak_memory_bytes=512 * 1024**2,
        peak_disk_bytes=1024**3,
        peak_processes=32,
        input_bytes_staged=0,
        execution_spec_sha256=spec.manifest_sha256,
    )
    return write_benchmark_run_report(spec, result, artifacts / "runs")


def _plan_approved_session(tmp_path, task_id):
    session = WorkflowSession.create(task_id, tmp_path / "audit.jsonl")
    session = session.advance(
        LifecycleState.TRIAGED,
        actor="workflow",
        actor_role=ActorRole.SYSTEM,
    )
    return session.advance(
        LifecycleState.PLAN_APPROVED,
        actor="researcher",
        actor_role=ActorRole.HUMAN,
        decision_note="Approved the benchmark reproduction plan.",
    )


def test_benchmark_execution_report_is_bound_to_reproduction_lifecycle(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "benchmark-lifecycle-001"
    report_path = _benchmark_report(artifacts, task_id)
    session = _plan_approved_session(tmp_path, task_id)

    updated = session.record_benchmark_execution(
        report_path.relative_to(artifacts),
        artifact_root=artifacts,
        bundle_path="bundles/reproduction.json",
    )

    assert updated.record.state is LifecycleState.REPRODUCTION_ATTEMPTED
    evidence_ref = updated.record.events[-1].evidence_refs[0]
    assert evidence_ref == "bundle:bundles/reproduction.json"
    assert updated.record.events[-1].actor_role is ActorRole.SYSTEM
    assert "benchmark-run-001" in updated.record.events[-1].decision_note
    bundle = artifacts / "bundles" / "reproduction.json"
    manifest = verify_evidence_bundle(bundle, artifact_root=artifacts)
    assert set(manifest["artifacts"]) == {"report", "stdout", "stderr"}
    assert WorkflowSession.open(updated.audit_path).record == updated.record


def test_benchmark_execution_rejects_manifest_digest_mismatch(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    report_path = _benchmark_report(artifacts, "benchmark-digest-001")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["execution_spec"]["argv"][-1] = "print('tampered')"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    session = _plan_approved_session(tmp_path, "benchmark-digest-001")

    with pytest.raises(ValueError, match="execution specification digest mismatch"):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
        )

    assert session.record.state is LifecycleState.PLAN_APPROVED
    assert not (artifacts / "bundles").exists()


def test_benchmark_execution_rejects_mutated_log_before_lifecycle_append(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    report_path = _benchmark_report(artifacts, "benchmark-log-001")
    (report_path.parent / "stdout.txt").write_text("tampered\\n", encoding="utf-8")
    session = _plan_approved_session(tmp_path, "benchmark-log-001")

    with pytest.raises(ValueError, match="stdout metadata does not match"):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
        )

    assert session.record.state is LifecycleState.PLAN_APPROVED
    assert not (artifacts / "bundles").exists()


def test_benchmark_execution_requires_human_plan_approval_before_reading_report(
    tmp_path,
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    session = WorkflowSession.create(
        "benchmark-plan-not-approved", tmp_path / "audit.jsonl"
    )

    with pytest.raises(ValueError, match="only be recorded after plan approval"):
        session.record_benchmark_execution(
            "missing/report.json",
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
        )

    assert not (artifacts / "bundles").exists()


def test_benchmark_execution_rejects_self_consistent_downgraded_vm_manifest(
    tmp_path,
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    report_path = _benchmark_report(artifacts, "benchmark-downgrade-001")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["execution_spec"]["requirements"]["minimum_isolation"] = "container"
    canonical = json.dumps(
        report["execution_spec"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    report["execution_spec_sha256"] = hashlib.sha256(canonical).hexdigest()
    report_path.write_text(json.dumps(report), encoding="utf-8")
    session = _plan_approved_session(tmp_path, "benchmark-downgrade-001")

    with pytest.raises(ValueError, match="every mandatory VM isolation requirement"):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
        )

    assert session.record.state is LifecycleState.PLAN_APPROVED
    assert not (artifacts / "bundles").exists()


def test_benchmark_patch_test_report_is_bound_to_patch_test_lifecycle(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "benchmark-patch-test-001"
    session = _plan_approved_session(tmp_path, task_id)
    session = session.advance(
        LifecycleState.REPRODUCTION_ATTEMPTED,
        actor="runner",
        actor_role=ActorRole.SYSTEM,
    )
    session = session.advance(
        LifecycleState.EVIDENCE_REVIEWED,
        actor="reviewer",
        actor_role=ActorRole.HUMAN,
        evidence_refs=["bundle:reproduction.json"],
    )
    (artifacts / "fix.patch").write_text(
        "diff --git a/example.py b/example.py\\n", encoding="utf-8"
    )
    session = session.propose_patch(
        "fix.patch",
        artifact_root=artifacts,
        bundle_path="bundles/proposal.json",
        actor="agent",
        actor_role=ActorRole.AGENT,
        decision_note="Proposed the benchmark patch.",
    )
    report_path = _benchmark_report(artifacts, task_id)

    updated = session.record_benchmark_patch_test(
        report_path.relative_to(artifacts),
        artifact_root=artifacts,
        bundle_path="bundles/benchmark-patch-test.json",
    )

    assert updated.record.state is LifecycleState.PATCH_TESTED
    evidence_ref = updated.record.events[-1].evidence_refs[0]
    assert evidence_ref == "bundle:bundles/benchmark-patch-test.json"
    manifest = verify_evidence_bundle(
        artifacts / "bundles" / "benchmark-patch-test.json",
        artifact_root=artifacts,
    )
    assert set(manifest["artifacts"]) == {"report", "stdout", "stderr"}
    assert WorkflowSession.open(updated.audit_path).record == updated.record


def test_benchmark_patch_test_rejects_downgraded_execution_manifest(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "benchmark-patch-downgrade-001"
    session = _plan_approved_session(tmp_path, task_id)
    session = session.advance(
        LifecycleState.REPRODUCTION_ATTEMPTED,
        actor="runner",
        actor_role=ActorRole.SYSTEM,
    )
    session = session.advance(
        LifecycleState.EVIDENCE_REVIEWED,
        actor="reviewer",
        actor_role=ActorRole.HUMAN,
        evidence_refs=["bundle:reproduction.json"],
    )
    (artifacts / "fix.patch").write_text("diff --git a/a b/a\\n", encoding="utf-8")
    session = session.propose_patch(
        "fix.patch",
        artifact_root=artifacts,
        bundle_path="bundles/proposal.json",
        actor="agent",
        actor_role=ActorRole.AGENT,
        decision_note="Proposed the benchmark patch.",
    )
    report_path = _benchmark_report(artifacts, task_id)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["execution_spec"]["requirements"]["minimum_isolation"] = "container"
    canonical = json.dumps(
        report["execution_spec"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    report["execution_spec_sha256"] = hashlib.sha256(canonical).hexdigest()
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="every mandatory VM isolation requirement"):
        session.record_benchmark_patch_test(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/benchmark-patch-test.json",
        )

    assert session.record.state is LifecycleState.PATCH_PROPOSED
    assert not (artifacts / "bundles" / "benchmark-patch-test.json").exists()


@pytest.mark.parametrize("changed_artifact", ["report", "stdout"])
def test_benchmark_bundle_rejects_bytes_changed_between_validation_and_publication(
    tmp_path, monkeypatch, changed_artifact
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    report_path = _benchmark_report(artifacts, f"benchmark-race-{changed_artifact}")
    session = _plan_approved_session(tmp_path, f"benchmark-race-{changed_artifact}")
    original_create = session_module.create_evidence_bundle

    def mutate_then_create(task_id, bundle_artifacts, *, artifact_root, output_path):
        target = (
            report_path
            if changed_artifact == "report"
            else report_path.parent / "stdout.txt"
        )
        with target.open("ab") as stream:
            stream.write(b" ")
        return original_create(
            task_id,
            bundle_artifacts,
            artifact_root=artifact_root,
            output_path=output_path,
        )

    monkeypatch.setattr(
        session_module, "create_evidence_bundle", mutate_then_create
    )

    with pytest.raises(ValueError, match="exact report and log bytes validated"):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
        )

    assert session.record.state is LifecycleState.PLAN_APPROVED
