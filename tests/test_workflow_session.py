import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

import vulnresearch.execution.security as security_module
from vulnresearch.execution import (
    BackendCapabilities,
    BackendResult,
    ExecutionLimits,
    ExecutionRequirements,
    ExecutionSpec,
    ExecutionStatus,
    IsolationLevel,
    SecurityReviewApproval,
    backend_capabilities_sha256,
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
        evidence_refs=[reproduction_ref],
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
        "duration_seconds": 0.1,
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


class AllowTestReview:
    """Test-only verifier; not suitable for a deployment trust boundary."""

    def verify(self, approval):
        return True


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
    capabilities = BackendCapabilities(
        isolation_level=IsolationLevel.DISPOSABLE_VM,
        network_isolated=True,
        immutable_guest_image=True,
        isolated_storage=True,
        bounded_input_output=True,
        resource_limits=True,
        cleanup_verification=True,
        host_docker_socket_isolated=True,
    )
    now = datetime.now(UTC)
    approval = SecurityReviewApproval(
        review_id="workflow-review-fixture",
        reviewer_id="independent-reviewer",
        reviewer_organization="External Security Review Group",
        scope="benchmark_execution",
        reviewed_commit_sha="a" * 40,
        execution_spec_sha256=spec.manifest_sha256,
        backend_capabilities_sha256=backend_capabilities_sha256(capabilities),
        evidence_sha256="e" * 64,
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(days=1),
        signature="test-only-signature",
    )
    return write_benchmark_run_report(
        spec,
        result,
        backend_capabilities=capabilities,
        security_review=approval,
        output_dir=artifacts / "runs",
    )


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
        review_verifier=AllowTestReview(),
        software_commit_sha="a" * 40,
    )

    assert updated.record.state is LifecycleState.REPRODUCTION_ATTEMPTED
    evidence_ref = updated.record.events[-1].evidence_refs[0]
    bundle = artifacts / "bundles" / "reproduction.json"
    bundle_digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert evidence_ref == f"bundle:bundles/reproduction.json#sha256={bundle_digest}"
    assert updated.record.events[-1].actor == "benchmark-runner"
    assert updated.record.events[-1].actor_role is ActorRole.SYSTEM
    assert "benchmark-run-001" in updated.record.events[-1].decision_note
    manifest = verify_evidence_bundle(bundle, artifact_root=artifacts)
    assert set(manifest["artifacts"]) == {"report", "stdout", "stderr"}
    assert WorkflowSession.open(updated.audit_path).record == updated.record


def test_benchmark_lifecycle_requires_trusted_review_verifier(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    report_path = _benchmark_report(artifacts, "benchmark-review-required-001")
    session = _plan_approved_session(tmp_path, "benchmark-review-required-001")

    with pytest.raises(
        ValueError,
        match="no trusted independent-review verifier",
    ):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
            software_commit_sha="a" * 40,
        )

    assert session.record.state is LifecycleState.PLAN_APPROVED
    assert not (artifacts / "bundles").exists()


def test_benchmark_lifecycle_rejects_approval_expiring_during_verifier(
    tmp_path, monkeypatch
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "benchmark-review-expiry-race"
    report_path = _benchmark_report(artifacts, task_id)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    started = datetime.now(UTC)
    report["security_review"]["issued_at"] = (
        started - timedelta(seconds=1)
    ).isoformat()
    report["security_review"]["expires_at"] = (
        started + timedelta(seconds=1)
    ).isoformat()
    report_path.write_text(json.dumps(report), encoding="utf-8")
    session = _plan_approved_session(tmp_path, task_id)
    initial_record = session.record
    clock_values = iter((started, started + timedelta(seconds=2)))

    class ControlledClock(datetime):
        @classmethod
        def now(cls, _tz):
            return next(clock_values)

    class SuccessfulVerifier:
        def __init__(self):
            self.calls = 0

        def verify(self, _approval):
            self.calls += 1
            return True

    verifier = SuccessfulVerifier()
    monkeypatch.setattr(security_module, "datetime", ControlledClock)

    with pytest.raises(
        ValueError,
        match="expired during independent verification",
    ):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
            review_verifier=verifier,
            software_commit_sha="a" * 40,
        )

    assert verifier.calls == 1
    assert session.record.state is LifecycleState.PLAN_APPROVED
    assert session.record == initial_record
    assert not (artifacts / "bundles").exists()


def test_benchmark_lifecycle_rejects_approval_expiring_before_reproduction_record(
    tmp_path, monkeypatch
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "benchmark-review-expiry-before-record"
    report_path = _benchmark_report(artifacts, task_id)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    started = datetime.now(UTC)
    report["security_review"]["issued_at"] = (
        started - timedelta(seconds=1)
    ).isoformat()
    report["security_review"]["expires_at"] = (
        started + timedelta(seconds=1)
    ).isoformat()
    report_path.write_text(json.dumps(report), encoding="utf-8")
    session = _plan_approved_session(tmp_path, task_id)
    initial_record = session.record
    clock_values = iter(
        (
            started,
            started + timedelta(milliseconds=500),
            started + timedelta(seconds=2),
        )
    )

    class ControlledClock(datetime):
        @classmethod
        def now(cls, _tz):
            return next(clock_values)

    class SuccessfulVerifier:
        def verify(self, _approval):
            return True

    monkeypatch.setattr(security_module, "datetime", ControlledClock)

    with pytest.raises(
        ValueError,
        match="expired before reproduction lifecycle recording",
    ):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
            review_verifier=SuccessfulVerifier(),
            software_commit_sha="a" * 40,
        )

    assert session.record == initial_record
    assert (artifacts / "bundles" / "reproduction.json").is_file()


def test_benchmark_patch_test_rejects_approval_expiring_before_lifecycle_record(
    tmp_path, monkeypatch
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "benchmark-patch-review-expiry-before-record"
    session = _plan_approved_session(tmp_path, task_id)
    session = session.advance(
        LifecycleState.REPRODUCTION_ATTEMPTED,
        actor="runner",
        actor_role=ActorRole.SYSTEM,
        evidence_refs=["bundle:reproduction.json"],
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
    initial_record = session.record
    report_path = _benchmark_report(artifacts, task_id)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    started = datetime.now(UTC)
    report["security_review"]["issued_at"] = (
        started - timedelta(seconds=1)
    ).isoformat()
    report["security_review"]["expires_at"] = (
        started + timedelta(seconds=1)
    ).isoformat()
    report_path.write_text(json.dumps(report), encoding="utf-8")
    clock_values = iter(
        (
            started,
            started + timedelta(milliseconds=500),
            started + timedelta(seconds=2),
        )
    )

    class ControlledClock(datetime):
        @classmethod
        def now(cls, _tz):
            return next(clock_values)

    class SuccessfulVerifier:
        def verify(self, _approval):
            return True

    monkeypatch.setattr(security_module, "datetime", ControlledClock)

    with pytest.raises(
        ValueError,
        match="expired before benchmark patch-test lifecycle recording",
    ):
        session.record_benchmark_patch_test(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/benchmark-patch-test.json",
            review_verifier=SuccessfulVerifier(),
            software_commit_sha="a" * 40,
        )

    assert session.record == initial_record
    assert (artifacts / "bundles" / "benchmark-patch-test.json").is_file()


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
            review_verifier=AllowTestReview(),
            software_commit_sha="a" * 40,
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
        evidence_refs=["bundle:reproduction.json"],
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
        review_verifier=AllowTestReview(),
        software_commit_sha="a" * 40,
    )

    assert updated.record.state is LifecycleState.PATCH_TESTED
    assert updated.record.events[-1].actor == "benchmark-runner"
    assert updated.record.events[-1].actor_role is ActorRole.SYSTEM
    assert updated.record.events[-1].decision_note.startswith(
        "Benchmark patch regression run succeeded"
    )
    evidence_ref = updated.record.events[-1].evidence_refs[0]
    bundle = artifacts / "bundles" / "benchmark-patch-test.json"
    bundle_digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert evidence_ref == (
        f"bundle:bundles/benchmark-patch-test.json#sha256={bundle_digest}"
    )
    manifest = verify_evidence_bundle(bundle, artifact_root=artifacts)
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
        evidence_refs=["bundle:reproduction.json"],
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
            review_verifier=AllowTestReview(),
            software_commit_sha="a" * 40,
        )

    assert session.record.state is LifecycleState.PATCH_PROPOSED
    assert not (artifacts / "bundles" / "benchmark-patch-test.json").exists()


@pytest.mark.parametrize("changed_artifact", ["report", "stdout", "stderr"])
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
            else report_path.parent / f"{changed_artifact}.txt"
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
            review_verifier=AllowTestReview(),
            software_commit_sha="a" * 40,
        )

    assert session.record.state is LifecycleState.PLAN_APPROVED


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda report: report.update(backend_status="failed"),
            "status does not match backend_status",
        ),
        (
            lambda report: report.update(
                backend_status="blocked", status="failed", exit_code=1
            ),
            "blocked benchmark reports cannot have a process exit_code",
        ),
        (
            lambda report: report["resource_usage"].update(
                peak_memory_bytes=report["execution_spec"]["limits"]["memory_bytes"] + 1
            ),
            "resource_usage peak_memory_bytes",
        ),
        (
            lambda report: report["resource_usage"].update(input_bytes_staged=1),
            "input_bytes_staged does not match",
        ),
        (
            lambda report: report["output_artifacts"].append(
                {
                    "artifact_id": "bad-output",
                    "sha256": "not-a-digest",
                    "size_bytes": 1,
                    "guest_path": "../escape",
                }
            ),
            "invalid output artifact",
        ),
        (
            lambda report: report.update(duration_seconds=float("nan")),
            "duration_seconds is invalid",
        ),
        (
            lambda report: report.update(
                duration_seconds=report["execution_spec"]["timeout_seconds"] + 1
            ),
            "exceeds the approved execution timeout",
        ),
    ],
)
def test_benchmark_execution_rejects_inconsistent_report_semantics(
    tmp_path, mutation, message
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "benchmark-report-semantics"
    report_path = _benchmark_report(artifacts, task_id)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    mutation(report)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    session = _plan_approved_session(tmp_path, task_id)

    with pytest.raises(ValueError, match=message):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
        )

    assert session.record.state is LifecycleState.PLAN_APPROVED
    assert not (artifacts / "bundles").exists()


def test_benchmark_execution_rejects_aggregate_output_over_spec_limit(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "benchmark-report-output-limit"
    report_path = _benchmark_report(artifacts, task_id)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["output_artifacts"] = [
        {
            "artifact_id": "large-output",
            "sha256": "a" * 64,
            "size_bytes": 2 * 1024 * 1024 + 1,
            "guest_path": "results/output.bin",
        }
    ]
    report_path.write_text(json.dumps(report), encoding="utf-8")
    session = _plan_approved_session(tmp_path, task_id)

    with pytest.raises(ValueError, match="output artifacts exceed the aggregate limit"):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
        )

    assert session.record.state is LifecycleState.PLAN_APPROVED


@pytest.mark.parametrize("changed_stream", ["stdout", "stderr"])
def test_patch_test_rejects_log_mutated_after_bundle_verification(
    tmp_path, monkeypatch, changed_stream
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "fixture-log-mutated-after-verify"
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
    original_read = session_module.read_evidence_artifact
    report_relative = report_path.relative_to(artifacts).as_posix()
    stream_path = report_path.parent / f"{changed_stream}.txt"

    def read_report_then_mutate_log(root, relative_path, *, limit=5 * 1024 * 1024):
        content = original_read(root, relative_path, limit=limit)
        if relative_path == report_relative:
            stream_path.write_text("mutated after verification\\n", encoding="utf-8")
        return content

    monkeypatch.setattr(
        session_module, "read_evidence_artifact", read_report_then_mutate_log
    )

    with pytest.raises(
        ValueError,
        match=f"{changed_stream} integrity check failed after bundle verification",
    ):
        session.record_patch_test(bundle, artifact_root=artifacts)

    assert session.record.state is LifecycleState.IMPORTED


def test_benchmark_execution_rejects_stream_above_approved_per_stream_limit(
    tmp_path,
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "benchmark-report-stream-limit"
    report_path = _benchmark_report(artifacts, task_id)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    oversized_stdout = b"x" * (
        report["execution_spec"]["max_output_bytes_per_stream"] + 1
    )
    stdout_path = report_path.parent / "stdout.txt"
    stdout_path.write_bytes(oversized_stdout)
    report["artifacts"]["stdout"].update(
        sha256=hashlib.sha256(oversized_stdout).hexdigest(),
        size_bytes=len(oversized_stdout),
        truncated=False,
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")
    session = _plan_approved_session(tmp_path, task_id)

    with pytest.raises(
        ValueError,
        match="exceeds the approved per-stream output limit",
    ):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
        )

    assert session.record.state is LifecycleState.PLAN_APPROVED
    assert not (artifacts / "bundles").exists()


def test_patch_test_rejects_local_stream_above_report_writer_limit(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "fixture-report-stream-limit"
    task = _research_task(tmp_path, task_id)
    report_path = write_run_report(
        task,
        SandboxResult(0, "ok", "", False, False, 0.1),
        artifacts / "runs",
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    oversized_stdout = b"x" * (1024 * 1024 + 1)
    stdout_path = report_path.parent / "stdout.txt"
    stdout_path.write_bytes(oversized_stdout)
    report["artifacts"]["stdout"].update(
        sha256=hashlib.sha256(oversized_stdout).hexdigest(),
        size_bytes=len(oversized_stdout),
        truncated=False,
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")
    bundle = create_evidence_bundle(
        task_id,
        {
            "report": report_path.relative_to(artifacts).as_posix(),
            "stdout": stdout_path.relative_to(artifacts).as_posix(),
            "stderr": (report_path.parent / "stderr.txt").relative_to(artifacts).as_posix(),
        },
        artifact_root=artifacts,
        output_path=artifacts / "bundles" / "patch-test.json",
    )
    session = WorkflowSession.create(task_id, tmp_path / "audit.jsonl")

    with pytest.raises(
        ValueError,
        match="exceeds the local report stream limit",
    ):
        session.record_patch_test(bundle, artifact_root=artifacts)

    assert session.record.state is LifecycleState.IMPORTED


def test_patch_test_rejects_bundle_replaced_between_validation_and_reference_pin(
    tmp_path, monkeypatch
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "fixture-bundle-replaced-before-pin"
    stdout = artifacts / "stdout.txt"
    stderr = artifacts / "stderr.txt"
    stdout.write_text("passed\\n", encoding="utf-8")
    stderr.write_text("", encoding="utf-8")
    report = {
        "schema_version": "1.0",
        "run_id": "fixture-run-001",
        "task_id": task_id,
        "status": "succeeded",
        "exit_code": 0,
        "duration_seconds": 0.1,
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
    (artifacts / "report.json").write_text(json.dumps(report), encoding="utf-8")
    bundle = create_evidence_bundle(
        task_id,
        {"report": "report.json", "stdout": "stdout.txt", "stderr": "stderr.txt"},
        artifact_root=artifacts,
        output_path=artifacts / "bundles" / "patch-test.json",
    )
    session = WorkflowSession.create(task_id, tmp_path / "audit.jsonl")
    original_verify_reference = session_module.verify_evidence_reference

    def replace_bundle_then_verify(reference, *, artifact_root):
        replacement = json.loads(bundle.read_text(encoding="utf-8"))
        replacement["created_at"] = "2026-11-03T00:00:00+00:00"
        bundle.write_text(
            json.dumps(replacement, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return original_verify_reference(reference, artifact_root=artifact_root)

    monkeypatch.setattr(
        session_module, "verify_evidence_reference", replace_bundle_then_verify
    )

    with pytest.raises(ValueError, match="reference SHA-256 mismatch"):
        session.record_patch_test(bundle, artifact_root=artifacts)

    assert session.record.state is LifecycleState.IMPORTED
    assert not session.record.events


def test_patch_test_rejects_non_finite_report_duration(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "fixture-report-invalid-duration"
    task = _research_task(tmp_path, task_id)
    report_path = write_run_report(
        task,
        SandboxResult(0, "passed\\n", "", False, False, 0.1),
        artifacts / "runs",
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["duration_seconds"] = float("nan")
    report_path.write_text(json.dumps(report), encoding="utf-8")
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

    with pytest.raises(ValueError, match="duration_seconds is invalid"):
        session.record_patch_test(bundle, artifact_root=artifacts)

    assert session.record.state is LifecycleState.IMPORTED
    assert not session.record.events


def test_benchmark_patch_test_rejects_bundle_replacement_before_generic_ingestion(
    tmp_path, monkeypatch
):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    task_id = "benchmark-patch-bundle-swap"
    session = _plan_approved_session(tmp_path, task_id)
    session = session.advance(
        LifecycleState.REPRODUCTION_ATTEMPTED,
        actor="runner",
        actor_role=ActorRole.SYSTEM,
        evidence_refs=["bundle:reproduction.json"],
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
    bundle = artifacts / "bundles" / "benchmark-patch-test.json"
    original_verify = session_module.verify_evidence_bundle
    calls = 0

    def replace_bundle_before_patch_ingestion(path, *, artifact_root):
        nonlocal calls
        calls += 1
        if calls == 2:
            (artifacts / "replacement-stdout.txt").write_text(
                "replacement passed\\n", encoding="utf-8"
            )
            (artifacts / "replacement-stderr.txt").write_text("", encoding="utf-8")
            replacement_report = {
                "schema_version": "1.0",
                "task_id": task_id,
                "run_id": "unvalidated-replacement",
                "status": "succeeded",
                "exit_code": 0,
                "duration_seconds": 0.1,
                "artifacts": {
                    "stdout": {
                        "path": "stdout.txt",
                        "sha256": hashlib.sha256(
                            (artifacts / "replacement-stdout.txt").read_bytes()
                        ).hexdigest(),
                        "size_bytes": (artifacts / "replacement-stdout.txt").stat().st_size,
                        "truncated": False,
                    },
                    "stderr": {
                        "path": "stderr.txt",
                        "sha256": hashlib.sha256(
                            (artifacts / "replacement-stderr.txt").read_bytes()
                        ).hexdigest(),
                        "size_bytes": (artifacts / "replacement-stderr.txt").stat().st_size,
                        "truncated": False,
                    },
                },
            }
            (artifacts / "replacement-report.json").write_text(
                json.dumps(replacement_report), encoding="utf-8"
            )
            bundle.unlink()
            create_evidence_bundle(
                task_id,
                {
                    "report": "replacement-report.json",
                    "stdout": "replacement-stdout.txt",
                    "stderr": "replacement-stderr.txt",
                },
                artifact_root=artifacts,
                output_path=bundle,
            )
        return original_verify(path, artifact_root=artifact_root)

    monkeypatch.setattr(
        session_module, "verify_evidence_bundle", replace_bundle_before_patch_ingestion
    )

    with pytest.raises(
        ValueError,
        match="changed after benchmark report validation",
    ):
        session.record_benchmark_patch_test(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/benchmark-patch-test.json",
            review_verifier=AllowTestReview(),
            software_commit_sha="a" * 40,
        )

    assert calls == 2
    assert session.record.state is LifecycleState.PATCH_PROPOSED
    assert session.record.events[-1].to_state is LifecycleState.PATCH_PROPOSED


def test_public_patch_test_api_cannot_select_benchmark_ingestion_mode(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    session = WorkflowSession.create(
        "benchmark-ingestion-mode-private", tmp_path / "audit.jsonl"
    )

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        session.record_patch_test(
            "missing/bundle.json",
            artifact_root=artifacts,
            run_kind="benchmark",
        )

    assert session.record.state is LifecycleState.IMPORTED
    assert not session.record.events


def test_benchmark_lifecycle_rejects_downgraded_backend_capability_claims(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    report_path = _benchmark_report(artifacts, "benchmark-capability-001")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["backend_capabilities"]["isolation_level"] = "container"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    session = _plan_approved_session(tmp_path, "benchmark-capability-001")

    with pytest.raises(ValueError, match="backend capability claims do not satisfy"):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
        )

    assert session.record.state is LifecycleState.PLAN_APPROVED
    assert not (artifacts / "bundles").exists()


def test_benchmark_execution_actor_cannot_be_overridden_by_caller(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    report_path = _benchmark_report(artifacts, "benchmark-actor-override-001")
    session = _plan_approved_session(tmp_path, "benchmark-actor-override-001")

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        session.record_benchmark_execution(
            report_path.relative_to(artifacts),
            artifact_root=artifacts,
            bundle_path="bundles/reproduction.json",
            actor="independent-reviewer",
            review_verifier=AllowTestReview(),
            software_commit_sha="a" * 40,
        )

    assert session.record.state is LifecycleState.PLAN_APPROVED
    assert not (artifacts / "bundles").exists()


def test_public_advance_cannot_forge_patch_test_completion(tmp_path):
    session = WorkflowSession.create(
        "patch-test-transition-bypass", tmp_path / "audit.jsonl"
    )

    with pytest.raises(
        PermissionError,
        match="must be recorded through verified patch-test evidence ingestion",
    ):
        session.advance(
            LifecycleState.PATCH_TESTED,
            actor="forged-runner",
            actor_role=ActorRole.SYSTEM,
            evidence_refs=["bundle:forged-report.json"],
            decision_note="Claimed tests passed without report validation.",
        )

    assert session.record.state is LifecycleState.IMPORTED
    assert not session.record.events
