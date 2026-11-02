from datetime import UTC, datetime

from vulnresearch.workflow.evidence import (
    create_evidence_bundle,
    verify_evidence_bundle,
)
from vulnresearch.workflow.lifecycle import ActorRole, LifecycleState
from vulnresearch.workflow.session import WorkflowSession


def test_complete_harmless_fixture_workflow_round_trips_with_evidence(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "stdout.txt").write_text("fixture reproduced\n", encoding="utf-8")
    (artifacts / "report.json").write_text(
        '{"status":"passed"}\n', encoding="utf-8"
    )
    bundle_path = create_evidence_bundle(
        "fixture-e2e-001",
        {"stdout": "stdout.txt", "report": "report.json"},
        artifact_root=artifacts,
        output_path=artifacts / "bundles" / "fixture-e2e-001.json",
    )
    verify_evidence_bundle(bundle_path, artifact_root=artifacts)
    evidence_ref = f"bundle:{bundle_path.relative_to(artifacts).as_posix()}"

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
        evidence_refs=[evidence_ref],
    )
    session = session.advance(
        LifecycleState.PATCH_PROPOSED,
        actor="agent",
        actor_role=ActorRole.AGENT,
        evidence_refs=[evidence_ref],
        decision_note="Proposed a defensive regression-test change.",
    )
    session = session.advance(
        LifecycleState.PATCH_TESTED,
        actor="runner",
        actor_role=ActorRole.SYSTEM,
    )
    session = session.advance(
        LifecycleState.HUMAN_ACCEPTED,
        actor="maintainer",
        actor_role=ActorRole.HUMAN,
        evidence_refs=[evidence_ref],
        decision_note="Reviewed the fixture report and accepted the result.",
    )

    reopened = WorkflowSession.open(session.audit_path)
    assert reopened.record == session.record
    assert reopened.record.state is LifecycleState.HUMAN_ACCEPTED
    assert len(reopened.record.events) == 7
    assert reopened.record.events[-1].occurred_at == datetime.now(UTC).isoformat() or (
        reopened.record.events[-1].occurred_at.endswith("+00:00")
    )
