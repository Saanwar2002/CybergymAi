from datetime import UTC, datetime, timedelta

import pytest

from vulnresearch.workflow.lifecycle import (
    ActorRole,
    LifecycleState,
    create_lifecycle,
    transition,
)


def move(record, target, role=ActorRole.SYSTEM, **kwargs):
    return transition(
        record,
        target,
        actor="test-actor",
        actor_role=role,
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC)
        + timedelta(seconds=len(record.events)),
        **kwargs,
    )


def test_full_lifecycle_requires_human_approval_and_records_audit_history():
    record = create_lifecycle("fixture/project-001")
    record = move(record, LifecycleState.TRIAGED)
    with pytest.raises(PermissionError, match="human"):
        move(record, LifecycleState.PLAN_APPROVED, ActorRole.AGENT)

    record = move(
        record,
        LifecycleState.PLAN_APPROVED,
        ActorRole.HUMAN,
        decision_note="Reviewed and approved the bounded plan.",
    )
    record = move(record, LifecycleState.REPRODUCTION_ATTEMPTED)
    record = move(
        record,
        LifecycleState.EVIDENCE_REVIEWED,
        ActorRole.HUMAN,
        evidence_refs=["artifact://run/123/stdout.txt"],
    )
    record = move(record, LifecycleState.PATCH_PROPOSED, ActorRole.AGENT)
    record = move(
        record,
        LifecycleState.PATCH_TESTED,
        evidence_refs=["artifact://run/patch-test/report.json"],
    )
    record = move(
        record,
        LifecycleState.HUMAN_ACCEPTED,
        ActorRole.HUMAN,
        evidence_refs=["artifact://run/123/report.json"],
        decision_note="Regression evidence reviewed; patch accepted.",
    )

    assert record.state is LifecycleState.HUMAN_ACCEPTED
    assert len(record.events) == 7
    assert record.events[1].actor_role is ActorRole.HUMAN
    assert record.events[-1].evidence_refs == ("artifact://run/123/report.json",)
    with pytest.raises(ValueError, match="Invalid lifecycle transition"):
        move(record, LifecycleState.TRIAGED)


def test_agent_cannot_self_approve_or_finalize():
    record = move(create_lifecycle("fixture/002"), LifecycleState.TRIAGED)
    with pytest.raises(PermissionError):
        move(
            record,
            LifecycleState.PLAN_APPROVED,
            ActorRole.AGENT,
            decision_note="Agent says approved.",
        )


def test_final_review_requires_note_and_evidence():
    record = create_lifecycle("fixture/003")
    record = move(record, LifecycleState.TRIAGED)
    record = move(
        record,
        LifecycleState.PLAN_APPROVED,
        ActorRole.HUMAN,
        decision_note="Approved.",
    )
    record = move(record, LifecycleState.REPRODUCTION_ATTEMPTED)
    record = move(
        record,
        LifecycleState.EVIDENCE_REVIEWED,
        ActorRole.HUMAN,
        evidence_refs=["artifact://run/003/stdout.txt"],
    )
    record = move(record, LifecycleState.PATCH_PROPOSED, ActorRole.AGENT)
    record = move(record, LifecycleState.PATCH_TESTED)

    with pytest.raises(ValueError, match="evidence"):
        move(
            record,
            LifecycleState.HUMAN_ACCEPTED,
            ActorRole.HUMAN,
            decision_note="Accepted.",
        )
    with pytest.raises(ValueError, match="decision note"):
        move(
            record,
            LifecycleState.HUMAN_REJECTED,
            ActorRole.HUMAN,
            evidence_refs=["artifact://report"],
        )


def test_invalid_timestamp_order_is_rejected():
    record = move(create_lifecycle("fixture/004"), LifecycleState.TRIAGED)
    with pytest.raises(ValueError, match="precede"):
        transition(
            record,
            LifecycleState.PLAN_APPROVED,
            actor="reviewer",
            actor_role=ActorRole.HUMAN,
            decision_note="Approved.",
            occurred_at=datetime(2025, 1, 1, tzinfo=UTC),
        )


def test_empty_task_identifier_is_rejected():
    with pytest.raises(ValueError, match="task_id"):
        create_lifecycle(" ")


def test_agent_cannot_claim_execution_or_test_completion():
    record = move(create_lifecycle("fixture/005"), LifecycleState.TRIAGED)
    record = move(
        record,
        LifecycleState.PLAN_APPROVED,
        ActorRole.HUMAN,
        decision_note="Approved.",
    )
    with pytest.raises(PermissionError, match="system"):
        move(record, LifecycleState.REPRODUCTION_ATTEMPTED, ActorRole.AGENT)


def test_evidence_review_requires_evidence_references():
    record = move(create_lifecycle("fixture/006"), LifecycleState.TRIAGED)
    record = move(
        record,
        LifecycleState.PLAN_APPROVED,
        ActorRole.HUMAN,
        decision_note="Approved.",
    )
    record = move(record, LifecycleState.REPRODUCTION_ATTEMPTED)
    with pytest.raises(ValueError, match="evidence"):
        move(record, LifecycleState.EVIDENCE_REVIEWED, ActorRole.HUMAN)
