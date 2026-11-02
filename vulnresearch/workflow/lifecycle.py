"""Auditable, human-governed CyberGym-E2E-style lifecycle transitions.

This module records workflow decisions only. It does not execute benchmark code,
generate proof-of-concept inputs, apply patches, or invoke external services.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


class LifecycleState(StrEnum):
    """States in the defensive research and patch-review lifecycle."""

    IMPORTED = "imported"
    TRIAGED = "triaged"
    PLAN_APPROVED = "plan_approved"
    REPRODUCTION_ATTEMPTED = "reproduction_attempted"
    EVIDENCE_REVIEWED = "evidence_reviewed"
    PATCH_PROPOSED = "patch_proposed"
    PATCH_TESTED = "patch_tested"
    HUMAN_ACCEPTED = "human_accepted"
    HUMAN_REJECTED = "human_rejected"
    INCONCLUSIVE = "inconclusive"


class ActorRole(StrEnum):
    """Roles used for authorization of lifecycle transitions."""

    HUMAN = "human"
    AGENT = "agent"
    SYSTEM = "system"


@dataclass(frozen=True)
class LifecycleEvent:
    """Immutable audit event for one state transition."""

    from_state: LifecycleState
    to_state: LifecycleState
    actor: str
    actor_role: ActorRole
    occurred_at: str
    evidence_refs: tuple[str, ...] = ()
    decision_note: str = ""


@dataclass(frozen=True)
class LifecycleRecord:
    """Current lifecycle state and append-only transition history."""

    task_id: str
    state: LifecycleState = LifecycleState.IMPORTED
    events: tuple[LifecycleEvent, ...] = ()


_TRANSITIONS: dict[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.IMPORTED: frozenset({LifecycleState.TRIAGED}),
    LifecycleState.TRIAGED: frozenset({LifecycleState.PLAN_APPROVED}),
    LifecycleState.PLAN_APPROVED: frozenset(
        {LifecycleState.REPRODUCTION_ATTEMPTED}
    ),
    LifecycleState.REPRODUCTION_ATTEMPTED: frozenset(
        {LifecycleState.EVIDENCE_REVIEWED}
    ),
    LifecycleState.EVIDENCE_REVIEWED: frozenset(
        {LifecycleState.PATCH_PROPOSED, LifecycleState.INCONCLUSIVE}
    ),
    LifecycleState.PATCH_PROPOSED: frozenset({LifecycleState.PATCH_TESTED}),
    LifecycleState.PATCH_TESTED: frozenset(
        {
            LifecycleState.HUMAN_ACCEPTED,
            LifecycleState.HUMAN_REJECTED,
            LifecycleState.INCONCLUSIVE,
        }
    ),
    LifecycleState.HUMAN_ACCEPTED: frozenset(),
    LifecycleState.HUMAN_REJECTED: frozenset(),
    LifecycleState.INCONCLUSIVE: frozenset(),
}

_ALLOWED_ROLES: dict[LifecycleState, frozenset[ActorRole]] = {
    LifecycleState.TRIAGED: frozenset({ActorRole.HUMAN, ActorRole.SYSTEM}),
    LifecycleState.PLAN_APPROVED: frozenset({ActorRole.HUMAN}),
    LifecycleState.REPRODUCTION_ATTEMPTED: frozenset({ActorRole.SYSTEM}),
    LifecycleState.EVIDENCE_REVIEWED: frozenset({ActorRole.HUMAN}),
    LifecycleState.PATCH_PROPOSED: frozenset({ActorRole.HUMAN, ActorRole.AGENT}),
    LifecycleState.PATCH_TESTED: frozenset({ActorRole.SYSTEM}),
    LifecycleState.HUMAN_ACCEPTED: frozenset({ActorRole.HUMAN}),
    LifecycleState.HUMAN_REJECTED: frozenset({ActorRole.HUMAN}),
    LifecycleState.INCONCLUSIVE: frozenset({ActorRole.HUMAN}),
}


def create_lifecycle(task_id: str) -> LifecycleRecord:
    """Create a new record in the imported state."""
    if not isinstance(task_id, str) or not task_id.strip():
        raise ValueError("task_id must be a non-empty string")
    return LifecycleRecord(task_id=task_id)


def transition(
    record: LifecycleRecord,
    target: LifecycleState,
    *,
    actor: str,
    actor_role: ActorRole,
    evidence_refs: tuple[str, ...] | list[str] = (),
    decision_note: str = "",
    occurred_at: datetime | None = None,
) -> LifecycleRecord:
    """Return a new record after validating and appending one audit event."""
    if not isinstance(target, LifecycleState):
        raise TypeError("target must be a LifecycleState")
    if not isinstance(actor_role, ActorRole):
        raise TypeError("actor_role must be an ActorRole")
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor must be a non-empty identifier")
    if not isinstance(decision_note, str):
        raise TypeError("decision_note must be a string")
    if not isinstance(evidence_refs, (tuple, list)) or any(
        not isinstance(ref, str) or not ref.strip() for ref in evidence_refs
    ):
        raise ValueError("evidence_refs must contain non-empty strings")
    if target not in _TRANSITIONS[record.state]:
        raise ValueError(
            f"Invalid lifecycle transition: {record.state.value} -> {target.value}"
        )
    if actor_role not in _ALLOWED_ROLES[target]:
        required = ", ".join(sorted(role.value for role in _ALLOWED_ROLES[target]))
        raise PermissionError(
            f"Transition to {target.value} requires actor role: {required}"
        )
    if target is LifecycleState.EVIDENCE_REVIEWED and not evidence_refs:
        raise ValueError("evidence review requires evidence references")
    if target is LifecycleState.PATCH_TESTED and not evidence_refs:
        raise ValueError("patch testing requires evidence references")
    if target is LifecycleState.PLAN_APPROVED and not decision_note.strip():
        raise ValueError("plan approval requires a human decision note")
    if target in {LifecycleState.HUMAN_ACCEPTED, LifecycleState.HUMAN_REJECTED}:
        if not decision_note.strip():
            raise ValueError("final human review requires a decision note")
        if not evidence_refs:
            raise ValueError("final human review requires evidence references")

    timestamp = occurred_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("occurred_at must be timezone-aware")
    if record.events:
        previous_time = datetime.fromisoformat(record.events[-1].occurred_at)
        if timestamp < previous_time:
            raise ValueError("occurred_at cannot precede the previous audit event")

    event = LifecycleEvent(
        from_state=record.state,
        to_state=target,
        actor=actor.strip(),
        actor_role=actor_role,
        occurred_at=timestamp.astimezone(UTC).isoformat(),
        evidence_refs=tuple(evidence_refs),
        decision_note=decision_note.strip(),
    )
    return LifecycleRecord(
        task_id=record.task_id,
        state=target,
        events=(*record.events, event),
    )
