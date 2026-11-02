"""Small orchestration facade for persisted, human-governed lifecycle sessions."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .lifecycle import (
    ActorRole,
    LifecycleRecord,
    LifecycleState,
    create_lifecycle,
    transition,
)
from .store import append_lifecycle_event, create_lifecycle_store, verify_lifecycle_store


@dataclass(frozen=True)
class WorkflowSession:
    """Immutable session view backed by a persisted lifecycle event store."""

    record: LifecycleRecord
    audit_path: Path

    @classmethod
    def create(cls, task_id: str, audit_path: str | Path) -> WorkflowSession:
        """Create a new workflow and its exclusive audit store."""
        path = create_lifecycle_store(task_id, audit_path)
        return cls(record=create_lifecycle(task_id), audit_path=path)

    @classmethod
    def open(cls, audit_path: str | Path) -> WorkflowSession:
        """Open a session only after verifying its complete persisted history."""
        path = Path(audit_path)
        record = verify_lifecycle_store(path)
        return cls(record=record, audit_path=path)

    def advance(
        self,
        target: LifecycleState,
        *,
        actor: str,
        actor_role: ActorRole,
        evidence_refs: tuple[str, ...] | list[str] = (),
        decision_note: str = "",
        occurred_at: datetime | None = None,
    ) -> WorkflowSession:
        """Validate and persist exactly one transition before returning a new view."""
        updated = transition(
            self.record,
            target,
            actor=actor,
            actor_role=actor_role,
            evidence_refs=evidence_refs,
            decision_note=decision_note,
            occurred_at=occurred_at,
        )
        append_lifecycle_event(self.audit_path, updated)
        return WorkflowSession(record=updated, audit_path=self.audit_path)
