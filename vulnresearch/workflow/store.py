"""Append-only, hash-chained persistence for lifecycle audit events.

The JSONL store is tamper-evident, not tamper-proof. Protect it with normal
filesystem permissions and copy verified records to trusted archival storage.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from .lifecycle import (
    ActorRole,
    LifecycleEvent,
    LifecycleRecord,
    LifecycleState,
    create_lifecycle,
    transition,
)

_SCHEMA_VERSION = "1.0"
_GENESIS = "0" * 64


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _header(task_id: str) -> dict[str, str]:
    return {
        "record_type": "header",
        "schema_version": _SCHEMA_VERSION,
        "task_id": task_id,
        "initial_state": LifecycleState.IMPORTED.value,
    }


def create_lifecycle_store(task_id: str, path: str | Path) -> Path:
    """Create a new private JSONL audit file; never overwrite an existing file."""
    record = create_lifecycle(task_id)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    header = _header(record.task_id)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(header, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return destination


def _read_verified(path: str | Path) -> tuple[LifecycleRecord, str]:
    source = Path(path)
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"Cannot read lifecycle store: {exc}") from exc
    if not lines:
        raise ValueError("Lifecycle store is empty")
    try:
        header = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise ValueError("Lifecycle store header is invalid JSON") from exc
    if not isinstance(header, dict) or header != _header(header.get("task_id", "")):
        raise ValueError("Lifecycle store header is invalid or unsupported")

    record = create_lifecycle(header["task_id"])
    previous_hash = _digest(header)
    for line_number, line in enumerate(lines[1:], start=2):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid event JSON on line {line_number}") from exc
        if not isinstance(entry, dict):
            raise ValueError(f"Invalid event record on line {line_number}")
        event_hash = entry.pop("event_hash", None)
        if entry.get("previous_hash") != previous_hash or event_hash != _digest(entry):
            raise ValueError(f"Audit hash-chain verification failed on line {line_number}")
        try:
            event = transition(
                record,
                LifecycleState(entry["to_state"]),
                actor=entry["actor"],
                actor_role=ActorRole(entry["actor_role"]),
                evidence_refs=entry["evidence_refs"],
                decision_note=entry["decision_note"],
                occurred_at=datetime.fromisoformat(entry["occurred_at"]),
            ).events[-1]
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            raise ValueError(f"Invalid lifecycle event on line {line_number}: {exc}") from exc
        expected = {
            "from_state": event.from_state.value,
            "to_state": event.to_state.value,
            "actor": event.actor,
            "actor_role": event.actor_role.value,
            "occurred_at": event.occurred_at,
            "evidence_refs": list(event.evidence_refs),
            "decision_note": event.decision_note,
        }
        actual = {key: entry.get(key) for key in expected}
        if actual != expected:
            raise ValueError(f"Lifecycle event validation failed on line {line_number}")
        record = LifecycleRecord(
            task_id=record.task_id,
            state=event.to_state,
            events=(*record.events, event),
        )
        previous_hash = event_hash
    return record, previous_hash


def verify_lifecycle_store(path: str | Path) -> LifecycleRecord:
    """Read and validate the complete event chain and all lifecycle transitions."""
    return _read_verified(path)[0]


def append_lifecycle_event(path: str | Path, record: LifecycleRecord) -> str:
    """Append exactly the next valid event from a newer immutable lifecycle record."""
    stored, previous_hash = _read_verified(path)
    if record.task_id != stored.task_id:
        raise ValueError("Lifecycle task_id does not match the audit store")
    if len(record.events) != len(stored.events) + 1:
        raise ValueError("Append requires exactly one new lifecycle event")
    if record.events[:-1] != stored.events:
        raise ValueError("Lifecycle record does not extend the stored event history")
    event = record.events[-1]
    try:
        validated_event = transition(
            stored,
            event.to_state,
            actor=event.actor,
            actor_role=event.actor_role,
            evidence_refs=event.evidence_refs,
            decision_note=event.decision_note,
            occurred_at=datetime.fromisoformat(event.occurred_at),
        ).events[-1]
    except (TypeError, ValueError, PermissionError) as exc:
        raise ValueError(f"New lifecycle event is invalid: {exc}") from exc
    if validated_event != event:
        raise ValueError("New lifecycle event does not match validated transition data")
    payload: dict[str, Any] = {
        "from_state": event.from_state.value,
        "to_state": event.to_state.value,
        "actor": event.actor,
        "actor_role": event.actor_role.value,
        "occurred_at": event.occurred_at,
        "evidence_refs": list(event.evidence_refs),
        "decision_note": event.decision_note,
        "previous_hash": previous_hash,
    }
    entry = {**payload, "event_hash": _digest(payload)}
    encoded = (json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        raise
    return entry["event_hash"]
