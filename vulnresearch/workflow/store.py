"""Append-only, hash-chained persistence for lifecycle audit events.

The JSONL store is tamper-evident, not tamper-proof. Protect it with normal
filesystem permissions and copy verified records to trusted archival storage.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from .._filesystem import fsync_directory
from ..jsonutil import loads_unique
from .lifecycle import (
    ActorRole,
    LifecycleRecord,
    LifecycleState,
    create_lifecycle,
    transition,
)

_SCHEMA_VERSION = "1.0"
_MAX_AUDIT_STORE_BYTES = 1024 * 1024

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
    # Build the store in a private sibling directory. Publish it with a
    # no-overwrite hard link only after the complete header is flushed to disk.
    # This avoids exposing a partial audit file and avoids unlinking a pathname
    # that an attacker may have replaced after an I/O failure.
    with tempfile.TemporaryDirectory(prefix=".audit-", dir=destination.parent) as staging:
        staged_path = Path(staging) / "store.jsonl"
        descriptor = os.open(
            staged_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            encoded_header = (json.dumps(header, sort_keys=True) + "\n").encode("utf-8")
            stream.write(encoded_header)
            stream.flush()
            os.fsync(stream.fileno())
        fsync_directory(staging)
        os.link(staged_path, destination)
    # Persist the published audit-store link and staging-directory cleanup.
    fsync_directory(destination.parent)
    return destination


def _read_verified(
    path: str | Path | None = None, *, descriptor: int | None = None
) -> tuple[LifecycleRecord, str]:
    """Verify a store from a path or an already-open descriptor."""
    owns_descriptor = descriptor is None
    if owns_descriptor:
        if path is None:
            raise ValueError("Lifecycle store path is required")
        try:
            descriptor = os.open(
                Path(path), os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
            )
        except OSError as exc:
            raise ValueError(f"Cannot read lifecycle store: {exc}") from exc
    assert descriptor is not None
    try:
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("Lifecycle store must be a regular file")
            os.lseek(descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            total = 0
            while total <= _MAX_AUDIT_STORE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(65536, _MAX_AUDIT_STORE_BYTES + 1 - total),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            encoded_store = b"".join(chunks)
        except OSError as exc:
            raise ValueError(f"Cannot read lifecycle store: {exc}") from exc
    finally:
        if owns_descriptor:
            os.close(descriptor)
    if len(encoded_store) > _MAX_AUDIT_STORE_BYTES:
        raise ValueError(
            f"Lifecycle store exceeds {_MAX_AUDIT_STORE_BYTES} bytes"
        )
    try:
        lines = encoded_store.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("Lifecycle store is not valid UTF-8") from exc
    if not lines:
        raise ValueError("Lifecycle store is empty")
    try:
        header = loads_unique(lines[0])
    except json.JSONDecodeError as exc:
        raise ValueError("Lifecycle store header is invalid JSON") from exc
    if not isinstance(header, dict) or header != _header(header.get("task_id", "")):
        raise ValueError("Lifecycle store header is invalid or unsupported")

    record = create_lifecycle(header["task_id"])
    previous_hash = _digest(header)
    for line_number, line in enumerate(lines[1:], start=2):
        try:
            entry = loads_unique(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid event JSON on line {line_number}") from exc
        if not isinstance(entry, dict):
            raise TypeError(f"Invalid event record on line {line_number}")
        allowed_fields = {
            "from_state", "to_state", "actor", "actor_role", "occurred_at",
            "evidence_refs", "decision_note", "previous_hash", "event_hash",
        }
        if set(entry) != allowed_fields:
            raise ValueError(f"Unsupported event fields on line {line_number}")
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
    """Validate and append the next event using one verified open file descriptor."""
    flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"Cannot open lifecycle store for append: {exc}") from exc
    try:
        stored, previous_hash = _read_verified(descriptor=descriptor)
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
        encoded = (
            json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Lifecycle store must be a regular file")
        if os.fstat(descriptor).st_size + len(encoded) > _MAX_AUDIT_STORE_BYTES:
            raise ValueError(f"Lifecycle store exceeds {_MAX_AUDIT_STORE_BYTES} bytes")
        original_size = os.fstat(descriptor).st_size
        try:
            remaining = memoryview(encoded)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("Lifecycle store append made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
        except BaseException:
            # A failed short write must not leave a truncated JSONL event behind.
            try:
                os.ftruncate(descriptor, original_size)
                os.fsync(descriptor)
            except OSError as rollback_error:
                raise OSError(
                    "Lifecycle store append failed and rollback could not be confirmed"
                ) from rollback_error
            raise
        return entry["event_hash"]
    finally:
        os.close(descriptor)
