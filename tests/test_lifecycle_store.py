import json
from datetime import UTC, datetime

import pytest

from vulnresearch.workflow.lifecycle import (
    ActorRole,
    LifecycleState,
    create_lifecycle,
    transition,
)
from vulnresearch.workflow.store import (
    append_lifecycle_event,
    create_lifecycle_store,
    verify_lifecycle_store,
)


def _transition(record, state, role=ActorRole.SYSTEM, **kwargs):
    return transition(
        record,
        state,
        actor="test",
        actor_role=role,
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
        **kwargs,
    )


def test_store_round_trips_and_appends_a_valid_chain(tmp_path):
    path = create_lifecycle_store("fixture/store-001", tmp_path / "audit.jsonl")
    record = create_lifecycle("fixture/store-001")
    record = _transition(record, LifecycleState.TRIAGED)
    append_lifecycle_event(path, record)
    record = _transition(
        record,
        LifecycleState.PLAN_APPROVED,
        ActorRole.HUMAN,
        decision_note="Approved after review.",
    )
    append_lifecycle_event(path, record)

    loaded = verify_lifecycle_store(path)
    assert loaded == record
    assert len(loaded.events) == 2


def test_store_refuses_overwrite_and_task_mismatch(tmp_path):
    path = create_lifecycle_store("fixture/store-002", tmp_path / "audit.jsonl")
    with pytest.raises(FileExistsError):
        create_lifecycle_store("fixture/store-002", path)

    record = _transition(
        create_lifecycle("fixture/other"),
        LifecycleState.TRIAGED,
    )
    with pytest.raises(ValueError, match="task_id"):
        append_lifecycle_event(path, record)


def test_store_rejects_modified_event(tmp_path):
    path = create_lifecycle_store("fixture/store-003", tmp_path / "audit.jsonl")
    record = _transition(create_lifecycle("fixture/store-003"), LifecycleState.TRIAGED)
    append_lifecycle_event(path, record)

    lines = path.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[1])
    event["actor"] = "tampered"
    lines[1] = json.dumps(event)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="hash-chain"):
        verify_lifecycle_store(path)


def test_store_requires_exactly_one_new_event(tmp_path):
    path = create_lifecycle_store("fixture/store-004", tmp_path / "audit.jsonl")
    record = _transition(create_lifecycle("fixture/store-004"), LifecycleState.TRIAGED)
    record = _transition(
        record,
        LifecycleState.PLAN_APPROVED,
        ActorRole.HUMAN,
        decision_note="Approved.",
    )
    with pytest.raises(ValueError, match="exactly one"):
        append_lifecycle_event(path, record)


def test_store_rejects_forged_event_not_created_by_transition(tmp_path):
    from dataclasses import replace

    path = create_lifecycle_store("fixture/store-005", tmp_path / "audit.jsonl")
    record = _transition(create_lifecycle("fixture/store-005"), LifecycleState.TRIAGED)
    forged_event = replace(record.events[-1], actor_role=ActorRole.AGENT)
    forged_record = replace(record, events=(forged_event,))

    with pytest.raises(ValueError, match="invalid"):
        append_lifecycle_event(path, forged_record)


def test_store_rejects_unknown_event_fields(tmp_path):
    path = create_lifecycle_store("fixture/store-006", tmp_path / "audit.jsonl")
    record = _transition(create_lifecycle("fixture/store-006"), LifecycleState.TRIAGED)
    append_lifecycle_event(path, record)

    lines = path.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[1])
    event["unreviewed_extension"] = "ignored?"
    lines[1] = json.dumps(event)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported event fields"):
        verify_lifecycle_store(path)


def test_store_rejects_symlink_paths(tmp_path):
    target = create_lifecycle_store("fixture/store-007", tmp_path / "real.jsonl")
    link = tmp_path / "linked.jsonl"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="Cannot read"):
        verify_lifecycle_store(link)


def test_store_rejects_duplicate_json_event_keys(tmp_path):
    path = create_lifecycle_store("fixture/store-duplicate", tmp_path / "audit.jsonl")
    record = _transition(
        create_lifecycle("fixture/store-duplicate"), LifecycleState.TRIAGED
    )
    append_lifecycle_event(path, record)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace(
        '"actor": "test"', '"actor": "forged", "actor": "test"', 1
    )
    path.write_text("\\n".join(lines) + "\\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate JSON object key"):
        verify_lifecycle_store(path)
