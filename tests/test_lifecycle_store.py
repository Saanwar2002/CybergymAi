import json
import os
import threading
from datetime import UTC, datetime

import pytest

from vulnresearch.workflow import store as store_module
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
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate JSON object key"):
        verify_lifecycle_store(path)


def test_store_rejects_oversized_audit_file(tmp_path):
    path = tmp_path / "oversized.jsonl"
    path.write_bytes(b" " * (1024 * 1024 + 1))

    with pytest.raises(ValueError, match="Lifecycle store exceeds"):
        verify_lifecycle_store(path)



def test_append_uses_the_same_verified_file_when_path_is_replaced(
    tmp_path, monkeypatch
):
    import vulnresearch.workflow.store as store_module

    path = create_lifecycle_store("fixture/store-fd", tmp_path / "audit.jsonl")
    held = tmp_path / "held-audit.jsonl"
    decoy = create_lifecycle_store("fixture/decoy", tmp_path / "decoy.jsonl")
    record = _transition(
        create_lifecycle("fixture/store-fd"), LifecycleState.TRIAGED
    )
    original_read = store_module._read_verified
    replaced = False

    def replace_path_after_verification(path_arg=None, *, descriptor=None):
        nonlocal replaced
        result = original_read(path_arg, descriptor=descriptor)
        if descriptor is not None and not replaced:
            path.rename(held)
            path.symlink_to(decoy)
            replaced = True
        return result

    monkeypatch.setattr(store_module, "_read_verified", replace_path_after_verification)
    append_lifecycle_event(path, record)

    assert replaced
    assert verify_lifecycle_store(held) == record
    assert verify_lifecycle_store(decoy).events == ()



def test_append_rolls_back_a_partial_write_failure(tmp_path, monkeypatch):
    import vulnresearch.workflow.store as store_module

    path = create_lifecycle_store("fixture/store-partial-write", tmp_path / "audit.jsonl")
    original_bytes = path.read_bytes()
    record = _transition(
        create_lifecycle("fixture/store-partial-write"), LifecycleState.TRIAGED
    )
    real_write = store_module.os.write
    calls = 0

    def fail_after_partial_write(descriptor, data):
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, data[:8])
        raise OSError("simulated storage failure")

    monkeypatch.setattr(store_module.os, "write", fail_after_partial_write)
    with pytest.raises(OSError, match="simulated storage failure"):
        append_lifecycle_event(path, record)

    assert path.read_bytes() == original_bytes
    assert verify_lifecycle_store(path).events == ()


def test_partial_append_and_failed_rollback_expose_uncertain_store_state(
    tmp_path, monkeypatch
):
    path = create_lifecycle_store(
        "fixture/store-rollback-uncertain", tmp_path / "audit.jsonl"
    )
    original_size = path.stat().st_size
    record = _transition(
        create_lifecycle("fixture/store-rollback-uncertain"),
        LifecycleState.TRIAGED,
    )
    real_write = store_module.os.write
    calls = 0

    def partial_then_fail(descriptor, data):
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, data[:8])
        raise OSError("simulated append write failure")

    def fail_rollback(_descriptor, _size):
        raise OSError("simulated rollback truncate failure")

    monkeypatch.setattr(store_module.os, "write", partial_then_fail)
    monkeypatch.setattr(store_module.os, "ftruncate", fail_rollback)

    with pytest.raises(
        store_module.LifecycleStoreAppendUncertainError,
        match="rollback could not be confirmed",
    ) as error:
        append_lifecycle_event(path, record)

    assert error.value.store_path == path
    assert error.value.original_size == original_size
    assert isinstance(error.value.append_error, OSError)
    assert str(error.value.append_error) == "simulated append write failure"
    assert isinstance(error.value.rollback_error, OSError)
    assert str(error.value.rollback_error) == "simulated rollback truncate failure"
    assert path.stat().st_size == original_size + 8
    with pytest.raises(ValueError):
        verify_lifecycle_store(path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is unavailable")
def test_store_rejects_fifo_without_blocking(tmp_path):
    path = tmp_path / "audit.fifo"
    os.mkfifo(path)

    with pytest.raises(ValueError, match="regular file"):
        verify_lifecycle_store(path)


def test_store_creation_failure_never_publishes_partial_path(tmp_path, monkeypatch):
    import vulnresearch.workflow.store as store_module

    destination = tmp_path / "audit.jsonl"

    def fail_fsync(descriptor):
        raise OSError("simulated store sync failure")

    monkeypatch.setattr(store_module.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="simulated store sync failure"):
        create_lifecycle_store("fixture/store-create-failure", destination)

    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_lifecycle_store_fsyncs_staging_and_parent_after_cleanup(
    tmp_path, monkeypatch
):
    synced = []

    def record_fsync(path):
        path = os.fspath(path)
        if path == os.fspath(tmp_path):
            assert not list(tmp_path.glob(".audit-*"))
        synced.append(path)

    monkeypatch.setattr(store_module, "fsync_directory", record_fsync)

    path = create_lifecycle_store("fixture/durable-store", tmp_path / "audit.jsonl")

    assert path.is_file()
    assert len(synced) == 2
    assert os.path.dirname(synced[0]) == os.fspath(tmp_path)
    assert os.path.basename(synced[0]).startswith(".audit-")
    assert synced[1] == os.fspath(tmp_path)


def test_lifecycle_store_staging_fsync_failure_publishes_nothing(
    tmp_path, monkeypatch
):
    def fail_fsync(_path):
        raise OSError("simulated audit staging directory fsync failure")

    monkeypatch.setattr(store_module, "fsync_directory", fail_fsync)

    with pytest.raises(OSError, match="audit staging directory fsync failure"):
        create_lifecycle_store("fixture/durable-store-failure", tmp_path / "audit.jsonl")

    assert list(tmp_path.iterdir()) == []


def test_lifecycle_store_parent_fsync_failure_leaves_complete_store_visible(
    tmp_path, monkeypatch
):
    def fail_parent_fsync(path):
        if path == tmp_path:
            raise OSError("simulated audit parent directory fsync failure")

    monkeypatch.setattr(store_module, "fsync_directory", fail_parent_fsync)

    with pytest.raises(
        store_module.LifecycleStorePublicationError,
        match="durability is uncertain",
    ) as error:
        create_lifecycle_store(
            "fixture/durable-store-parent-failure", tmp_path / "audit.jsonl"
        )

    path = tmp_path / "audit.jsonl"
    assert error.value.store_path == path
    assert error.value.store_path.is_file()
    assert isinstance(error.value.cause, OSError)
    assert verify_lifecycle_store(path).task_id == "fixture/durable-store-parent-failure"


@pytest.mark.skipif(os.name == "nt", reason="thread-level msvcrt locking differs from POSIX flock")
def test_audit_store_exclusive_lock_blocks_a_second_writer(tmp_path):
    path = create_lifecycle_store("fixture/concurrent-lock", tmp_path / "audit.jsonl")
    first = os.open(path, os.O_RDWR)
    second = os.open(path, os.O_RDWR)
    started = threading.Event()
    acquired = threading.Event()
    errors = []

    def wait_for_lock():
        started.set()
        try:
            store_module._lock_audit_store(second)
            acquired.set()
            store_module._unlock_audit_store(second)
        except OSError as exc:
            errors.append(exc)

    try:
        store_module._lock_audit_store(first)
        worker = threading.Thread(target=wait_for_lock)
        worker.start()
        assert started.wait(timeout=1)
        assert not acquired.wait(timeout=0.05)

        store_module._unlock_audit_store(first)
        assert acquired.wait(timeout=1)
        worker.join(timeout=1)

        assert not worker.is_alive()
        assert errors == []
    finally:
        os.close(first)
        os.close(second)


def test_lifecycle_append_acquires_lock_before_reading_store(tmp_path, monkeypatch):
    path = create_lifecycle_store("fixture/lock-order", tmp_path / "audit.jsonl")
    record = _transition(create_lifecycle("fixture/lock-order"), LifecycleState.TRIAGED)
    calls = []
    original_lock = store_module._lock_audit_store
    original_read = store_module._read_verified

    def record_lock(descriptor):
        calls.append("lock")
        original_lock(descriptor)

    def record_read(path_arg=None, *, descriptor=None):
        calls.append("read")
        return original_read(path_arg, descriptor=descriptor)

    monkeypatch.setattr(store_module, "_lock_audit_store", record_lock)
    monkeypatch.setattr(store_module, "_read_verified", record_read)

    append_lifecycle_event(path, record)

    assert calls[0] == "lock"
    assert calls[1] == "read"
