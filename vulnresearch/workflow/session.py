"""Persisted, human-governed lifecycle sessions and evidence-backed patch review."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath

from ..jsonutil import loads_unique
from .evidence import create_evidence_bundle, verify_evidence_bundle
from .lifecycle import (
    ActorRole,
    LifecycleRecord,
    LifecycleState,
    create_lifecycle,
    transition,
)
from .store import append_lifecycle_event, create_lifecycle_store, verify_lifecycle_store


def _bundle_destination(root: Path, bundle_path: str | Path) -> Path:
    destination = Path(bundle_path)
    if not destination.is_absolute():
        destination = root / destination
    destination = destination.resolve(strict=False)
    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise ValueError("evidence bundle path must remain beneath artifact_root") from exc
    return destination


def _bundle_reference(bundle_path: Path, root: Path) -> str:
    return f"bundle:{bundle_path.relative_to(root).as_posix()}"


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

    def propose_patch(
        self,
        patch_path: str,
        *,
        artifact_root: str | Path,
        bundle_path: str | Path,
        actor: str,
        actor_role: ActorRole,
        decision_note: str,
    ) -> WorkflowSession:
        """Record a human/agent patch proposal as a bounded, hashed artifact bundle."""
        if not isinstance(patch_path, str) or PurePosixPath(patch_path).suffix not in {
            ".patch",
            ".diff",
        }:
            raise ValueError("patch proposal must reference a .patch or .diff artifact")
        if not isinstance(decision_note, str) or not decision_note.strip():
            raise ValueError("patch proposal requires a decision note")
        root = Path(artifact_root).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("artifact_root must be an existing directory")
        destination = _bundle_destination(root, bundle_path)
        bundle = create_evidence_bundle(
            self.record.task_id,
            {"patch": patch_path},
            artifact_root=root,
            output_path=destination,
        )
        manifest = verify_evidence_bundle(bundle, artifact_root=root)
        if manifest["task_id"] != self.record.task_id:
            raise ValueError("patch bundle task_id does not match workflow task")
        return self.advance(
            LifecycleState.PATCH_PROPOSED,
            actor=actor,
            actor_role=actor_role,
            evidence_refs=[_bundle_reference(bundle, root)],
            decision_note=decision_note,
        )

    def record_patch_test(
        self,
        bundle_path: str | Path,
        *,
        artifact_root: str | Path,
    ) -> WorkflowSession:
        """Record a sandbox test attempt only when its report/log bundle verifies."""
        root = Path(artifact_root).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("artifact_root must be an existing directory")
        bundle = _bundle_destination(root, bundle_path)
        manifest = verify_evidence_bundle(bundle, artifact_root=root)
        if manifest["task_id"] != self.record.task_id:
            raise ValueError("test bundle task_id does not match workflow task")
        entries = manifest["artifacts"]
        if not {"report", "stdout", "stderr"}.issubset(entries):
            raise ValueError("patch test bundle requires report, stdout, and stderr artifacts")
        report_path = (root / entries["report"]["path"]).resolve(strict=True)
        try:
            report = loads_unique(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read patch test report: {exc}") from exc
        if not isinstance(report, dict) or report.get("task_id") != self.record.task_id:
            raise ValueError("patch test report task_id does not match workflow task")
        report_artifacts = report.get("artifacts")
        if not isinstance(report_artifacts, dict) or set(report_artifacts) != {
            "stdout", "stderr"
        }:
            raise ValueError("patch test report must reference stdout and stderr artifacts")
        for stream_name in ("stdout", "stderr"):
            report_entry = report_artifacts[stream_name]
            bundle_entry = entries[stream_name]
            if not isinstance(report_entry, dict) or set(report_entry) != {
                "path", "sha256", "size_bytes", "truncated"
            }:
                raise ValueError(f"patch test report has invalid {stream_name} metadata")
            report_relative_path = report_entry["path"]
            if not isinstance(report_relative_path, str):
                raise TypeError(f"patch test report has invalid {stream_name} path")
            relative_parts = PurePosixPath(report_relative_path)
            if (
                relative_parts.is_absolute()
                or not relative_parts.parts
                or any(part in {"", ".", ".."} for part in relative_parts.parts)
            ):
                raise ValueError(f"patch test report {stream_name} path is not relative")
            referenced_log = (report_path.parent / Path(*relative_parts.parts)).resolve(
                strict=True
            )
            bundled_log = (root / bundle_entry["path"]).resolve(strict=True)
            if referenced_log != bundled_log:
                raise ValueError(
                    f"patch test report {stream_name} path does not match evidence bundle"
                )
            if (
                report_entry["sha256"] != bundle_entry["sha256"]
                or report_entry["size_bytes"] != bundle_entry["size_bytes"]
                or type(report_entry["truncated"]) is not bool
            ):
                raise ValueError(
                    f"patch test report {stream_name} metadata does not match evidence bundle"
                )
        status = report.get("status")
        exit_code = report.get("exit_code")
        if (
            not isinstance(status, str)
            or status not in {"succeeded", "failed"}
            or type(exit_code) is not int
        ):
            raise ValueError("patch test report has invalid status or exit_code")
        expected_status = "succeeded" if exit_code == 0 else "failed"
        if status != expected_status:
            raise ValueError("patch test report status does not match exit_code")
        return self.advance(
            LifecycleState.PATCH_TESTED,
            actor="sandbox-runner",
            actor_role=ActorRole.SYSTEM,
            evidence_refs=[_bundle_reference(bundle, root)],
            decision_note=f"Sandbox regression run {status}; exit_code={exit_code}.",
        )
