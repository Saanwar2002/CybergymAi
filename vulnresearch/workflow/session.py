"""Persisted, human-governed lifecycle sessions and evidence-backed patch review."""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath

from ..execution.base import ExecutionOutput, ExecutionSpec
from ..jsonutil import loads_unique
from .evidence import (
    create_evidence_bundle,
    read_evidence_artifact,
    verify_evidence_bundle,
)
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

    def _create_benchmark_evidence_bundle(
        self,
        report_path: str | Path,
        *,
        artifact_root: str | Path,
        bundle_path: str | Path,
    ) -> tuple[Path, Path, dict[str, object]]:
        """Validate a benchmark report and publish its report/log evidence bundle."""
        root = Path(artifact_root).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("artifact_root must be an existing directory")
        candidate = Path(report_path)
        if candidate.is_absolute():
            try:
                report_relative = candidate.relative_to(root).as_posix()
            except ValueError as exc:
                raise ValueError("benchmark report must remain beneath artifact_root") from exc
        else:
            report_relative = candidate.as_posix()

        try:
            report_bytes = read_evidence_artifact(
                root, report_relative, limit=256 * 1024
            )
            report = loads_unique(report_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"cannot read benchmark execution report: {exc}") from exc
        required_report_fields = {
            "schema_version",
            "run_id",
            "task_id",
            "execution_spec_sha256",
            "execution_spec",
            "status",
            "backend_status",
            "exit_code",
            "duration_seconds",
            "cleanup_confirmed",
            "resource_usage",
            "artifacts",
            "output_artifacts",
        }
        if not isinstance(report, dict) or set(report) != required_report_fields:
            raise ValueError("benchmark execution report has an unsupported schema")
        if report["schema_version"] != "1.0":
            raise ValueError("benchmark execution report has an unsupported schema_version")
        if report["task_id"] != self.record.task_id:
            raise ValueError("benchmark report task_id does not match workflow task")
        if not isinstance(report["run_id"], str) or not report["run_id"].strip():
            raise ValueError("benchmark report run_id is invalid")
        if report["cleanup_confirmed"] is not True:
            raise ValueError("benchmark report cleanup is not confirmed")

        execution_spec = report["execution_spec"]
        try:
            validated_spec = ExecutionSpec.from_manifest(execution_spec)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"benchmark report execution_spec is invalid: {exc}") from exc
        if (
            validated_spec.task_id != self.record.task_id
            or validated_spec.run_id != report["run_id"]
        ):
            raise ValueError("benchmark report execution_spec identifiers do not match")
        if (
            not isinstance(report["execution_spec_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", report["execution_spec_sha256"])
        ):
            raise ValueError("benchmark report execution_spec_sha256 is invalid")
        if validated_spec.manifest_sha256 != report["execution_spec_sha256"]:
            raise ValueError("benchmark report execution specification digest mismatch")

        backend_status = report["backend_status"]
        exit_code = report["exit_code"]
        report_status = report["status"]
        if backend_status not in {"completed", "failed", "timed_out", "blocked"}:
            raise ValueError("benchmark report backend_status is invalid")
        if exit_code is not None and type(exit_code) is not int:
            raise ValueError("benchmark report exit_code must be an integer or null")
        expected_status = "succeeded" if backend_status == "completed" else "failed"
        if report_status != expected_status:
            raise ValueError("benchmark report status does not match backend_status")
        if backend_status == "completed" and exit_code != 0:
            raise ValueError("completed benchmark reports require exit_code zero")
        if backend_status == "failed" and (
            exit_code is None or exit_code == 0
        ):
            raise ValueError("failed benchmark reports require a non-zero exit_code")
        if backend_status in {"timed_out", "blocked"} and exit_code == 0:
            raise ValueError(
                f"{backend_status} benchmark reports cannot have exit_code zero"
            )

        duration = report["duration_seconds"]
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(duration)
            or duration < 0
        ):
            raise ValueError("benchmark report duration_seconds is invalid")

        usage = report["resource_usage"]
        usage_limits = {
            "allocated_vcpu_count": validated_spec.limits.vcpu_count,
            "peak_memory_bytes": validated_spec.limits.memory_bytes,
            "peak_disk_bytes": validated_spec.limits.disk_bytes,
            "peak_processes": validated_spec.limits.max_processes,
            "input_bytes_staged": validated_spec.limits.max_input_bytes,
        }
        if not isinstance(usage, dict) or set(usage) != set(usage_limits):
            raise ValueError("benchmark report resource_usage has an invalid schema")
        for field, limit in usage_limits.items():
            value = usage[field]
            if type(value) is not int or value < 0 or value > limit:
                raise ValueError(
                    f"benchmark report resource_usage {field} exceeds its valid range"
                )
        expected_input_bytes = sum(item.size_bytes for item in validated_spec.inputs)
        if usage["input_bytes_staged"] != expected_input_bytes:
            raise ValueError(
                "benchmark report input_bytes_staged does not match the execution manifest"
            )

        output_artifacts = report["output_artifacts"]
        if not isinstance(output_artifacts, list) or len(output_artifacts) > 64:
            raise ValueError("benchmark report output_artifacts is invalid")
        validated_outputs: list[ExecutionOutput] = []
        for entry in output_artifacts:
            if not isinstance(entry, dict) or set(entry) != {
                "artifact_id", "sha256", "size_bytes", "guest_path"
            }:
                raise ValueError("benchmark report contains an invalid output artifact")
            try:
                validated_outputs.append(ExecutionOutput(**entry))
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"benchmark report contains an invalid output artifact: {exc}"
                ) from exc
        output_total = sum(item.size_bytes for item in validated_outputs)
        if output_total > validated_spec.limits.max_output_bytes_total:
            raise ValueError("benchmark report output artifacts exceed the aggregate limit")

        stream_artifacts = report["artifacts"]
        if not isinstance(stream_artifacts, dict) or set(stream_artifacts) != {
            "stdout", "stderr"
        }:
            raise ValueError("benchmark report must reference stdout and stderr artifacts")
        bundle_artifacts = {"report": report_relative}
        expected_bundle_entries = {
            "report": {
                "path": report_relative,
                "size_bytes": len(report_bytes),
                "sha256": hashlib.sha256(report_bytes).hexdigest(),
            }
        }
        report_parent = PurePosixPath(report_relative).parent
        for stream_name in ("stdout", "stderr"):
            entry = stream_artifacts[stream_name]
            if not isinstance(entry, dict) or set(entry) != {
                "path", "sha256", "size_bytes", "truncated"
            }:
                raise ValueError(f"benchmark report has invalid {stream_name} metadata")
            if entry["path"] != f"{stream_name}.txt":
                raise ValueError(
                    f"benchmark report {stream_name} path must be {stream_name}.txt"
                )
            if (
                not isinstance(entry["sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"])
                or type(entry["size_bytes"]) is not int
                or not 0 <= entry["size_bytes"] <= 5 * 1024 * 1024
                or type(entry["truncated"]) is not bool
            ):
                raise ValueError(f"benchmark report has invalid {stream_name} metadata")
            relative_log = (report_parent / entry["path"]).as_posix()
            try:
                log_bytes = read_evidence_artifact(
                    root, relative_log, limit=5 * 1024 * 1024
                )
            except (OSError, ValueError) as exc:
                raise ValueError(f"cannot read benchmark {stream_name}: {exc}") from exc
            if (
                len(log_bytes) != entry["size_bytes"]
                or hashlib.sha256(log_bytes).hexdigest() != entry["sha256"]
            ):
                raise ValueError(
                    f"benchmark report {stream_name} metadata does not match stored evidence"
                )
            bundle_artifacts[stream_name] = relative_log
            expected_bundle_entries[stream_name] = {
                "path": relative_log,
                "size_bytes": len(log_bytes),
                "sha256": hashlib.sha256(log_bytes).hexdigest(),
            }

        destination = _bundle_destination(root, bundle_path)
        bundle = create_evidence_bundle(
            self.record.task_id,
            bundle_artifacts,
            artifact_root=root,
            output_path=destination,
        )
        manifest = verify_evidence_bundle(bundle, artifact_root=root)
        if manifest["task_id"] != self.record.task_id:
            raise ValueError("benchmark evidence bundle task_id does not match workflow task")
        if manifest["artifacts"] != expected_bundle_entries:
            raise ValueError(
                "benchmark evidence bundle does not contain the exact report and log bytes validated"
            )
        return root, bundle, report

    def record_benchmark_execution(
        self,
        report_path: str | Path,
        *,
        artifact_root: str | Path,
        bundle_path: str | Path,
        actor: str = "benchmark-runner",
    ) -> WorkflowSession:
        """Bind a verified benchmark run report and logs to the reproduction event."""
        if self.record.state is not LifecycleState.PLAN_APPROVED:
            raise ValueError(
                "benchmark execution evidence can only be recorded after plan approval"
            )
        root, bundle, report = self._create_benchmark_evidence_bundle(
            report_path,
            artifact_root=artifact_root,
            bundle_path=bundle_path,
        )
        evidence_ref = _bundle_reference(bundle, root)
        return self.advance(
            LifecycleState.REPRODUCTION_ATTEMPTED,
            actor=actor,
            actor_role=ActorRole.SYSTEM,
            evidence_refs=[evidence_ref],
            decision_note=(
                "Recorded benchmark run "
                f"{report['run_id']} with execution spec SHA-256 "
                f"{report['execution_spec_sha256']}."
            ),
        )

    def record_benchmark_patch_test(
        self,
        report_path: str | Path,
        *,
        artifact_root: str | Path,
        bundle_path: str | Path,
    ) -> WorkflowSession:
        """Record a benchmark patch test after validating and bundling its run report."""
        if self.record.state is not LifecycleState.PATCH_PROPOSED:
            raise ValueError(
                "benchmark patch-test evidence can only be recorded after patch proposal"
            )
        root, bundle, _report = self._create_benchmark_evidence_bundle(
            report_path,
            artifact_root=artifact_root,
            bundle_path=bundle_path,
        )
        return self.record_patch_test(bundle, artifact_root=root)

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
        report_artifact_path = entries["report"]["path"]
        try:
            report_bytes = read_evidence_artifact(root, report_artifact_path)
            report = loads_unique(report_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"cannot read patch test report: {exc}") from exc
        report_bundle_entry = entries["report"]
        if (
            len(report_bytes) != report_bundle_entry["size_bytes"]
            or hashlib.sha256(report_bytes).hexdigest() != report_bundle_entry["sha256"]
        ):
            raise ValueError("patch test report integrity check failed after read")
        if not isinstance(report, dict) or report.get("task_id") != self.record.task_id:
            raise ValueError("patch test report task_id does not match workflow task")
        if report.get("schema_version") != "1.0":
            raise ValueError("patch test report has an unsupported schema_version")
        if not isinstance(report.get("run_id"), str) or not report["run_id"].strip():
            raise ValueError("patch test report run_id is invalid")
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
            if report_relative_path != f"{stream_name}.txt":
                raise ValueError(
                    f"patch test report {stream_name} path must be {stream_name}.txt"
                )
            referenced_log = (
                PurePosixPath(report_artifact_path).parent / report_relative_path
            ).as_posix()
            if referenced_log != bundle_entry["path"]:
                raise ValueError(
                    f"patch test report {stream_name} path does not match evidence bundle"
                )
            if (
                not isinstance(report_entry["sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", report_entry["sha256"])
                or type(report_entry["size_bytes"]) is not int
                or report_entry["size_bytes"] < 0
                or type(report_entry["truncated"]) is not bool
                or report_entry["sha256"] != bundle_entry["sha256"]
                or report_entry["size_bytes"] != bundle_entry["size_bytes"]
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
