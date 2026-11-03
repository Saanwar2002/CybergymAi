from __future__ import annotations

import hashlib
import json

import pytest

from vulnresearch.execution import (
    BackendResult,
    ExecutionInput,
    ExecutionLimits,
    ExecutionOutput,
    ExecutionRequirements,
    ExecutionSpec,
    ExecutionStatus,
)
from vulnresearch.execution import reporting as reporting_module
from vulnresearch.execution.reporting import write_benchmark_run_report


def make_spec(*, inputs: tuple[ExecutionInput, ...] = ()) -> ExecutionSpec:
    return ExecutionSpec(
        run_id="benchmark-run-1",
        task_id="benchmark-task-1",
        command_id="smoke-test",
        argv=("python", "-c", "print('safe')"),
        timeout_seconds=30,
        requirements=ExecutionRequirements.for_benchmark(),
        limits=ExecutionLimits(
            vcpu_count=1,
            memory_bytes=1024 * 1024**2,
            disk_bytes=5 * 1024**3,
            max_processes=256,
            max_input_bytes=64 * 1024**2,
            max_output_bytes_total=20 * 1024**2,
        ),
        inputs=inputs,
        max_output_bytes_per_stream=10 * 1024 * 1024,
    )


def make_result(
    spec: ExecutionSpec,
    *,
    stdout: str = "safe output",
    stdout_truncated: bool = False,
    cleanup_confirmed: bool = True,
    outputs: tuple[ExecutionOutput, ...] = (),
    digest: str | None = None,
) -> BackendResult:
    return BackendResult(
        status=ExecutionStatus.COMPLETED,
        returncode=0,
        stdout=stdout,
        stderr="",
        stdout_truncated=stdout_truncated,
        stderr_truncated=False,
        duration_seconds=0.25,
        cleanup_confirmed=cleanup_confirmed,
        allocated_vcpu_count=1,
        peak_memory_bytes=512 * 1024**2,
        peak_disk_bytes=1024**3,
        peak_processes=32,
        input_bytes_staged=sum(item.size_bytes for item in spec.inputs),
        execution_spec_sha256=digest or spec.manifest_sha256,
        outputs=outputs,
    )


def test_benchmark_report_persists_manifest_result_and_hashed_streams(tmp_path):
    spec = make_spec(
        inputs=(
            ExecutionInput(
                artifact_id="input-1",
                sha256="a" * 64,
                size_bytes=5,
                guest_path="src/input.bin",
            ),
        )
    )
    output = ExecutionOutput(
        artifact_id="output-1",
        sha256="b" * 64,
        size_bytes=12,
        guest_path="results/report.json",
    )
    result = make_result(spec, outputs=(output,))

    report_path = write_benchmark_run_report(spec, result, tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    stdout_path = report_path.parent / report["artifacts"]["stdout"]["path"]
    stdout_bytes = stdout_path.read_bytes()

    assert report["schema_version"] == "1.0"
    assert report["run_id"] == spec.run_id
    assert report["task_id"] == spec.task_id
    assert report["execution_spec"] == spec.to_manifest()
    assert report["execution_spec_sha256"] == spec.manifest_sha256
    assert report["resource_usage"]["input_bytes_staged"] == 5
    assert report["output_artifacts"][0]["artifact_id"] == output.artifact_id
    assert report["artifacts"]["stdout"]["sha256"] == hashlib.sha256(stdout_bytes).hexdigest()
    assert report["artifacts"]["stdout"]["size_bytes"] == len(stdout_bytes)
    assert stdout_bytes == b"safe output"


def test_benchmark_report_rejects_result_for_different_spec(tmp_path):
    spec = make_spec()
    result = make_result(spec, digest="f" * 64)

    with pytest.raises(ValueError, match="does not match the approved"):
        write_benchmark_run_report(spec, result, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_benchmark_report_rejects_unconfirmed_cleanup(tmp_path):
    spec = make_spec()
    result = make_result(spec, cleanup_confirmed=False)

    with pytest.raises(ValueError, match="unconfirmed cleanup"):
        write_benchmark_run_report(spec, result, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_benchmark_report_truncates_streams_to_evidence_artifact_limit(tmp_path):
    spec = make_spec()
    result = make_result(spec, stdout="x" * (5 * 1024 * 1024 + 17))

    report_path = write_benchmark_run_report(spec, result, tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    stdout_metadata = report["artifacts"]["stdout"]
    stdout_bytes = (report_path.parent / stdout_metadata["path"]).read_bytes()

    assert len(stdout_bytes) == 5 * 1024 * 1024
    assert stdout_metadata["truncated"] is True
    assert stdout_metadata["size_bytes"] == len(stdout_bytes)
    assert stdout_metadata["sha256"] == hashlib.sha256(stdout_bytes).hexdigest()


def test_benchmark_report_write_failure_never_publishes_partial_run(
    tmp_path, monkeypatch
):
    spec = make_spec()
    result = make_result(spec)
    original_write = reporting_module._write_bytes

    def fail_report_write(directory, name, content):
        if name == "report.json":
            raise OSError("simulated report write failure")
        original_write(directory, name, content)

    monkeypatch.setattr(reporting_module, "_write_bytes", fail_report_write)

    with pytest.raises(OSError, match="simulated report write failure"):
        write_benchmark_run_report(spec, result, tmp_path)

    assert list(tmp_path.iterdir()) == []
