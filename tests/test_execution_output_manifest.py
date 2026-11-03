from __future__ import annotations

import pytest

from vulnresearch.execution import BackendResult, ExecutionOutput, ExecutionStatus


def output(artifact_id: str, guest_path: str) -> ExecutionOutput:
    return ExecutionOutput(
        artifact_id=artifact_id,
        sha256="a" * 64,
        size_bytes=1,
        guest_path=guest_path,
    )


def result(outputs: tuple[ExecutionOutput, ...]) -> BackendResult:
    return BackendResult(
        status=ExecutionStatus.COMPLETED,
        returncode=0,
        stdout="",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.1,
        cleanup_confirmed=True,
        allocated_vcpu_count=1,
        peak_memory_bytes=128 * 1024**2,
        peak_disk_bytes=256 * 1024**2,
        peak_processes=1,
        input_bytes_staged=0,
        execution_spec_sha256="b" * 64,
        outputs=outputs,
    )


def test_backend_result_rejects_more_than_64_output_artifacts():
    outputs = tuple(output(f"artifact-{index}", f"reports/{index}.json") for index in range(65))

    with pytest.raises(ValueError, match="more than 64 artifacts"):
        result(outputs)


def test_backend_result_rejects_duplicate_output_artifact_ids():
    outputs = (
        output("duplicate", "reports/first.json"),
        output("duplicate", "reports/second.json"),
    )

    with pytest.raises(ValueError, match="artifact_id values must be unique"):
        result(outputs)


def test_backend_result_rejects_duplicate_output_guest_paths():
    outputs = (
        output("first", "reports/result.json"),
        output("second", "reports/result.json"),
    )

    with pytest.raises(ValueError, match="guest_path values must be unique"):
        result(outputs)


@pytest.mark.parametrize(
    ("first_path", "second_path"),
    [
        ("reports", "reports/result.json"),
        ("reports/nested", "reports/nested/result.json"),
    ],
)
def test_backend_result_rejects_output_file_directory_conflicts(first_path, second_path):
    outputs = (
        output("first", first_path),
        output("second", second_path),
    )

    with pytest.raises(ValueError, match="file/directory conflicts"):
        result(outputs)


def test_backend_result_requires_an_immutable_output_tuple():
    with pytest.raises(TypeError, match="tuple of ExecutionOutput"):
        result([output("first", "reports/result.json")])
