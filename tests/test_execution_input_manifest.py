from __future__ import annotations

import pytest

from vulnresearch.execution import (
    ExecutionInput,
    ExecutionLimits,
    ExecutionRequirements,
    ExecutionSpec,
)


def input_artifact(artifact_id: str, guest_path: str, size_bytes: int = 1) -> ExecutionInput:
    return ExecutionInput(
        artifact_id=artifact_id,
        sha256="a" * 64,
        size_bytes=size_bytes,
        guest_path=guest_path,
    )


def make_spec(
    inputs: tuple[ExecutionInput, ...], *, max_input_bytes: int = 1024
) -> ExecutionSpec:
    return ExecutionSpec(
        run_id="input-manifest-run",
        task_id="input-manifest-task",
        command_id="fixture-command",
        argv=("python", "-c", "pass"),
        timeout_seconds=30,
        requirements=ExecutionRequirements.for_benchmark(),
        limits=ExecutionLimits(
            vcpu_count=1,
            memory_bytes=128 * 1024**2,
            disk_bytes=256 * 1024**2,
            max_processes=1,
            max_input_bytes=max_input_bytes,
            max_output_bytes_total=1,
        ),
        inputs=inputs,
    )


def test_execution_spec_rejects_more_than_64_input_artifacts():
    inputs = tuple(
        input_artifact(f"input-{index}", f"inputs/{index}.bin", size_bytes=0)
        for index in range(65)
    )

    with pytest.raises(ValueError, match="more than 64 artifacts"):
        make_spec(inputs)


def test_execution_spec_rejects_duplicate_input_artifact_ids():
    inputs = (
        input_artifact("duplicate", "inputs/first.bin"),
        input_artifact("duplicate", "inputs/second.bin"),
    )

    with pytest.raises(ValueError, match="artifact_id values must be unique"):
        make_spec(inputs)


def test_execution_spec_rejects_duplicate_input_guest_paths():
    inputs = (
        input_artifact("first", "inputs/data.bin"),
        input_artifact("second", "inputs/data.bin"),
    )

    with pytest.raises(ValueError, match="guest_path values must be unique"):
        make_spec(inputs)


def test_execution_spec_rejects_input_file_directory_conflicts():
    inputs = (
        input_artifact("first", "inputs"),
        input_artifact("second", "inputs/data.bin"),
    )

    with pytest.raises(ValueError, match="file/directory conflicts"):
        make_spec(inputs)


def test_execution_spec_rejects_input_bytes_over_the_approved_limit():
    inputs = (
        input_artifact("first", "inputs/first.bin"),
        input_artifact("second", "inputs/second.bin"),
    )

    with pytest.raises(ValueError, match="exceed the configured max_input_bytes"):
        make_spec(inputs, max_input_bytes=1)
