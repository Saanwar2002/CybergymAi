from __future__ import annotations

import pytest

from vulnresearch.execution import (
    ExecutionLimits,
    ExecutionRequirements,
    ExecutionSpec,
)


def make_spec() -> ExecutionSpec:
    return ExecutionSpec(
        run_id="manifest-roundtrip-run",
        task_id="manifest-roundtrip-task",
        command_id="fixture-command",
        argv=("python", "-c", "pass"),
        timeout_seconds=30,
        requirements=ExecutionRequirements.for_benchmark(),
        limits=ExecutionLimits(
            vcpu_count=1,
            memory_bytes=128 * 1024**2,
            disk_bytes=256 * 1024**2,
            max_processes=1,
            max_input_bytes=1024,
            max_output_bytes_total=1024,
        ),
    )


def test_execution_spec_manifest_round_trip_preserves_spec_and_digest():
    spec = make_spec()

    restored = ExecutionSpec.from_manifest(spec.to_manifest())

    assert restored == spec
    assert restored.manifest_sha256 == spec.manifest_sha256


def test_execution_spec_manifest_rejects_unknown_root_fields():
    manifest = make_spec().to_manifest()
    manifest["unexpected"] = "not part of schema 1.0"

    with pytest.raises(ValueError, match="unsupported schema"):
        ExecutionSpec.from_manifest(manifest)


def test_execution_spec_manifest_rejects_unsupported_schema_version():
    manifest = make_spec().to_manifest()
    manifest["schema_version"] = "2.0"

    with pytest.raises(ValueError, match="unsupported schema_version"):
        ExecutionSpec.from_manifest(manifest)


def test_execution_spec_manifest_rejects_unknown_nested_limit_fields():
    manifest = make_spec().to_manifest()
    manifest["limits"]["unexpected"] = 1

    with pytest.raises(ValueError, match="limits are invalid"):
        ExecutionSpec.from_manifest(manifest)


def test_execution_spec_manifest_rejects_non_boolean_requirement_values():
    manifest = make_spec().to_manifest()
    manifest["requirements"]["network_isolated"] = 1

    with pytest.raises(TypeError, match="network_isolated must be a boolean"):
        ExecutionSpec.from_manifest(manifest)
