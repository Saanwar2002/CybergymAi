from __future__ import annotations

import pytest

from vulnresearch.execution import ExecutionInput, ExecutionOutput


@pytest.mark.parametrize("artifact_type", [ExecutionInput, ExecutionOutput])
@pytest.mark.parametrize(
    "guest_path",
    [
        "",
        " ",
        " leading/file",
        "trailing/file ",
        "/absolute/file",
        "../outside",
        "nested/../outside",
        "nested//file",
        "nested/./file",
        "nested\\file",
        "nested\x00file",
    ],
)
def test_execution_artifact_rejects_noncanonical_or_escaping_guest_paths(
    artifact_type, guest_path
):
    with pytest.raises(ValueError):
        artifact_type(
            artifact_id="fixture-artifact",
            sha256="a" * 64,
            size_bytes=1,
            guest_path=guest_path,
        )


@pytest.mark.parametrize("artifact_type", [ExecutionInput, ExecutionOutput])
def test_execution_artifact_accepts_canonical_nested_guest_path(artifact_type):
    artifact = artifact_type(
        artifact_id="fixture-artifact",
        sha256="a" * 64,
        size_bytes=1,
        guest_path="workspace/results/output.bin",
    )

    assert artifact.guest_path == "workspace/results/output.bin"
