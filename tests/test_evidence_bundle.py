import hashlib
import json

import pytest

from vulnresearch.workflow.evidence import (
    create_evidence_bundle,
    verify_evidence_bundle,
    verify_evidence_reference,
)


def test_create_and_verify_evidence_bundle(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "stdout.txt").write_text("fixture output\n", encoding="utf-8")
    (root / "report.json").write_text('{"status":"succeeded"}\n', encoding="utf-8")

    bundle = create_evidence_bundle(
        "fixture-001",
        {"stdout": "stdout.txt", "report": "report.json"},
        artifact_root=root,
        output_path=tmp_path / "bundle.json",
    )
    manifest = verify_evidence_bundle(bundle, artifact_root=root)

    assert manifest["task_id"] == "fixture-001"
    assert manifest["artifacts"]["stdout"]["size_bytes"] == 15
    assert len(manifest["artifacts"]["report"]["sha256"]) == 64
    with pytest.raises(FileExistsError):
        create_evidence_bundle(
            "fixture-001",
            {"stdout": "stdout.txt"},
            artifact_root=root,
            output_path=bundle,
        )


def test_verification_detects_artifact_tampering(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    artifact = root / "stdout.txt"
    artifact.write_text("original", encoding="utf-8")
    bundle = create_evidence_bundle(
        "fixture-002",
        {"stdout": "stdout.txt"},
        artifact_root=root,
        output_path=tmp_path / "bundle.json",
    )
    artifact.write_text("modified", encoding="utf-8")

    with pytest.raises(ValueError, match="integrity check failed"):
        verify_evidence_bundle(bundle, artifact_root=root)


@pytest.mark.parametrize("relative_path", ["../outside.txt", "/etc/passwd", "sub/../../x"])
def test_create_rejects_paths_outside_artifact_root(tmp_path, relative_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("not in root", encoding="utf-8")

    with pytest.raises((ValueError, FileNotFoundError)):
        create_evidence_bundle(
            "fixture-003",
            {"artifact": relative_path},
            artifact_root=root,
            output_path=tmp_path / "bundle.json",
        )


def test_create_rejects_symlink_artifact(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (root / "linked.txt").symlink_to(outside)

    with pytest.raises(ValueError, match="symbolic-link"):
        create_evidence_bundle(
            "fixture-004",
            {"artifact": "linked.txt"},
            artifact_root=root,
            output_path=tmp_path / "bundle.json",
        )


def test_create_and_verify_reject_symlinked_parent_directory(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside", encoding="utf-8")
    (root / "linked-dir").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symbolic-link"):
        create_evidence_bundle(
            "fixture-parent-symlink",
            {"artifact": "linked-dir/secret.txt"},
            artifact_root=root,
            output_path=tmp_path / "bundle.json",
        )


def test_verification_rejects_unknown_manifest_fields(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "stdout.txt").write_text("ok", encoding="utf-8")
    bundle = create_evidence_bundle(
        "fixture-005",
        {"stdout": "stdout.txt"},
        artifact_root=root,
        output_path=tmp_path / "bundle.json",
    )
    manifest = json.loads(bundle.read_text(encoding="utf-8"))
    manifest["extra"] = "not allowed"
    bundle.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported schema"):
        verify_evidence_bundle(bundle, artifact_root=root)


def test_verification_rejects_duplicate_manifest_json_keys(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "stdout.txt").write_text("ok", encoding="utf-8")
    bundle = create_evidence_bundle(
        "fixture-duplicate-manifest",
        {"stdout": "stdout.txt"},
        artifact_root=root,
        output_path=tmp_path / "bundle.json",
    )
    raw = bundle.read_text(encoding="utf-8")
    bundle.write_text(
        raw.replace('"schema_version": "1.0"', '"schema_version": "1.0", "schema_version": "1.0"', 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate JSON object key"):
        verify_evidence_bundle(bundle, artifact_root=root)


def test_verification_rejects_symlink_bundle_manifest(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "stdout.txt").write_text("ok", encoding="utf-8")
    bundle = create_evidence_bundle(
        "fixture-symlink-bundle",
        {"stdout": "stdout.txt"},
        artifact_root=root,
        output_path=tmp_path / "real-bundle.json",
    )
    link = tmp_path / "linked-bundle.json"
    link.symlink_to(bundle)

    with pytest.raises(ValueError, match="cannot read evidence bundle"):
        verify_evidence_bundle(link, artifact_root=root)


def test_verification_rejects_oversized_bundle_manifest(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "stdout.txt").write_text("ok", encoding="utf-8")
    bundle = create_evidence_bundle(
        "fixture-large-bundle",
        {"stdout": "stdout.txt"},
        artifact_root=root,
        output_path=tmp_path / "bundle.json",
    )
    with bundle.open("a", encoding="utf-8") as stream:
        stream.write(" " * (256 * 1024))

    with pytest.raises(ValueError, match="manifest exceeds"):
        verify_evidence_bundle(bundle, artifact_root=root)


def test_create_rejects_too_many_evidence_artifacts(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    artifacts = {}
    for index in range(65):
        name = f"artifact-{index}.txt"
        (root / name).write_text("ok", encoding="utf-8")
        artifacts[f"artifact-{index}"] = name

    with pytest.raises(ValueError, match="no more than 64"):
        create_evidence_bundle(
            "fixture-too-many-artifacts",
            artifacts,
            artifact_root=root,
            output_path=tmp_path / "bundle.json",
        )



def test_read_evidence_artifact_rejects_symlinked_parent_directory(tmp_path):
    from vulnresearch.workflow.evidence import read_evidence_artifact

    root = tmp_path / "artifacts"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside", encoding="utf-8")
    (root / "linked-dir").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symbolic-link"):
        read_evidence_artifact(root, "linked-dir/secret.txt")


def test_bundle_creation_failure_never_publishes_partial_manifest(tmp_path, monkeypatch):
    from vulnresearch.workflow import evidence as evidence_module

    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "stdout.txt").write_text("complete output", encoding="utf-8")
    destination = tmp_path / "bundle.json"

    def fail_fsync(_descriptor):
        raise OSError("simulated manifest fsync failure")

    monkeypatch.setattr(evidence_module.os, "fsync", fail_fsync)

    with pytest.raises(OSError, match="simulated manifest fsync failure"):
        create_evidence_bundle(
            "fixture-atomic-bundle",
            {"stdout": "stdout.txt"},
            artifact_root=root,
            output_path=destination,
        )

    assert not destination.exists()
    assert list(tmp_path.iterdir()) == [root]


def test_content_pinned_evidence_reference_verifies_bundle_and_artifacts(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "stdout.txt").write_text("pinned output", encoding="utf-8")
    bundle = create_evidence_bundle(
        "fixture-pinned-reference",
        {"stdout": "stdout.txt"},
        artifact_root=root,
        output_path=root / "bundle.json",
    )
    encoded = bundle.read_bytes()
    digest = hashlib.sha256(encoded).hexdigest()
    reference = f"bundle:bundle.json#sha256={digest}"

    manifest = verify_evidence_reference(reference, artifact_root=root)

    assert manifest["task_id"] == "fixture-pinned-reference"


def test_content_pinned_evidence_reference_rejects_replaced_manifest(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "first.txt").write_text("first", encoding="utf-8")
    (root / "second.txt").write_text("second", encoding="utf-8")
    bundle = create_evidence_bundle(
        "fixture-pinned-reference",
        {"output": "first.txt"},
        artifact_root=root,
        output_path=root / "bundle.json",
    )
    original_digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    bundle.unlink()
    create_evidence_bundle(
        "fixture-pinned-reference",
        {"output": "second.txt"},
        artifact_root=root,
        output_path=bundle,
    )

    with pytest.raises(ValueError, match="reference SHA-256 mismatch"):
        verify_evidence_reference(
            f"bundle:bundle.json#sha256={original_digest}",
            artifact_root=root,
        )
