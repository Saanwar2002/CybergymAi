import hashlib
import json
from pathlib import Path

import pytest

from vulnresearch.workflow import evidence as evidence_module
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


def test_verification_rejects_symlinked_parent_of_in_root_bundle(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "stdout.txt").write_text("fixture output", encoding="utf-8")
    bundle = create_evidence_bundle(
        "fixture-parent-symlink-bundle",
        {"stdout": "stdout.txt"},
        artifact_root=root,
        output_path=outside / "bundle.json",
    )
    (root / "linked-dir").symlink_to(outside, target_is_directory=True)

    with pytest.raises(
        ValueError, match="symbolic-link or non-directory evidence path components"
    ):
        verify_evidence_bundle(
            root / "linked-dir" / bundle.name,
            artifact_root=root,
        )


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


def test_content_pinned_reference_rejects_manifest_from_raced_parent_path(
    tmp_path, monkeypatch
):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "stdout.txt").write_text("pinned output", encoding="utf-8")
    bundle = create_evidence_bundle(
        "fixture-pinned-reference",
        {"stdout": "stdout.txt"},
        artifact_root=root,
        output_path=root / "bundle.json",
    )
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    verified = verify_evidence_bundle(bundle, artifact_root=root)
    raced_manifest = dict(verified)
    raced_manifest["task_id"] = "attacker-controlled-manifest"

    # Model the unsafe path open observing a different file after a parent
    # directory substitution, while the descriptor-relative pinned reads still
    # see the original bundle bytes.
    monkeypatch.setattr(
        evidence_module, "verify_evidence_bundle", lambda *_args, **_kwargs: raced_manifest
    )

    with pytest.raises(ValueError, match="do not match the content-pinned manifest bytes"):
        verify_evidence_reference(
            f"bundle:bundle.json#sha256={digest}",
            artifact_root=root,
        )


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


def test_evidence_bundle_fsyncs_staging_and_parent_directories(tmp_path, monkeypatch):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "stdout.txt").write_text("fixture output", encoding="utf-8")
    synced = []

    def record_fsync(path):
        synced.append(path)

    monkeypatch.setattr(evidence_module, "fsync_directory", record_fsync)

    bundle = create_evidence_bundle(
        "fixture-durable",
        {"stdout": "stdout.txt"},
        artifact_root=root,
        output_path=tmp_path / "bundle.json",
    )

    assert bundle.is_file()
    assert len(synced) == 2
    staging_directory = Path(synced[0])
    assert staging_directory.parent == tmp_path
    assert staging_directory.name.startswith(".evidence-bundle-")
    assert synced[1] == tmp_path


def test_evidence_bundle_staging_fsync_failure_publishes_nothing(
    tmp_path, monkeypatch
):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "stdout.txt").write_text("fixture output", encoding="utf-8")

    def fail_fsync(_path):
        raise OSError("simulated bundle staging directory fsync failure")

    monkeypatch.setattr(evidence_module, "fsync_directory", fail_fsync)

    with pytest.raises(OSError, match="bundle staging directory fsync failure"):
        create_evidence_bundle(
            "fixture-durable-failure",
            {"stdout": "stdout.txt"},
            artifact_root=root,
            output_path=tmp_path / "bundle.json",
        )

    assert not (tmp_path / "bundle.json").exists()


def test_evidence_bundle_parent_fsync_failure_reports_uncertain_durability(
    tmp_path, monkeypatch
):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "stdout.txt").write_text("fixture output", encoding="utf-8")

    def fail_parent_fsync(path):
        if path == tmp_path:
            raise OSError("simulated bundle parent directory fsync failure")

    monkeypatch.setattr(evidence_module, "fsync_directory", fail_parent_fsync)

    with pytest.raises(
        evidence_module.EvidenceBundlePublicationError,
        match="durability is uncertain",
    ) as error:
        create_evidence_bundle(
            "fixture-durable-parent-failure",
            {"stdout": "stdout.txt"},
            artifact_root=root,
            output_path=tmp_path / "bundle.json",
        )

    assert error.value.bundle_path == tmp_path / "bundle.json"
    assert error.value.bundle_path.is_file()
    assert isinstance(error.value.cause, OSError)
