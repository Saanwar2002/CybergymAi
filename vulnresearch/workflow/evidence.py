"""Create and verify bounded metadata bundles for local evidence artifacts."""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .._filesystem import fsync_directory
from ..jsonutil import loads_unique

_SCHEMA_VERSION = "1.0"
_MAX_ARTIFACT_BYTES = 5 * 1024 * 1024
_MAX_BUNDLE_BYTES = 20 * 1024 * 1024
_MAX_ARTIFACTS = 64
_MAX_BUNDLE_MANIFEST_BYTES = 256 * 1024
_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


class EvidenceBundlePublicationError(OSError):
    """Evidence bundle is visible, but parent-directory durability is uncertain."""

    def __init__(self, bundle_path: Path, cause: OSError) -> None:
        self.bundle_path = bundle_path
        self.cause = cause
        super().__init__(
            f"Evidence bundle was published at {bundle_path}, but parent-directory "
            f"durability is uncertain: {cause}"
        )


def _artifact_parts(relative_path: str) -> tuple[str, ...]:
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or "\x00" in relative_path
        or "\\" in relative_path
        or len(relative_path) > 1024
    ):
        raise ValueError("artifact path must be a non-empty relative POSIX path")
    path = PurePosixPath(relative_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("artifact path must stay beneath artifact_root")
    return path.parts


def _open_artifact(root: Path, relative_path: str) -> int:
    """Open an artifact relative to a pinned root without following any symlink."""
    parts = _artifact_parts(relative_path)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    file_flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(
                        "symbolic-link or non-directory evidence path components are not allowed"
                    ) from exc
                raise
            os.close(directory_fd)
            directory_fd = next_fd
        try:
            descriptor = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError("symbolic-link evidence artifacts are not allowed") from exc
            raise
    finally:
        os.close(directory_fd)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("evidence artifact must be a regular file")
    return descriptor


def read_evidence_artifact(
    artifact_root: str | Path, relative_path: str, *, limit: int = _MAX_ARTIFACT_BYTES
) -> bytes:
    """Read one bounded artifact through the same no-symlink descriptor walk as verification."""
    if type(limit) is not int or limit < 0:
        raise ValueError("artifact read limit must be a non-negative integer")
    root = Path(artifact_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("artifact_root must be an existing directory")
    descriptor = _open_artifact(root, relative_path)
    with os.fdopen(descriptor, "rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError(f"evidence artifact exceeds {limit} bytes")
    return content


def _hash_file(root: Path, relative_path: str, *, limit: int) -> tuple[str, int]:
    descriptor = _open_artifact(root, relative_path)
    with os.fdopen(descriptor, "rb") as stream:
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError(f"evidence artifact exceeds {limit} bytes")
            digest.update(chunk)
    return digest.hexdigest(), size


def create_evidence_bundle(
    task_id: str,
    artifacts: Mapping[str, str],
    *,
    artifact_root: str | Path,
    output_path: str | Path,
) -> Path:
    """Write a new bundle manifest referencing bounded files beneath artifact_root."""
    if not isinstance(task_id, str) or not task_id.strip():
        raise ValueError("task_id must be a non-empty string")
    if not isinstance(artifacts, Mapping) or not artifacts:
        raise ValueError("artifacts must be a non-empty name-to-relative-path mapping")
    if len(artifacts) > _MAX_ARTIFACTS:
        raise ValueError(f"evidence bundle may contain no more than {_MAX_ARTIFACTS} artifacts")
    root = Path(artifact_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("artifact_root must be an existing directory")

    entries: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    total_size = 0
    for name, relative_path in sorted(artifacts.items()):
        if not isinstance(name, str) or not _NAME_PATTERN.fullmatch(name):
            raise ValueError(f"invalid evidence artifact name: {name!r}")
        parts = _artifact_parts(relative_path)
        normalized_path = PurePosixPath(*parts).as_posix()
        if normalized_path in seen_paths:
            raise ValueError("each evidence artifact must reference a unique file")
        seen_paths.add(normalized_path)
        digest, size = _hash_file(root, normalized_path, limit=_MAX_ARTIFACT_BYTES)
        total_size += size
        if total_size > _MAX_BUNDLE_BYTES:
            raise ValueError(f"evidence bundle exceeds {_MAX_BUNDLE_BYTES} bytes")
        entries[name] = {
            "path": normalized_path,
            "size_bytes": size,
            "sha256": digest,
        }

    manifest = {
        "schema_version": _SCHEMA_VERSION,
        "task_id": task_id.strip(),
        "created_at": datetime.now(UTC).isoformat(),
        "artifacts": entries,
    }
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > _MAX_BUNDLE_MANIFEST_BYTES:
        raise ValueError(
            f"evidence bundle manifest exceeds {_MAX_BUNDLE_MANIFEST_BYTES} bytes"
        )
    # Stage the complete manifest privately beside its destination. Publish with
    # a no-overwrite hard link so readers never observe a partially written bundle.
    with tempfile.TemporaryDirectory(
        prefix=".evidence-bundle-", dir=destination.parent
    ) as staging:
        staged_path = Path(staging) / "manifest.json"
        descriptor = os.open(
            staged_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        fsync_directory(staging)
        os.link(staged_path, destination)
    # TemporaryDirectory cleanup also changes the parent directory. Synchronize
    # after cleanup so both the published link and removal of the staging entry
    # are durable before returning.
    try:
        fsync_directory(destination.parent)
    except OSError as exc:
        raise EvidenceBundlePublicationError(destination, exc) from exc
    return destination


def verify_evidence_reference(
    reference: str, *, artifact_root: str | Path
) -> dict[str, Any]:
    """Verify a content-pinned lifecycle reference and all artifacts it names."""
    if not isinstance(reference, str) or not reference.startswith("bundle:"):
        raise ValueError("evidence reference must use the bundle: scheme")
    relative_path, separator, expected_digest = reference[len("bundle:") :].partition(
        "#sha256="
    )
    if (
        not separator
        or not re.fullmatch(r"[a-f0-9]{64}", expected_digest)
        or not relative_path
    ):
        raise ValueError("evidence bundle reference must include a SHA-256 pin")
    parts = _artifact_parts(relative_path)
    if PurePosixPath(*parts).as_posix() != relative_path:
        raise ValueError("evidence bundle reference path must be canonical")

    root = Path(artifact_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("artifact_root must be an existing directory")
    encoded_manifest = read_evidence_artifact(
        root, relative_path, limit=_MAX_BUNDLE_MANIFEST_BYTES
    )
    if hashlib.sha256(encoded_manifest).hexdigest() != expected_digest:
        raise ValueError("evidence bundle reference SHA-256 mismatch")

    manifest_path = root.joinpath(*parts)
    manifest = verify_evidence_bundle(manifest_path, artifact_root=root)
    # Bind the parsed/verified manifest to the same exact bytes that were pinned.
    verified_bytes = read_evidence_artifact(
        root, relative_path, limit=_MAX_BUNDLE_MANIFEST_BYTES
    )
    if hashlib.sha256(verified_bytes).hexdigest() != expected_digest:
        raise ValueError("evidence bundle changed while verifying its pinned reference")
    return manifest


def verify_evidence_bundle(
    bundle_path: str | Path, *, artifact_root: str | Path
) -> dict[str, Any]:
    """Validate bundle structure and re-hash every referenced artifact."""
    source = Path(bundle_path)
    try:
        descriptor = os.open(
            source,
            os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise ValueError("evidence bundle must be a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            encoded_manifest = stream.read(_MAX_BUNDLE_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"cannot read evidence bundle: {exc}") from exc
    if len(encoded_manifest) > _MAX_BUNDLE_MANIFEST_BYTES:
        raise ValueError(
            f"evidence bundle manifest exceeds {_MAX_BUNDLE_MANIFEST_BYTES} bytes"
        )
    try:
        manifest = loads_unique(encoded_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read evidence bundle: {exc}") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "task_id", "created_at", "artifacts"
    }:
        raise ValueError("evidence bundle has an unsupported schema")
    if manifest["schema_version"] != _SCHEMA_VERSION:
        raise ValueError("unsupported evidence bundle schema_version")
    if not isinstance(manifest["task_id"], str) or not manifest["task_id"].strip():
        raise ValueError("evidence bundle task_id is invalid")
    try:
        timestamp = datetime.fromisoformat(manifest["created_at"])
    except (TypeError, ValueError) as exc:
        raise ValueError("evidence bundle created_at is invalid") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("evidence bundle created_at must be timezone-aware")
    entries = manifest["artifacts"]
    if not isinstance(entries, dict) or not entries:
        raise ValueError("evidence bundle must contain at least one artifact")
    if len(entries) > _MAX_ARTIFACTS:
        raise ValueError(f"evidence bundle may contain no more than {_MAX_ARTIFACTS} artifacts")

    root = Path(artifact_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("artifact_root must be an existing directory")
    total_size = 0
    seen_paths: set[str] = set()
    for name, entry in entries.items():
        if not isinstance(name, str) or not _NAME_PATTERN.fullmatch(name):
            raise ValueError(f"invalid evidence artifact name: {name!r}")
        if not isinstance(entry, dict) or set(entry) != {"path", "size_bytes", "sha256"}:
            raise ValueError(f"invalid evidence metadata for artifact {name}")
        parts = _artifact_parts(entry["path"])
        normalized_path = PurePosixPath(*parts).as_posix()
        if normalized_path in seen_paths:
            raise ValueError("evidence bundle contains duplicate artifact paths")
        seen_paths.add(normalized_path)
        if type(entry["size_bytes"]) is not int or entry["size_bytes"] < 0:
            raise ValueError(f"invalid size for evidence artifact {name}")
        if (
            not isinstance(entry["sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"])
        ):
            raise ValueError(f"invalid SHA-256 for evidence artifact {name}")
        digest, size = _hash_file(root, normalized_path, limit=_MAX_ARTIFACT_BYTES)
        if size != entry["size_bytes"] or digest != entry["sha256"]:
            raise ValueError(f"evidence artifact integrity check failed: {name}")
        total_size += size
        if total_size > _MAX_BUNDLE_BYTES:
            raise ValueError(f"evidence bundle exceeds {_MAX_BUNDLE_BYTES} bytes")
    return manifest
