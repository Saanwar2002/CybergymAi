"""Create and verify bounded metadata bundles for local evidence artifacts."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

_SCHEMA_VERSION = "1.0"
_MAX_ARTIFACT_BYTES = 5 * 1024 * 1024
_MAX_BUNDLE_BYTES = 20 * 1024 * 1024
_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def _safe_artifact_path(root: Path, relative_path: str) -> Path:
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or "\x00" in relative_path
        or "\\" in relative_path
    ):
        raise ValueError("artifact path must be a non-empty relative POSIX path")
    path = PurePosixPath(relative_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("artifact path must stay beneath artifact_root")
    candidate = root.joinpath(*path.parts)
    if candidate.is_symlink():
        raise ValueError("symbolic-link evidence artifacts are not allowed")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("evidence artifact escapes artifact_root") from exc
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise ValueError("evidence artifact must be a regular file")
    return resolved


def _hash_file(path: Path, *, limit: int) -> tuple[str, int]:
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("evidence artifact must be a regular file")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise ValueError(f"evidence artifact exceeds {limit} bytes")
                digest.update(chunk)
        return digest.hexdigest(), size
    except BaseException:
        # fdopen owns the descriptor after it succeeds; this close handles open failures.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


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
    root = Path(artifact_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("artifact_root must be an existing directory")

    entries: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    total_size = 0
    for name, relative_path in sorted(artifacts.items()):
        if not isinstance(name, str) or not _NAME_PATTERN.fullmatch(name):
            raise ValueError(f"invalid evidence artifact name: {name!r}")
        path = _safe_artifact_path(root, relative_path)
        normalized_path = path.relative_to(root).as_posix()
        if normalized_path in seen_paths:
            raise ValueError("each evidence artifact must reference a unique file")
        seen_paths.add(normalized_path)
        digest, size = _hash_file(path, limit=_MAX_ARTIFACT_BYTES)
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
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return destination


def verify_evidence_bundle(
    bundle_path: str | Path, *, artifact_root: str | Path
) -> dict[str, Any]:
    """Validate bundle structure and re-hash every referenced artifact."""
    try:
        manifest = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
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
        path = _safe_artifact_path(root, entry["path"])
        normalized_path = path.relative_to(root).as_posix()
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
        digest, size = _hash_file(path, limit=_MAX_ARTIFACT_BYTES)
        if size != entry["size_bytes"] or digest != entry["sha256"]:
            raise ValueError(f"evidence artifact integrity check failed: {name}")
        total_size += size
        if total_size > _MAX_BUNDLE_BYTES:
            raise ValueError(f"evidence bundle exceeds {_MAX_BUNDLE_BYTES} bytes")
    return manifest
