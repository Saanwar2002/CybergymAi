"""Fail-closed validation for an offline GCE canary image release manifest.

This module validates evidence supplied by a future image build pipeline. It does not
build, publish, sign, scan, or deploy an image and does not contact Google Cloud.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from vulnresearch.execution.gce import GceCanaryConfig


class GceImageManifestError(ValueError):
    """Raised when image release evidence is missing or fails the release policy."""


_PROJECT = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
_IMAGE_PATH = re.compile(rf"^projects/{_PROJECT}/global/images/[a-z][a-z0-9-]{{0,61}}[a-z0-9]$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_BUILD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")


@dataclass(frozen=True)
class GceImageRelease:
    """Validated immutable image identity and minimum release evidence."""

    image_self_link: str
    source_image_self_link: str
    build_commit: str
    build_id: str
    artifact_sha256: str
    provenance_uri: str
    scanner: str
    scan_timestamp: str


def _required_string(data: Mapping[str, object], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise GceImageManifestError(f"{field} must be a non-empty string")
    if value != value.strip():
        raise GceImageManifestError(f"{field} must not contain surrounding whitespace")
    return value


def _https_uri(value: str, field: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise GceImageManifestError(f"{field} must be an HTTPS URI without embedded credentials")


def validate_gce_image_release_manifest(data: Mapping[str, object]) -> GceImageRelease:
    """Validate an image release manifest; reject mutable sources and unclean scan results."""
    if not isinstance(data, Mapping):
        raise GceImageManifestError("image release manifest must be an object")

    image = _required_string(data, "image_self_link")
    source = _required_string(data, "source_image_self_link")
    if not _IMAGE_PATH.fullmatch(image):
        raise GceImageManifestError("image_self_link must identify one exact GCE image")
    if not _IMAGE_PATH.fullmatch(source):
        raise GceImageManifestError("source_image_self_link must identify one exact GCE image")
    if image == source:
        raise GceImageManifestError("release image must differ from its source image")

    commit = _required_string(data, "build_commit")
    if not _COMMIT.fullmatch(commit):
        raise GceImageManifestError("build_commit must be a full 40- or 64-character Git SHA")

    build_id = _required_string(data, "build_id")
    if not _BUILD_ID.fullmatch(build_id):
        raise GceImageManifestError("build_id has an invalid format")

    digest = _required_string(data, "artifact_sha256")
    if not _SHA256.fullmatch(digest):
        raise GceImageManifestError("artifact_sha256 must be a lowercase SHA-256 digest")

    provenance = _required_string(data, "provenance_uri")
    _https_uri(provenance, "provenance_uri")

    scan = data.get("vulnerability_scan")
    if not isinstance(scan, Mapping):
        raise GceImageManifestError("vulnerability_scan must be an object")
    scanner = scan.get("scanner")
    scanned_at = scan.get("scanned_at")
    if not isinstance(scanner, str) or not scanner.strip():
        raise GceImageManifestError("vulnerability_scan.scanner must be non-empty")
    if not isinstance(scanned_at, str) or not scanned_at:
        raise GceImageManifestError("vulnerability_scan.scanned_at must be an ISO-8601 timestamp")
    try:
        timestamp = datetime.fromisoformat(scanned_at)
    except ValueError as exc:
        raise GceImageManifestError(
            "vulnerability_scan.scanned_at must be an ISO-8601 timestamp"
        ) from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise GceImageManifestError("vulnerability_scan.scanned_at must include a timezone")

    for severity in ("critical", "high"):
        count = scan.get(severity)
        if type(count) is not int or count < 0:
            raise GceImageManifestError(
                f"vulnerability_scan.{severity} must be a non-negative integer"
            )
        if count != 0:
            raise GceImageManifestError(
                f"image release blocked: vulnerability scan reports {count} {severity} findings"
            )

    return GceImageRelease(
        image_self_link=image,
        source_image_self_link=source,
        build_commit=commit,
        build_id=build_id,
        artifact_sha256=digest,
        provenance_uri=provenance,
        scanner=scanner,
        scan_timestamp=scanned_at,
    )


def build_gce_canary_config_from_release_manifest(
    *,
    project_id: str,
    zone: str,
    subnetwork: str,
    release_manifest: Mapping[str, object],
    machine_type: str = "e2-standard-2",
    boot_disk_size_gb: int = 20,
    max_runtime_seconds: int = 300,
    max_console_output_bytes: int = 64 * 1024,
) -> GceCanaryConfig:
    """Construct runtime config only from a structurally valid, project-matched release."""
    release = validate_gce_image_release_manifest(release_manifest)
    image_project = release.image_self_link.split("/")[1]
    if image_project != project_id:
        raise GceImageManifestError(
            "approved release image must belong to the dedicated runtime project"
        )
    return GceCanaryConfig(
        project_id=project_id,
        zone=zone,
        subnetwork=subnetwork,
        approved_image=release.image_self_link,
        machine_type=machine_type,
        boot_disk_size_gb=boot_disk_size_gb,
        max_runtime_seconds=max_runtime_seconds,
        max_console_output_bytes=max_console_output_bytes,
    )
