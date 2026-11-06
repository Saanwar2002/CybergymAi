"""Offline policy validation for reproducible GCE image build inputs.

This module validates a proposed build plan only. It does not build, scan,
sign, publish, or deploy images and does not contact Google Cloud.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit


class GceImageBuildPolicyError(ValueError):
    """Raised when an image build plan is incomplete or violates release policy."""


_PROJECT = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
_IMAGE_PATH = re.compile(
    rf"^projects/{_PROJECT}/global/images/[a-z][a-z0-9-]{{0,61}}[a-z0-9]$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


@dataclass(frozen=True)
class GceImageBuildPolicy:
    """Validated, immutable inputs and trust identities for a future image build."""

    base_image_self_link: str
    source_commit: str
    input_lock_sha256: str
    builder_id: str
    build_type: str
    scanner_name: str
    scanner_version: str
    max_critical_findings: int
    max_high_findings: int


def _required_text(data: Mapping[str, object], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value or value != value.strip():
        raise GceImageBuildPolicyError(f"{field} must be a non-empty string without surrounding whitespace")
    return value


def _https_identity(value: str, field: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise GceImageBuildPolicyError(f"{field} must be an HTTPS URI without embedded credentials")


def validate_gce_image_build_policy(data: Mapping[str, object]) -> GceImageBuildPolicy:
    """Validate pinned build inputs and fail-closed vulnerability thresholds.

    Exact GCE image self-links are used instead of image families or mutable
    aliases. The input lock digest binds the complete, externally prepared
    dependency lock; this validator does not resolve or verify that file.
    """
    if not isinstance(data, Mapping):
        raise GceImageBuildPolicyError("build policy must be an object")

    base_image = _required_text(data, "base_image_self_link")
    if not _IMAGE_PATH.fullmatch(base_image):
        raise GceImageBuildPolicyError(
            "base_image_self_link must identify one exact GCE image, not a family or alias"
        )

    source_commit = _required_text(data, "source_commit")
    if not _COMMIT.fullmatch(source_commit):
        raise GceImageBuildPolicyError("source_commit must be a full 40- or 64-character Git SHA")

    lock_digest = _required_text(data, "input_lock_sha256")
    if not _SHA256.fullmatch(lock_digest):
        raise GceImageBuildPolicyError("input_lock_sha256 must be a lowercase SHA-256 digest")

    builder_id = _required_text(data, "builder_id")
    _https_identity(builder_id, "builder_id")
    build_type = _required_text(data, "build_type")
    _https_identity(build_type, "build_type")

    scanner_name = _required_text(data, "scanner_name")
    scanner_version = _required_text(data, "scanner_version")

    thresholds = {}
    for field in ("max_critical_findings", "max_high_findings"):
        value = data.get(field)
        if type(value) is not int or value != 0:
            raise GceImageBuildPolicyError(
                f"{field} must be integer 0; critical and high findings block release"
            )
        thresholds[field] = value

    return GceImageBuildPolicy(
        base_image_self_link=base_image,
        source_commit=source_commit,
        input_lock_sha256=lock_digest,
        builder_id=builder_id,
        build_type=build_type,
        scanner_name=scanner_name,
        scanner_version=scanner_version,
        max_critical_findings=thresholds["max_critical_findings"],
        max_high_findings=thresholds["max_high_findings"],
    )
