"""Offline validation for deterministic GCE image build recipes."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit


class GceImageRecipeError(ValueError):
    """Raised when a proposed reproducible image recipe is incomplete or unsafe."""


_PROJECT = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
_IMAGE = re.compile(
    rf"^projects/{_PROJECT}/global/images/[a-z][a-z0-9-]{{0,61}}[a-z0-9]$"
)
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OCI_IMAGE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]{1,5})?/"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"@sha256:[0-9a-f]{64}$"
)
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


@dataclass(frozen=True)
class GceImageReproducibilityRecipe:
    """Validated immutable recipe inputs and canonical recipe digest."""

    schema_version: int
    base_image_self_link: str
    source_commit: str
    input_lock_sha256: str
    builder_image: str
    toolchain_version: str
    build_type: str
    source_date_epoch: int
    platform: str
    recipe_sha256: str


def validate_gce_image_reproducibility_recipe(
    data: Mapping[str, object],
) -> GceImageReproducibilityRecipe:
    """Validate a deterministic build contract without executing a build."""
    if not isinstance(data, Mapping):
        raise GceImageRecipeError("build recipe must be an object")

    allowed = {
        "schema_version",
        "base_image_self_link",
        "source_commit",
        "input_lock_sha256",
        "builder_image",
        "toolchain_version",
        "build_type",
        "source_date_epoch",
        "platform",
        "network_access",
        "environment",
    }
    unknown = set(data) - allowed
    if unknown:
        raise GceImageRecipeError(
            "build recipe contains unknown fields: "
            + ", ".join(sorted(str(field) for field in unknown))
        )

    version = data.get("schema_version")
    if type(version) is not int or version != 1:
        raise GceImageRecipeError("schema_version must be integer 1")

    def required_text(field: str) -> str:
        value = data.get(field)
        if not isinstance(value, str) or not value or value != value.strip():
            raise GceImageRecipeError(
                f"{field} must be a non-empty string without surrounding whitespace"
            )
        return value

    base_image = required_text("base_image_self_link")
    if not _IMAGE.fullmatch(base_image):
        raise GceImageRecipeError("base_image_self_link must identify one exact GCE image")

    source_commit = required_text("source_commit")
    if not _COMMIT.fullmatch(source_commit):
        raise GceImageRecipeError("source_commit must be a full 40- or 64-character Git SHA")

    lock_digest = required_text("input_lock_sha256")
    if not _SHA256.fullmatch(lock_digest):
        raise GceImageRecipeError("input_lock_sha256 must be a lowercase SHA-256 digest")

    builder_image = required_text("builder_image")
    if not _OCI_IMAGE.fullmatch(builder_image):
        raise GceImageRecipeError("builder_image must be an OCI image reference pinned by sha256 digest")

    toolchain_version = required_text("toolchain_version")
    if not _VERSION.fullmatch(toolchain_version):
        raise GceImageRecipeError("toolchain_version must be an exact numeric x.y.z version")

    build_type = required_text("build_type")
    parsed = urlsplit(build_type)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise GceImageRecipeError("build_type must be an HTTPS URI without embedded credentials")

    epoch = data.get("source_date_epoch")
    if type(epoch) is not int or epoch < 0:
        raise GceImageRecipeError("source_date_epoch must be a non-negative integer")

    platform = data.get("platform")
    if platform not in ("linux/amd64", "linux/arm64"):
        raise GceImageRecipeError("platform must be linux/amd64 or linux/arm64")

    if data.get("network_access") is not False:
        raise GceImageRecipeError("network_access must be false for deterministic builds")

    environment = data.get("environment")
    if not isinstance(environment, Mapping):
        raise GceImageRecipeError("environment must be an object")
    expected_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "umask": "0022",
    }
    if dict(environment) != expected_environment:
        raise GceImageRecipeError(
            "environment must set exactly LANG=C.UTF-8, LC_ALL=C.UTF-8, TZ=UTC, and umask=0022"
        )

    try:
        canonical = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise GceImageRecipeError("build recipe cannot be encoded as canonical JSON") from exc

    return GceImageReproducibilityRecipe(
        schema_version=version,
        base_image_self_link=base_image,
        source_commit=source_commit,
        input_lock_sha256=lock_digest,
        builder_image=builder_image,
        toolchain_version=toolchain_version,
        build_type=build_type,
        source_date_epoch=epoch,
        platform=platform,
        recipe_sha256=hashlib.sha256(canonical).hexdigest(),
    )
