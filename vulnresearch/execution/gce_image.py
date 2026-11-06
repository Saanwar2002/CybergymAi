"""Fail-closed validation for an offline GCE canary image release manifest.

This module validates evidence supplied by a future image build pipeline. It does not
build, publish, sign, scan, or deploy an image and does not contact Google Cloud.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from vulnresearch.execution.gce import GceCanaryConfig
from vulnresearch.execution.gce_image_build import validate_gce_image_build_policy
from vulnresearch.execution.gce_image_recipe import validate_gce_image_reproducibility_recipe


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
    scanner_version: str
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
    scanner_version = scan.get("scanner_version")
    scanned_at = scan.get("scanned_at")
    if not isinstance(scanner, str) or not scanner.strip():
        raise GceImageManifestError("vulnerability_scan.scanner must be non-empty")
    if (
        not isinstance(scanner_version, str)
        or not scanner_version
        or scanner_version != scanner_version.strip()
    ):
        raise GceImageManifestError(
            "vulnerability_scan.scanner_version must be a non-empty exact version"
        )
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
        scanner_version=scanner_version,
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


def verify_gce_image_release_manifest_signature(
    data: Mapping[str, object],
    *,
    signature_base64: str,
    public_key_pem: str | bytes,
    expected_public_key_sha256: str,
) -> GceImageRelease:
    """Validate a manifest and its detached Ed25519 signature against a pinned key.

    The expected fingerprint is an out-of-band trust anchor. Supplying an arbitrary
    public key and its matching fingerprint proves possession only, not publisher identity.
    The signature covers canonical UTF-8 JSON (sorted keys, compact separators).
    """
    release = validate_gce_image_release_manifest(data)
    if not isinstance(expected_public_key_sha256, str) or not _SHA256.fullmatch(
        expected_public_key_sha256
    ):
        raise GceImageManifestError(
            "expected_public_key_sha256 must be a lowercase SHA-256 fingerprint"
        )
    if not isinstance(signature_base64, str) or not signature_base64:
        raise GceImageManifestError("signature_base64 must be a non-empty base64 string")
    try:
        signature = base64.b64decode(signature_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise GceImageManifestError("signature_base64 is malformed") from exc

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError as exc:
        raise GceImageManifestError(
            "Ed25519 verification requires the optional image-signing dependency"
        ) from exc

    try:
        pem_bytes = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
        if not isinstance(pem_bytes, bytes):
            raise TypeError("public_key_pem must be text or bytes")
        public_key = load_pem_public_key(pem_bytes)
    except (TypeError, ValueError) as exc:
        raise GceImageManifestError("public_key_pem is not a valid PEM public key") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise GceImageManifestError("public_key_pem must contain an Ed25519 public key")

    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_key_der).hexdigest()
    if fingerprint != expected_public_key_sha256:
        raise GceImageManifestError("image signing key fingerprint does not match trust policy")

    try:
        payload = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise GceImageManifestError("manifest cannot be encoded as canonical JSON") from exc
    try:
        public_key.verify(signature, payload)
    except InvalidSignature as exc:
        raise GceImageManifestError("image release manifest signature is invalid") from exc
    return release


def build_gce_canary_config_from_signed_release_manifest(
    *,
    project_id: str,
    zone: str,
    subnetwork: str,
    release_manifest: Mapping[str, object],
    signature_base64: str,
    public_key_pem: str | bytes,
    expected_public_key_sha256: str,
    machine_type: str = "e2-standard-2",
    boot_disk_size_gb: int = 20,
    max_runtime_seconds: int = 300,
    max_console_output_bytes: int = 64 * 1024,
) -> GceCanaryConfig:
    """Build canary config only after manifest signature and pinned-key verification."""
    verify_gce_image_release_manifest_signature(
        release_manifest,
        signature_base64=signature_base64,
        public_key_pem=public_key_pem,
        expected_public_key_sha256=expected_public_key_sha256,
    )
    return build_gce_canary_config_from_release_manifest(
        project_id=project_id,
        zone=zone,
        subnetwork=subnetwork,
        release_manifest=release_manifest,
        machine_type=machine_type,
        boot_disk_size_gb=boot_disk_size_gb,
        max_runtime_seconds=max_runtime_seconds,
        max_console_output_bytes=max_console_output_bytes,
    )


def validate_slsa_provenance_statement(
    statement: Mapping[str, object],
    *,
    release_manifest: Mapping[str, object],
    expected_builder_id: str,
    expected_build_type: str | None = None,
    expected_input_lock_sha256: str | None = None,
    expected_base_image_self_link: str | None = None,
    expected_recipe_sha256: str | None = None,
    expected_builder_image: str | None = None,
) -> GceImageRelease:
    """Validate an offline SLSA provenance v1 statement against a release and trusted builder.

    This validates the statement's shape and identity bindings. It does not
    authenticate the statement; callers must obtain it through an authenticated
    channel or verify a separate DSSE/in-toto envelope before trusting it.
    """
    release = validate_gce_image_release_manifest(release_manifest)
    if not isinstance(statement, Mapping):
        raise GceImageManifestError("provenance statement must be an object")
    if not isinstance(expected_builder_id, str) or not expected_builder_id.strip():
        raise GceImageManifestError("expected_builder_id must be a non-empty trusted identity")
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise GceImageManifestError("provenance statement must use in-toto Statement v1")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise GceImageManifestError("provenance statement must contain exactly one subject")
    subject = subjects[0]
    if not isinstance(subject, Mapping) or subject.get("name") != release.image_self_link:
        raise GceImageManifestError("provenance subject does not match the approved image")
    subject_digest = subject.get("digest")
    if not isinstance(subject_digest, Mapping) or subject_digest.get("sha256") != release.artifact_sha256:
        raise GceImageManifestError("provenance subject digest does not match the release manifest")

    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise GceImageManifestError("provenance predicate must use SLSA provenance v1")
    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        raise GceImageManifestError("provenance predicate must be an object")
    build_definition = predicate.get("buildDefinition")
    if not isinstance(build_definition, Mapping):
        raise GceImageManifestError("provenance buildDefinition must be an object")
    build_type = build_definition.get("buildType")
    if not isinstance(build_type, str) or not build_type.startswith("https://"):
        raise GceImageManifestError("provenance buildType must be an HTTPS URI")
    if expected_build_type is not None and build_type != expected_build_type:
        raise GceImageManifestError("provenance buildType does not match build policy")

    dependencies = build_definition.get("resolvedDependencies")
    if not isinstance(dependencies, list):
        raise GceImageManifestError("provenance resolvedDependencies must be a list")
    matching_commit = False
    matching_lock = False
    matching_base_image = False
    matching_recipe = False
    matching_builder_image = False
    for dependency in dependencies:
        if not isinstance(dependency, Mapping):
            continue
        digest = dependency.get("digest")
        if isinstance(digest, Mapping):
            if digest.get("gitCommit") == release.build_commit:
                matching_commit = True
            if (
                expected_input_lock_sha256 is not None
                and digest.get("sha256") == expected_input_lock_sha256
            ):
                matching_lock = True
            if (
                expected_recipe_sha256 is not None
                and digest.get("sha256") == expected_recipe_sha256
            ):
                matching_recipe = True
        if (
            expected_base_image_self_link is not None
            and dependency.get("uri") == expected_base_image_self_link
        ):
            matching_base_image = True
        if (
            expected_builder_image is not None
            and dependency.get("uri") == expected_builder_image
        ):
            matching_builder_image = True
    if not matching_commit:
        raise GceImageManifestError(
            "provenance resolvedDependencies do not bind the manifest build commit"
        )
    if expected_input_lock_sha256 is not None and not matching_lock:
        raise GceImageManifestError(
            "provenance resolvedDependencies do not bind the policy dependency lock digest"
        )
    if expected_base_image_self_link is not None and not matching_base_image:
        raise GceImageManifestError(
            "provenance resolvedDependencies do not bind the policy base image"
        )
    if expected_builder_image is not None and not matching_builder_image:
        raise GceImageManifestError(
            "provenance resolvedDependencies do not bind the pinned builder image"
        )
    if expected_recipe_sha256 is not None and not matching_recipe:
        raise GceImageManifestError(
            "provenance resolvedDependencies do not bind the reproducibility recipe digest"
        )

    run_details = predicate.get("runDetails")
    if not isinstance(run_details, Mapping):
        raise GceImageManifestError("provenance runDetails must be an object")
    builder = run_details.get("builder")
    if not isinstance(builder, Mapping) or builder.get("id") != expected_builder_id:
        raise GceImageManifestError("provenance builder identity does not match trust policy")
    metadata = run_details.get("metadata")
    if not isinstance(metadata, Mapping) or metadata.get("invocationId") != release.build_id:
        raise GceImageManifestError(
            "provenance invocationId does not match the release manifest build_id"
        )
    return release


def verify_dsse_slsa_provenance_envelope(
    envelope: Mapping[str, object],
    *,
    release_manifest: Mapping[str, object],
    expected_builder_id: str,
    public_key_pem: str | bytes,
    expected_public_key_sha256: str,
    max_payload_bytes: int = 1024 * 1024,
    expected_build_type: str | None = None,
    expected_input_lock_sha256: str | None = None,
    expected_base_image_self_link: str | None = None,
    expected_recipe_sha256: str | None = None,
    expected_builder_image: str | None = None,
) -> GceImageRelease:
    """Verify one DSSE Ed25519 signature, then validate its SLSA provenance payload.

    The key fingerprint and builder ID are independent trust policy inputs.
    This accepts exactly one DSSE signature whose keyid equals the pinned key
    fingerprint, and rejects duplicate JSON object keys in the signed payload.
    """
    if not isinstance(envelope, Mapping):
        raise GceImageManifestError("DSSE envelope must be an object")
    if envelope.get("payloadType") != "application/vnd.in-toto+json":
        raise GceImageManifestError("DSSE payloadType must be application/vnd.in-toto+json")
    if type(max_payload_bytes) is not int or max_payload_bytes <= 0:
        raise GceImageManifestError("max_payload_bytes must be a positive integer")
    encoded_payload = envelope.get("payload")
    if not isinstance(encoded_payload, str) or not encoded_payload:
        raise GceImageManifestError("DSSE payload must be non-empty base64 text")
    if len(encoded_payload) > ((max_payload_bytes + 2) // 3) * 4:
        raise GceImageManifestError("DSSE payload exceeds the configured size limit")
    try:
        payload = base64.b64decode(encoded_payload, validate=True)
    except (ValueError, TypeError) as exc:
        raise GceImageManifestError("DSSE payload is malformed base64") from exc
    if len(payload) > max_payload_bytes:
        raise GceImageManifestError("DSSE payload exceeds the configured size limit")

    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise GceImageManifestError("DSSE envelope must contain exactly one signature")
    signature_record = signatures[0]
    if not isinstance(signature_record, Mapping):
        raise GceImageManifestError("DSSE signature record must be an object")
    signature_text = signature_record.get("sig")
    key_id = signature_record.get("keyid")
    if not isinstance(signature_text, str) or not signature_text:
        raise GceImageManifestError("DSSE signature must be non-empty base64 text")
    if not isinstance(expected_public_key_sha256, str) or not _SHA256.fullmatch(
        expected_public_key_sha256
    ):
        raise GceImageManifestError("expected_public_key_sha256 must be a lowercase SHA-256 fingerprint")
    if key_id != expected_public_key_sha256:
        raise GceImageManifestError("DSSE keyid does not match the pinned public-key fingerprint")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, TypeError) as exc:
        raise GceImageManifestError("DSSE signature is malformed base64") from exc

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError as exc:
        raise GceImageManifestError(
            "DSSE verification requires the optional image-signing dependency"
        ) from exc
    try:
        pem_bytes = (
            public_key_pem.encode("utf-8")
            if isinstance(public_key_pem, str)
            else public_key_pem
        )
        if not isinstance(pem_bytes, bytes):
            raise TypeError("public_key_pem must be text or bytes")
        public_key = load_pem_public_key(pem_bytes)
    except (TypeError, ValueError) as exc:
        raise GceImageManifestError("public_key_pem is not a valid PEM public key") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise GceImageManifestError("public_key_pem must contain an Ed25519 public key")
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_key_der).hexdigest()
    if fingerprint != expected_public_key_sha256:
        raise GceImageManifestError("image signing key fingerprint does not match trust policy")

    payload_type = b"application/vnd.in-toto+json"
    pae = (
        b"DSSEv1 "
        + str(len(payload_type)).encode("ascii")
        + b" "
        + payload_type
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )
    try:
        public_key.verify(signature, pae)
    except InvalidSignature as exc:
        raise GceImageManifestError("DSSE provenance signature is invalid") from exc

    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        statement = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise GceImageManifestError("DSSE payload must be unambiguous UTF-8 JSON") from exc
    if not isinstance(statement, Mapping):
        raise GceImageManifestError("DSSE payload must contain a provenance statement object")
    return validate_slsa_provenance_statement(
        statement,
        release_manifest=release_manifest,
        expected_builder_id=expected_builder_id,
        expected_build_type=expected_build_type,
        expected_input_lock_sha256=expected_input_lock_sha256,
        expected_base_image_self_link=expected_base_image_self_link,
        expected_recipe_sha256=expected_recipe_sha256,
        expected_builder_image=expected_builder_image,
    )


def build_gce_canary_config_from_verified_release_evidence(
    *,
    project_id: str,
    zone: str,
    subnetwork: str,
    release_manifest: Mapping[str, object],
    manifest_signature_base64: str,
    manifest_public_key_pem: str | bytes,
    expected_manifest_key_sha256: str,
    provenance_envelope: Mapping[str, object],
    provenance_public_key_pem: str | bytes,
    expected_provenance_key_sha256: str,
    expected_builder_id: str,
    machine_type: str = "e2-standard-2",
    boot_disk_size_gb: int = 20,
    max_runtime_seconds: int = 300,
    max_console_output_bytes: int = 64 * 1024,
) -> GceCanaryConfig:
    """Construct canary config only after manifest and provenance authenticity checks."""
    verify_gce_image_release_manifest_signature(
        release_manifest,
        signature_base64=manifest_signature_base64,
        public_key_pem=manifest_public_key_pem,
        expected_public_key_sha256=expected_manifest_key_sha256,
    )
    verify_dsse_slsa_provenance_envelope(
        provenance_envelope,
        release_manifest=release_manifest,
        expected_builder_id=expected_builder_id,
        public_key_pem=provenance_public_key_pem,
        expected_public_key_sha256=expected_provenance_key_sha256,
    )
    return build_gce_canary_config_from_release_manifest(
        project_id=project_id,
        zone=zone,
        subnetwork=subnetwork,
        release_manifest=release_manifest,
        machine_type=machine_type,
        boot_disk_size_gb=boot_disk_size_gb,
        max_runtime_seconds=max_runtime_seconds,
        max_console_output_bytes=max_console_output_bytes,
    )


def verify_dsse_slsa_provenance_for_build_policy(
    envelope: Mapping[str, object],
    *,
    release_manifest: Mapping[str, object],
    build_policy: Mapping[str, object],
    public_key_pem: str | bytes,
    expected_public_key_sha256: str,
) -> GceImageRelease:
    """Verify signed provenance and bind it to every immutable build-policy input."""
    policy = validate_gce_image_build_policy(build_policy)
    release = validate_gce_image_release_manifest(release_manifest)
    if release.build_commit != policy.source_commit:
        raise GceImageManifestError(
            "release manifest build commit does not match build policy source_commit"
        )
    if release.scanner != policy.scanner_name:
        raise GceImageManifestError(
            "release manifest scanner does not match build policy scanner_name"
        )
    if release.scanner_version != policy.scanner_version:
        raise GceImageManifestError(
            "release manifest scanner_version does not match build policy scanner_version"
        )
    return verify_dsse_slsa_provenance_envelope(
        envelope,
        release_manifest=release_manifest,
        expected_builder_id=policy.builder_id,
        public_key_pem=public_key_pem,
        expected_public_key_sha256=expected_public_key_sha256,
        expected_build_type=policy.build_type,
        expected_input_lock_sha256=policy.input_lock_sha256,
        expected_base_image_self_link=policy.base_image_self_link,
    )


def verify_dsse_slsa_provenance_for_reproducible_recipe(
    envelope: Mapping[str, object],
    *,
    release_manifest: Mapping[str, object],
    build_policy: Mapping[str, object],
    reproducibility_recipe: Mapping[str, object],
    public_key_pem: str | bytes,
    expected_public_key_sha256: str,
) -> GceImageRelease:
    """Verify signed provenance against the build policy and canonical recipe digest."""
    policy = validate_gce_image_build_policy(build_policy)
    recipe = validate_gce_image_reproducibility_recipe(reproducibility_recipe)
    release = validate_gce_image_release_manifest(release_manifest)
    if release.build_commit != policy.source_commit:
        raise GceImageManifestError(
            "release manifest build commit does not match build policy source_commit"
        )
    if release.scanner != policy.scanner_name:
        raise GceImageManifestError(
            "release manifest scanner does not match build policy scanner_name"
        )
    if release.scanner_version != policy.scanner_version:
        raise GceImageManifestError(
            "release manifest scanner_version does not match build policy scanner_version"
        )
    recipe_bindings = {
        "base_image_self_link": policy.base_image_self_link,
        "source_commit": policy.source_commit,
        "input_lock_sha256": policy.input_lock_sha256,
        "build_type": policy.build_type,
    }
    for field, expected in recipe_bindings.items():
        if getattr(recipe, field) != expected:
            raise GceImageManifestError(
                f"reproducibility recipe {field} does not match build policy"
            )
    return verify_dsse_slsa_provenance_envelope(
        envelope,
        release_manifest=release_manifest,
        expected_builder_id=policy.builder_id,
        public_key_pem=public_key_pem,
        expected_public_key_sha256=expected_public_key_sha256,
        expected_build_type=policy.build_type,
        expected_input_lock_sha256=policy.input_lock_sha256,
        expected_base_image_self_link=policy.base_image_self_link,
        expected_recipe_sha256=recipe.recipe_sha256,
        expected_builder_image=recipe.builder_image,
    )



def sha256_artifact_file(path: str | Path) -> tuple[str, int]:
    """Hash a stable regular artifact file incrementally without following symlinks."""
    artifact_path = Path(path)
    if artifact_path.is_symlink() or not artifact_path.is_file():
        raise GceImageManifestError("artifact path must be a regular, non-symlink file")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(artifact_path, flags)
    except OSError as exc:
        raise GceImageManifestError(
            "artifact path must be a readable regular, non-symlink file"
        ) from exc

    digest = hashlib.sha256()
    total_bytes = 0
    try:
        with os.fdopen(descriptor, "rb") as artifact:
            before = os.fstat(artifact.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise GceImageManifestError(
                    "artifact path must be a regular, non-symlink file"
                )
            if before.st_size <= 0:
                raise GceImageManifestError("artifact file must not be empty")
            while chunk := artifact.read(1024 * 1024):
                digest.update(chunk)
                total_bytes += len(chunk)
            after = os.fstat(artifact.fileno())
    except OSError as exc:
        raise GceImageManifestError(
            "unable to read artifact file for SHA-256 verification"
        ) from exc

    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise GceImageManifestError("artifact file changed while its SHA-256 was being computed")
    if total_bytes != before.st_size:
        raise GceImageManifestError("artifact file size changed while it was being hashed")
    return digest.hexdigest(), total_bytes

def verify_gce_image_reproducibility_pair(
    *,
    build_policy: Mapping[str, object],
    reproducibility_recipe: Mapping[str, object],
    first_release_manifest: Mapping[str, object],
    first_provenance_envelope: Mapping[str, object],
    second_release_manifest: Mapping[str, object],
    second_provenance_envelope: Mapping[str, object],
    first_manifest_signature_base64: str,
    second_manifest_signature_base64: str,
    manifest_public_key_pem: str | bytes,
    expected_manifest_public_key_sha256: str,
    first_artifact_sha256: str,
    second_artifact_sha256: str,
    public_key_pem: str | bytes,
    expected_public_key_sha256: str,
) -> tuple[GceImageRelease, GceImageRelease]:
    """Verify signed manifests and provenance for two builds, then compare artifact digests."""
    if expected_manifest_public_key_sha256 == expected_public_key_sha256:
        raise GceImageManifestError(
            "manifest and provenance signing keys must be separate trust anchors"
        )
    first = verify_gce_image_release_manifest_signature(
        first_release_manifest,
        signature_base64=first_manifest_signature_base64,
        public_key_pem=manifest_public_key_pem,
        expected_public_key_sha256=expected_manifest_public_key_sha256,
    )
    second = verify_gce_image_release_manifest_signature(
        second_release_manifest,
        signature_base64=second_manifest_signature_base64,
        public_key_pem=manifest_public_key_pem,
        expected_public_key_sha256=expected_manifest_public_key_sha256,
    )
    first = verify_dsse_slsa_provenance_for_reproducible_recipe(
        first_provenance_envelope,
        release_manifest=first_release_manifest,
        build_policy=build_policy,
        reproducibility_recipe=reproducibility_recipe,
        public_key_pem=public_key_pem,
        expected_public_key_sha256=expected_public_key_sha256,
    )
    second = verify_dsse_slsa_provenance_for_reproducible_recipe(
        second_provenance_envelope,
        release_manifest=second_release_manifest,
        build_policy=build_policy,
        reproducibility_recipe=reproducibility_recipe,
        public_key_pem=public_key_pem,
        expected_public_key_sha256=expected_public_key_sha256,
    )

    if not isinstance(first_artifact_sha256, str) or not _SHA256.fullmatch(
        first_artifact_sha256
    ):
        raise GceImageManifestError("first artifact SHA-256 must be a lowercase digest")
    if not isinstance(second_artifact_sha256, str) or not _SHA256.fullmatch(
        second_artifact_sha256
    ):
        raise GceImageManifestError("second artifact SHA-256 must be a lowercase digest")
    if first_artifact_sha256 != first.artifact_sha256:
        raise GceImageManifestError(
            "first artifact bytes do not match the signed release SHA-256 digest"
        )
    if second_artifact_sha256 != second.artifact_sha256:
        raise GceImageManifestError(
            "second artifact bytes do not match the signed release SHA-256 digest"
        )
    if first.build_id == second.build_id:
        raise GceImageManifestError(
            "reproducibility evidence must identify two distinct build IDs"
        )
    if first.build_commit != second.build_commit:
        raise GceImageManifestError(
            "independent builds do not use the same source commit"
        )
    if first.source_image_self_link != second.source_image_self_link:
        raise GceImageManifestError(
            "independent builds do not use the same source base image"
        )
    if first.artifact_sha256 != second.artifact_sha256:
        raise GceImageManifestError(
            "independent build artifact SHA-256 digests do not match"
        )
    return first, second
