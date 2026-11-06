import base64
import hashlib
import json
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vulnresearch.execution.gce_image import (
    GceImageManifestError,
    build_gce_canary_config_from_release_manifest,
    build_gce_canary_config_from_signed_release_manifest,
    validate_gce_image_release_manifest,
    verify_gce_image_release_manifest_signature,
)


@pytest.fixture
def manifest():
    return {
        "image_self_link": "projects/cybergym-canary/global/images/cybergym-canary-20261106",
        "source_image_self_link": "projects/cybergym-base/global/images/ubuntu-2404-v20261001",
        "build_commit": "a" * 40,
        "build_id": "build-2026-11-06.1",
        "artifact_sha256": "b" * 64,
        "provenance_uri": "https://attestations.example.invalid/cybergym/build-1",
        "vulnerability_scan": {
            "scanner": "approved-image-scanner",
            "scanned_at": "2026-11-06T12:00:00Z",
            "critical": 0,
            "high": 0,
        },
    }


def test_valid_manifest_returns_immutable_image_identity(manifest):
    release = validate_gce_image_release_manifest(manifest)
    assert release.image_self_link == manifest["image_self_link"]
    assert release.source_image_self_link == manifest["source_image_self_link"]
    assert release.build_commit == "a" * 40


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("image_self_link", "projects/p/global/images/family/my-image"),
        ("image_self_link", "https://example.invalid/projects/p/global/images/image"),
        ("source_image_self_link", "projects/p/global/images/family/ubuntu"),
        ("build_commit", "main"),
        ("build_commit", "a" * 39),
        ("build_id", "../mutable"),
        ("artifact_sha256", "B" * 64),
        ("artifact_sha256", "not-a-digest"),
        ("provenance_uri", "http://attestations.example.invalid/build"),
        ("provenance_uri", "https://user:password@example.invalid/build"),
    ],
)
def test_rejects_mutable_or_malformed_release_identity(manifest, field, value):
    candidate = deepcopy(manifest)
    candidate[field] = value
    with pytest.raises(GceImageManifestError):
        validate_gce_image_release_manifest(candidate)


@pytest.mark.parametrize("severity", ["critical", "high"])
def test_blocks_any_critical_or_high_vulnerability(manifest, severity):
    candidate = deepcopy(manifest)
    candidate["vulnerability_scan"][severity] = 1
    with pytest.raises(GceImageManifestError, match="image release blocked"):
        validate_gce_image_release_manifest(candidate)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("critical", True),
        ("high", -1),
        ("critical", "0"),
    ],
)
def test_scan_counts_must_be_non_negative_integers_not_booleans(manifest, field, value):
    candidate = deepcopy(manifest)
    candidate["vulnerability_scan"][field] = value
    with pytest.raises(GceImageManifestError):
        validate_gce_image_release_manifest(candidate)


@pytest.mark.parametrize(
    "timestamp",
    ["2026-11-06T12:00:00", "not-a-date", "2026-11-06"],
)
def test_scan_timestamp_must_include_timezone(manifest, timestamp):
    candidate = deepcopy(manifest)
    candidate["vulnerability_scan"]["scanned_at"] = timestamp
    with pytest.raises(GceImageManifestError):
        validate_gce_image_release_manifest(candidate)


def test_rejects_source_and_output_image_collision(manifest):
    candidate = deepcopy(manifest)
    candidate["source_image_self_link"] = candidate["image_self_link"]
    with pytest.raises(GceImageManifestError, match="must differ"):
        validate_gce_image_release_manifest(candidate)


def test_rejects_missing_scan_evidence(manifest):
    del manifest["vulnerability_scan"]
    with pytest.raises(GceImageManifestError):
        validate_gce_image_release_manifest(manifest)


def test_runtime_config_uses_exact_image_from_approved_manifest(manifest):
    config = build_gce_canary_config_from_release_manifest(
        project_id="cybergym-canary",
        zone="europe-west2-a",
        subnetwork=(
            "projects/cybergym-canary/regions/europe-west2/subnetworks/cybergym-canary"
        ),
        release_manifest=manifest,
    )
    assert config.approved_image == manifest["image_self_link"]
    assert config.project_id == "cybergym-canary"


def test_runtime_config_rejects_image_published_to_another_project(manifest):
    manifest["image_self_link"] = "projects/other-canary/global/images/approved-image"
    with pytest.raises(GceImageManifestError, match="dedicated runtime project"):
        build_gce_canary_config_from_release_manifest(
            project_id="cybergym-canary",
            zone="europe-west2-a",
            subnetwork=(
                "projects/cybergym-canary/regions/europe-west2/subnetworks/cybergym-canary"
            ),
            release_manifest=manifest,
        )


def test_runtime_config_rejects_manifest_with_high_findings(manifest):
    manifest["vulnerability_scan"]["high"] = 1
    with pytest.raises(GceImageManifestError, match="image release blocked"):
        build_gce_canary_config_from_release_manifest(
            project_id="cybergym-canary",
            zone="europe-west2-a",
            subnetwork=(
                "projects/cybergym-canary/regions/europe-west2/subnetworks/cybergym-canary"
            ),
            release_manifest=manifest,
        )


def _signed_manifest(manifest):
    private_key = Ed25519PrivateKey.generate()
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    signature = base64.b64encode(private_key.sign(payload)).decode("ascii")
    fingerprint = hashlib.sha256(public_key_der).hexdigest()
    return signature, public_key_pem, fingerprint


def test_verifies_ed25519_signature_with_pinned_public_key(manifest):
    signature, public_key, fingerprint = _signed_manifest(manifest)
    release = verify_gce_image_release_manifest_signature(
        manifest,
        signature_base64=signature,
        public_key_pem=public_key,
        expected_public_key_sha256=fingerprint,
    )
    assert release.image_self_link == manifest["image_self_link"]


def test_rejects_manifest_tampering_after_signing(manifest):
    signature, public_key, fingerprint = _signed_manifest(manifest)
    manifest["build_id"] = "different-build"
    with pytest.raises(GceImageManifestError, match="signature is invalid"):
        verify_gce_image_release_manifest_signature(
            manifest,
            signature_base64=signature,
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )


def test_rejects_untrusted_public_key_fingerprint(manifest):
    signature, public_key, _ = _signed_manifest(manifest)
    with pytest.raises(GceImageManifestError, match="fingerprint"):
        verify_gce_image_release_manifest_signature(
            manifest,
            signature_base64=signature,
            public_key_pem=public_key,
            expected_public_key_sha256="0" * 64,
        )


def test_rejects_malformed_signature_encoding(manifest):
    _, public_key, fingerprint = _signed_manifest(manifest)
    with pytest.raises(GceImageManifestError, match="base64"):
        verify_gce_image_release_manifest_signature(
            manifest,
            signature_base64="not base64!",
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )


def test_rejects_non_ed25519_public_key(manifest):
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(GceImageManifestError, match="Ed25519"):
        verify_gce_image_release_manifest_signature(
            manifest,
            signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
            public_key_pem=public_key,
            expected_public_key_sha256="0" * 64,
        )


def test_signed_runtime_config_requires_and_uses_verified_manifest(manifest):
    signature, public_key, fingerprint = _signed_manifest(manifest)
    config = build_gce_canary_config_from_signed_release_manifest(
        project_id="cybergym-canary",
        zone="europe-west2-a",
        subnetwork=(
            "projects/cybergym-canary/regions/europe-west2/subnetworks/cybergym-canary"
        ),
        release_manifest=manifest,
        signature_base64=signature,
        public_key_pem=public_key,
        expected_public_key_sha256=fingerprint,
    )
    assert config.approved_image == manifest["image_self_link"]


def test_signed_runtime_config_rejects_invalid_signature(manifest):
    _signature, public_key, fingerprint = _signed_manifest(manifest)
    with pytest.raises(GceImageManifestError, match="signature is invalid"):
        build_gce_canary_config_from_signed_release_manifest(
            project_id="cybergym-canary",
            zone="europe-west2-a",
            subnetwork=(
                "projects/cybergym-canary/regions/europe-west2/subnetworks/cybergym-canary"
            ),
            release_manifest=manifest,
            signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )
