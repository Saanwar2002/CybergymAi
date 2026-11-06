import base64
import hashlib
import json
import os
import sys
from copy import deepcopy
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vulnresearch.cli import main
from vulnresearch.execution.gce_image import (
    GceImageManifestError,
    build_gce_canary_config_from_release_manifest,
    build_gce_canary_config_from_signed_release_manifest,
    build_gce_canary_config_from_verified_release_evidence,
    sha256_artifact_file,
    validate_gce_image_release_manifest,
    validate_slsa_provenance_statement,
    verify_dsse_slsa_provenance_envelope,
    verify_dsse_slsa_provenance_for_build_policy,
    verify_dsse_slsa_provenance_for_reproducible_recipe,
    verify_gce_image_release_manifest_signature,
    verify_gce_image_reproducibility_pair,
)
from vulnresearch.execution.gce_image_recipe import validate_gce_image_reproducibility_recipe


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
            "scanner_version": "1.2.3",
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


def _signed_manifest(manifest, private_key=None):
    if private_key is None:
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



def _reproducibility_recipe_for_manifest(manifest):
    return {
        "schema_version": 1,
        "base_image_self_link": "projects/cybergym-base/global/images/ubuntu-2404-v20261001",
        "source_commit": manifest["build_commit"],
        "input_lock_sha256": "b" * 64,
        "builder_image": "us-docker.pkg.dev/cybergym/builders/packer@sha256:" + "c" * 64,
        "toolchain_version": "1.2.3",
        "build_type": "https://example.invalid/build-types/gce-image/v1",
        "source_date_epoch": 1793966400,
        "platform": "linux/amd64",
        "network_access": False,
        "environment": {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "umask": "0022",
        },
    }


def _slsa_statement(manifest):
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": manifest["image_self_link"],
                "digest": {"sha256": manifest["artifact_sha256"]},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://example.invalid/build-types/gce-image/v1",
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/example/repository",
                        "digest": {"gitCommit": manifest["build_commit"]},
                    },
                    {
                        "uri": "projects/cybergym-base/global/images/ubuntu-2404-v20261001",
                    },
                    {
                        "uri": "https://example.invalid/locks/requirements.lock",
                        "digest": {"sha256": "b" * 64},
                    },
                    {
                        "uri": _reproducibility_recipe_for_manifest(manifest)["builder_image"],
                    },
                    {
                        "uri": "https://example.invalid/attestations/reproducible-build-recipe",
                        "digest": {
                            "sha256": validate_gce_image_reproducibility_recipe(
                                _reproducibility_recipe_for_manifest(manifest)
                            ).recipe_sha256
                        },
                    },
                ],
            },
            "runDetails": {
                "builder": {"id": "https://builder.example.invalid/production"},
                "metadata": {"invocationId": manifest["build_id"]},
            },
        },
    }


def test_validates_slsa_provenance_subject_digest_commit_and_builder(manifest):
    statement = _slsa_statement(manifest)
    release = validate_slsa_provenance_statement(
        statement,
        release_manifest=manifest,
        expected_builder_id="https://builder.example.invalid/production",
    )
    assert release.image_self_link == manifest["image_self_link"]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda item: item["subject"][0].update(name="projects/other/global/images/wrong"),
         "subject does not match"),
        (lambda item: item["subject"][0]["digest"].update(sha256="0" * 64),
         "subject digest does not match"),
        (lambda item: item["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"].update(
            gitCommit="f" * 40
        ), "do not bind"),
        (lambda item: item["predicate"]["runDetails"]["builder"].update(
            id="https://attacker.example.invalid/builder"
        ), "builder identity"),
    ],
)
def test_rejects_slsa_provenance_identity_mismatch(manifest, mutate, message):
    statement = _slsa_statement(manifest)
    mutate(statement)
    with pytest.raises(GceImageManifestError, match=message):
        validate_slsa_provenance_statement(
            statement,
            release_manifest=manifest,
            expected_builder_id="https://builder.example.invalid/production",
        )


def test_rejects_wrong_slsa_statement_type(manifest):
    statement = _slsa_statement(manifest)
    statement["_type"] = "https://in-toto.io/Statement/v0.1"
    with pytest.raises(GceImageManifestError, match="Statement v1"):
        validate_slsa_provenance_statement(
            statement,
            release_manifest=manifest,
            expected_builder_id="https://builder.example.invalid/production",
        )


def _signed_dsse_envelope(manifest, private_key=None):
    if private_key is None:
        private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_key_der).hexdigest()
    payload = json.dumps(
        _slsa_statement(manifest), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    payload_type = b"application/vnd.in-toto+json"
    pae = (
        b"DSSEv1 " + str(len(payload_type)).encode("ascii") + b" "
        + payload_type + b" " + str(len(payload)).encode("ascii") + b" " + payload
    )
    envelope = {
        "payloadType": payload_type.decode("ascii"),
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{
            "keyid": fingerprint,
            "sig": base64.b64encode(private_key.sign(pae)).decode("ascii"),
        }],
    }
    return envelope, public_key_pem, fingerprint, private_key


def test_verifies_dsse_slsa_envelope_with_pinned_signer(manifest):
    envelope, public_key, fingerprint, _private_key = _signed_dsse_envelope(manifest)
    release = verify_dsse_slsa_provenance_envelope(
        envelope,
        release_manifest=manifest,
        expected_builder_id="https://builder.example.invalid/production",
        public_key_pem=public_key,
        expected_public_key_sha256=fingerprint,
    )
    assert release.image_self_link == manifest["image_self_link"]


def test_rejects_dsse_payload_tampering(manifest):
    envelope, public_key, fingerprint, _private_key = _signed_dsse_envelope(manifest)
    statement = _slsa_statement(manifest)
    statement["subject"][0]["name"] = "projects/other/global/images/forged"
    envelope["payload"] = base64.b64encode(
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    with pytest.raises(GceImageManifestError, match="DSSE provenance signature is invalid"):
        verify_dsse_slsa_provenance_envelope(
            envelope,
            release_manifest=manifest,
            expected_builder_id="https://builder.example.invalid/production",
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )


def test_rejects_dsse_key_id_not_matching_pinned_key(manifest):
    envelope, public_key, fingerprint, _private_key = _signed_dsse_envelope(manifest)
    envelope["signatures"][0]["keyid"] = "0" * 64
    with pytest.raises(GceImageManifestError, match="keyid"):
        verify_dsse_slsa_provenance_envelope(
            envelope,
            release_manifest=manifest,
            expected_builder_id="https://builder.example.invalid/production",
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )


def test_rejects_dsse_duplicate_json_keys(manifest):
    envelope, public_key, fingerprint, private_key = _signed_dsse_envelope(manifest)
    payload = (
        b'{"_type":"https://in-toto.io/Statement/v1",'
        b'"_type":"https://in-toto.io/Statement/v1"}'
    )
    payload_type = b"application/vnd.in-toto+json"
    pae = (
        b"DSSEv1 " + str(len(payload_type)).encode("ascii") + b" "
        + payload_type + b" " + str(len(payload)).encode("ascii") + b" " + payload
    )
    envelope["payload"] = base64.b64encode(payload).decode("ascii")
    envelope["signatures"][0]["sig"] = base64.b64encode(
        private_key.sign(pae)
    ).decode("ascii")
    with pytest.raises(GceImageManifestError, match="unambiguous UTF-8 JSON"):
        verify_dsse_slsa_provenance_envelope(
            envelope,
            release_manifest=manifest,
            expected_builder_id="https://builder.example.invalid/production",
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )


def test_rejects_dsse_oversized_payload(manifest):
    envelope, public_key, fingerprint, _private_key = _signed_dsse_envelope(manifest)
    with pytest.raises(GceImageManifestError, match="size limit"):
        verify_dsse_slsa_provenance_envelope(
            envelope,
            release_manifest=manifest,
            expected_builder_id="https://builder.example.invalid/production",
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
            max_payload_bytes=10,
        )


def test_runtime_config_requires_signed_manifest_and_authenticated_provenance(manifest):
    manifest_signature, manifest_public_key, manifest_fingerprint = _signed_manifest(manifest)
    envelope, provenance_public_key, provenance_fingerprint, _private_key = (
        _signed_dsse_envelope(manifest)
    )
    config = build_gce_canary_config_from_verified_release_evidence(
        project_id="cybergym-canary",
        zone="europe-west2-a",
        subnetwork=(
            "projects/cybergym-canary/regions/europe-west2/subnetworks/cybergym-canary"
        ),
        release_manifest=manifest,
        manifest_signature_base64=manifest_signature,
        manifest_public_key_pem=manifest_public_key,
        expected_manifest_key_sha256=manifest_fingerprint,
        provenance_envelope=envelope,
        provenance_public_key_pem=provenance_public_key,
        expected_provenance_key_sha256=provenance_fingerprint,
        expected_builder_id="https://builder.example.invalid/production",
    )
    assert config.approved_image == manifest["image_self_link"]


def test_runtime_config_rejects_valid_manifest_signature_but_invalid_provenance(manifest):
    manifest_signature, manifest_public_key, manifest_fingerprint = _signed_manifest(manifest)
    envelope, provenance_public_key, provenance_fingerprint, _private_key = (
        _signed_dsse_envelope(manifest)
    )
    envelope["payload"] = base64.b64encode(b'{"forged":true}').decode("ascii")
    with pytest.raises(GceImageManifestError, match="DSSE provenance signature is invalid"):
        build_gce_canary_config_from_verified_release_evidence(
            project_id="cybergym-canary",
            zone="europe-west2-a",
            subnetwork=(
                "projects/cybergym-canary/regions/europe-west2/subnetworks/cybergym-canary"
            ),
            release_manifest=manifest,
            manifest_signature_base64=manifest_signature,
            manifest_public_key_pem=manifest_public_key,
            expected_manifest_key_sha256=manifest_fingerprint,
            provenance_envelope=envelope,
            provenance_public_key_pem=provenance_public_key,
            expected_provenance_key_sha256=provenance_fingerprint,
            expected_builder_id="https://builder.example.invalid/production",
        )


def test_runtime_config_rejects_valid_provenance_but_invalid_manifest_signature(manifest):
    _, manifest_public_key, manifest_fingerprint = _signed_manifest(manifest)
    envelope, provenance_public_key, provenance_fingerprint, _private_key = (
        _signed_dsse_envelope(manifest)
    )
    with pytest.raises(GceImageManifestError, match="signature is invalid"):
        build_gce_canary_config_from_verified_release_evidence(
            project_id="cybergym-canary",
            zone="europe-west2-a",
            subnetwork=(
                "projects/cybergym-canary/regions/europe-west2/subnetworks/cybergym-canary"
            ),
            release_manifest=manifest,
            manifest_signature_base64=base64.b64encode(b"x" * 64).decode("ascii"),
            manifest_public_key_pem=manifest_public_key,
            expected_manifest_key_sha256=manifest_fingerprint,
            provenance_envelope=envelope,
            provenance_public_key_pem=provenance_public_key,
            expected_provenance_key_sha256=provenance_fingerprint,
            expected_builder_id="https://builder.example.invalid/production",
        )


def _build_policy_for_manifest(manifest):
    return {
        "schema_version": 1,
        "base_image_self_link": "projects/cybergym-base/global/images/ubuntu-2404-v20261001",
        "source_commit": manifest["build_commit"],
        "input_lock_sha256": "b" * 64,
        "builder_id": "https://builder.example.invalid/production",
        "build_type": "https://example.invalid/build-types/gce-image/v1",
        "scanner_name": "approved-image-scanner",
        "scanner_version": "1.2.3",
        "max_critical_findings": 0,
        "max_high_findings": 0,
    }


def test_verifies_signed_provenance_against_complete_build_policy(manifest):
    envelope, public_key, fingerprint, _private_key = _signed_dsse_envelope(manifest)
    release = verify_dsse_slsa_provenance_for_build_policy(
        envelope,
        release_manifest=manifest,
        build_policy=_build_policy_for_manifest(manifest),
        public_key_pem=public_key,
        expected_public_key_sha256=fingerprint,
    )
    assert release.image_self_link == manifest["image_self_link"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("source_commit", "f" * 40, "source_commit"),
        ("base_image_self_link", "projects/cybergym-base/global/images/other-base",
         "policy base image"),
        ("input_lock_sha256", "c" * 64, "policy dependency lock digest"),
        ("builder_id", "https://other-builder.example.invalid/production",
         "builder identity"),
        ("build_type", "https://other.example.invalid/build-type/v1", "buildType"),
        ("scanner_name", "unapproved-scanner", "scanner_name"),
        ("scanner_version", "9.9.9", "scanner_version"),
    ],
)
def test_rejects_provenance_not_bound_to_build_policy(manifest, field, value, message):
    envelope, public_key, fingerprint, _private_key = _signed_dsse_envelope(manifest)
    policy = _build_policy_for_manifest(manifest)
    policy[field] = value
    with pytest.raises(GceImageManifestError, match=message):
        verify_dsse_slsa_provenance_for_build_policy(
            envelope,
            release_manifest=manifest,
            build_policy=policy,
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )


def test_cli_verifies_provenance_against_complete_build_policy(
    tmp_path, monkeypatch, capsys, manifest
):
    envelope, public_key, fingerprint, _private_key = _signed_dsse_envelope(manifest)
    policy = _build_policy_for_manifest(manifest)
    policy_file = tmp_path / "policy.json"
    manifest_file = tmp_path / "manifest.json"
    envelope_file = tmp_path / "provenance.json"
    public_key_file = tmp_path / "provenance.pub"
    policy_file.write_text(json.dumps(policy), encoding="utf-8")
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    envelope_file.write_text(json.dumps(envelope), encoding="utf-8")
    public_key_file.write_bytes(public_key)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnresearch",
            "verify-image-build-evidence",
            str(policy_file),
            str(manifest_file),
            str(envelope_file),
            str(public_key_file),
            "--trusted-key-sha256",
            fingerprint,
        ],
    )

    main()

    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is True
    assert result["build_policy_verified"] is True
    assert result["provenance_verified"] is True
    assert result["input_lock_sha256"] == policy["input_lock_sha256"]


def test_verifies_signed_provenance_against_canonical_reproducibility_recipe(manifest):
    envelope, public_key, fingerprint, _private_key = _signed_dsse_envelope(manifest)
    release = verify_dsse_slsa_provenance_for_reproducible_recipe(
        envelope,
        release_manifest=manifest,
        build_policy=_build_policy_for_manifest(manifest),
        reproducibility_recipe=_reproducibility_recipe_for_manifest(manifest),
        public_key_pem=public_key,
        expected_public_key_sha256=fingerprint,
    )
    assert release.image_self_link == manifest["image_self_link"]


@pytest.mark.parametrize("field", ["source_date_epoch", "builder_image"])
def test_rejects_provenance_when_recipe_digest_or_builder_image_differs(manifest, field):
    envelope, public_key, fingerprint, _private_key = _signed_dsse_envelope(manifest)
    recipe = _reproducibility_recipe_for_manifest(manifest)
    if field == "source_date_epoch":
        recipe[field] += 1
        message = "recipe digest"
    else:
        recipe[field] = "us-docker.pkg.dev/cybergym/builders/packer@sha256:" + "d" * 64
        message = "pinned builder image"
    with pytest.raises(GceImageManifestError, match=message):
        verify_dsse_slsa_provenance_for_reproducible_recipe(
            envelope,
            release_manifest=manifest,
            build_policy=_build_policy_for_manifest(manifest),
            reproducibility_recipe=recipe,
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )


def test_cli_verifies_signed_recipe_digest_in_provenance(
    tmp_path, monkeypatch, capsys, manifest
):
    envelope, public_key, fingerprint, _private_key = _signed_dsse_envelope(manifest)
    policy = _build_policy_for_manifest(manifest)
    recipe = _reproducibility_recipe_for_manifest(manifest)
    policy_file = tmp_path / "policy.json"
    recipe_file = tmp_path / "recipe.json"
    manifest_file = tmp_path / "manifest.json"
    envelope_file = tmp_path / "provenance.json"
    public_key_file = tmp_path / "provenance.pub"
    policy_file.write_text(json.dumps(policy), encoding="utf-8")
    recipe_file.write_text(json.dumps(recipe), encoding="utf-8")
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    envelope_file.write_text(json.dumps(envelope), encoding="utf-8")
    public_key_file.write_bytes(public_key)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnresearch",
            "verify-image-build-recipe-evidence",
            str(policy_file),
            str(recipe_file),
            str(manifest_file),
            str(envelope_file),
            str(public_key_file),
            "--trusted-key-sha256",
            fingerprint,
        ],
    )

    main()

    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is True
    assert result["recipe_verified"] is True
    assert result["provenance_verified"] is True
    assert result["recipe_sha256"] == validate_gce_image_reproducibility_recipe(
        recipe
    ).recipe_sha256


def _signed_manifest_pair(first_manifest, second_manifest):
    private_key = Ed25519PrivateKey.generate()
    first_signature, public_key, fingerprint = _signed_manifest(first_manifest, private_key)
    second_signature, _public_key, _fingerprint = _signed_manifest(second_manifest, private_key)
    return first_signature, second_signature, public_key, fingerprint, private_key


def _independent_signed_build_pair(manifest):
    first_manifest = deepcopy(manifest)
    second_manifest = deepcopy(manifest)
    artifact_bytes = b"deterministic image artifact fixture bytes\\n"
    artifact_digest = hashlib.sha256(artifact_bytes).hexdigest()
    first_manifest["artifact_sha256"] = artifact_digest
    second_manifest["artifact_sha256"] = artifact_digest
    first_manifest["build_id"] = "build-independent-a"
    second_manifest["build_id"] = "build-independent-b"
    second_manifest["image_self_link"] = (
        "projects/cybergym-canary/global/images/cybergym-canary-independent-b"
    )
    first_envelope, public_key, fingerprint, private_key = _signed_dsse_envelope(
        first_manifest
    )
    second_envelope, _public_key, _fingerprint, _private_key = _signed_dsse_envelope(
        second_manifest, private_key
    )
    return (
        first_manifest,
        first_envelope,
        second_manifest,
        second_envelope,
        public_key,
        fingerprint,
        private_key,
        artifact_bytes,
    )


def test_rejects_reusing_provenance_key_for_manifest_signatures(manifest):
    (
        first_manifest,
        first_envelope,
        second_manifest,
        second_envelope,
        provenance_public_key,
        provenance_fingerprint,
        _provenance_private_key,
        artifact_bytes,
    ) = _independent_signed_build_pair(manifest)
    (
        first_manifest_signature,
        second_manifest_signature,
        _manifest_public_key,
        _manifest_fingerprint,
        _manifest_private_key,
    ) = _signed_manifest_pair(first_manifest, second_manifest)

    with pytest.raises(GceImageManifestError, match="must be separate trust anchors"):
        verify_gce_image_reproducibility_pair(
            build_policy=_build_policy_for_manifest(manifest),
            reproducibility_recipe=_reproducibility_recipe_for_manifest(manifest),
            first_release_manifest=first_manifest,
            first_provenance_envelope=first_envelope,
            second_release_manifest=second_manifest,
            second_provenance_envelope=second_envelope,
            first_manifest_signature_base64=first_manifest_signature,
            second_manifest_signature_base64=second_manifest_signature,
            manifest_public_key_pem=provenance_public_key,
            expected_manifest_public_key_sha256=provenance_fingerprint,
            first_artifact_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
            second_artifact_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
            public_key_pem=provenance_public_key,
            expected_public_key_sha256=provenance_fingerprint,
        )


def test_verifies_two_independent_signed_builds_have_identical_artifact(manifest):
    (
        first_manifest,
        first_envelope,
        second_manifest,
        second_envelope,
        public_key,
        fingerprint,
        _private_key,
        artifact_bytes,
    ) = _independent_signed_build_pair(manifest)
    (
        first_manifest_signature,
        second_manifest_signature,
        manifest_public_key,
        manifest_fingerprint,
        _manifest_private_key,
    ) = _signed_manifest_pair(first_manifest, second_manifest)
    first, second = verify_gce_image_reproducibility_pair(
        build_policy=_build_policy_for_manifest(manifest),
        reproducibility_recipe=_reproducibility_recipe_for_manifest(manifest),
        first_release_manifest=first_manifest,
        first_provenance_envelope=first_envelope,
        second_release_manifest=second_manifest,
        second_provenance_envelope=second_envelope,
        first_manifest_signature_base64=first_manifest_signature,
        second_manifest_signature_base64=second_manifest_signature,
        manifest_public_key_pem=manifest_public_key,
        expected_manifest_public_key_sha256=manifest_fingerprint,
        first_artifact_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
        second_artifact_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
        public_key_pem=public_key,
        expected_public_key_sha256=fingerprint,
    )
    assert first.build_id != second.build_id
    assert first.artifact_sha256 == second.artifact_sha256


def test_rejects_two_provenance_records_for_same_build_id(manifest):
    pair = list(_independent_signed_build_pair(manifest))
    pair[2]["build_id"] = pair[0]["build_id"]
    signed_pair = _independent_signed_build_pair(manifest)
    public_key, fingerprint, private_key = signed_pair[4], signed_pair[5], signed_pair[6]
    artifact_bytes = signed_pair[7]
    first_envelope, _public_key, _fingerprint, _private_key = _signed_dsse_envelope(
        pair[0], private_key
    )
    second_envelope, _public_key, _fingerprint, _private_key = _signed_dsse_envelope(
        pair[2], private_key
    )
    (
        first_manifest_signature,
        second_manifest_signature,
        manifest_public_key,
        manifest_fingerprint,
        _manifest_private_key,
    ) = _signed_manifest_pair(pair[0], pair[2])
    with pytest.raises(GceImageManifestError, match="distinct build IDs"):
        verify_gce_image_reproducibility_pair(
            build_policy=_build_policy_for_manifest(manifest),
            reproducibility_recipe=_reproducibility_recipe_for_manifest(manifest),
            first_release_manifest=pair[0],
            first_provenance_envelope=first_envelope,
            second_release_manifest=pair[2],
            second_provenance_envelope=second_envelope,
            first_manifest_signature_base64=first_manifest_signature,
            second_manifest_signature_base64=second_manifest_signature,
            manifest_public_key_pem=manifest_public_key,
            expected_manifest_public_key_sha256=manifest_fingerprint,
            first_artifact_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
            second_artifact_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )


def test_rejects_independent_builds_with_different_artifact_digests(manifest):
    (
        first_manifest,
        _first_envelope,
        second_manifest,
        _second_envelope,
        public_key,
        fingerprint,
        private_key,
        artifact_bytes,
    ) = _independent_signed_build_pair(manifest)
    second_artifact_bytes = b"different independently built image artifact"
    second_manifest["artifact_sha256"] = hashlib.sha256(second_artifact_bytes).hexdigest()
    first_envelope, _public_key, _fingerprint, _private_key = _signed_dsse_envelope(
        first_manifest, private_key
    )
    second_envelope, _public_key, _fingerprint, _private_key = _signed_dsse_envelope(
        second_manifest, private_key
    )
    (
        first_manifest_signature,
        second_manifest_signature,
        manifest_public_key,
        manifest_fingerprint,
        _manifest_private_key,
    ) = _signed_manifest_pair(first_manifest, second_manifest)
    with pytest.raises(GceImageManifestError, match="artifact SHA-256 digests do not match"):
        verify_gce_image_reproducibility_pair(
            build_policy=_build_policy_for_manifest(manifest),
            reproducibility_recipe=_reproducibility_recipe_for_manifest(manifest),
            first_release_manifest=first_manifest,
            first_provenance_envelope=first_envelope,
            second_release_manifest=second_manifest,
            second_provenance_envelope=second_envelope,
            first_manifest_signature_base64=first_manifest_signature,
            second_manifest_signature_base64=second_manifest_signature,
            manifest_public_key_pem=manifest_public_key,
            expected_manifest_public_key_sha256=manifest_fingerprint,
            first_artifact_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
            second_artifact_sha256=hashlib.sha256(second_artifact_bytes).hexdigest(),
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )


def test_cli_verifies_two_independent_signed_builds(
    tmp_path, monkeypatch, capsys, manifest
):
    (
        first_manifest,
        first_envelope,
        second_manifest,
        second_envelope,
        public_key,
        fingerprint,
        _private_key,
        artifact_bytes,
    ) = _independent_signed_build_pair(manifest)
    (
        first_manifest_signature,
        second_manifest_signature,
        manifest_public_key,
        manifest_fingerprint,
        _manifest_private_key,
    ) = _signed_manifest_pair(first_manifest, second_manifest)
    policy_file = tmp_path / "policy.json"
    recipe_file = tmp_path / "recipe.json"
    first_manifest_file = tmp_path / "first-manifest.json"
    first_manifest_signature_file = tmp_path / "first-manifest.sig"
    first_envelope_file = tmp_path / "first-provenance.json"
    second_manifest_file = tmp_path / "second-manifest.json"
    second_manifest_signature_file = tmp_path / "second-manifest.sig"
    second_envelope_file = tmp_path / "second-provenance.json"
    first_artifact_file = tmp_path / "first-artifact.img"
    second_artifact_file = tmp_path / "second-artifact.img"
    manifest_public_key_file = tmp_path / "manifest.pub"
    public_key_file = tmp_path / "provenance.pub"
    policy_file.write_text(json.dumps(_build_policy_for_manifest(manifest)), encoding="utf-8")
    recipe_file.write_text(
        json.dumps(_reproducibility_recipe_for_manifest(manifest)), encoding="utf-8"
    )
    first_manifest_file.write_text(json.dumps(first_manifest), encoding="utf-8")
    first_manifest_signature_file.write_text(first_manifest_signature, encoding="ascii")
    first_envelope_file.write_text(json.dumps(first_envelope), encoding="utf-8")
    second_manifest_file.write_text(json.dumps(second_manifest), encoding="utf-8")
    second_manifest_signature_file.write_text(second_manifest_signature, encoding="ascii")
    second_envelope_file.write_text(json.dumps(second_envelope), encoding="utf-8")
    first_artifact_file.write_bytes(artifact_bytes)
    second_artifact_file.write_bytes(artifact_bytes)
    manifest_public_key_file.write_bytes(manifest_public_key)
    public_key_file.write_bytes(public_key)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnresearch",
            "verify-image-build-reproducibility",
            str(policy_file),
            str(recipe_file),
            str(first_manifest_file),
            str(first_manifest_signature_file),
            str(first_envelope_file),
            str(first_artifact_file),
            str(second_manifest_file),
            str(second_manifest_signature_file),
            str(second_envelope_file),
            str(second_artifact_file),
            str(manifest_public_key_file),
            str(public_key_file),
            "--trusted-manifest-key-sha256",
            manifest_fingerprint,
            "--trusted-key-sha256",
            fingerprint,
        ],
    )

    main()

    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is True
    assert result["reproducible"] is True
    assert result["independent_builds_verified"] == 2
    assert result["artifact_bytes_verified"] is True
    assert result["builds_executed"] is False


def test_rejects_artifact_bytes_that_do_not_match_signed_digest(manifest):
    (
        first_manifest,
        first_envelope,
        second_manifest,
        second_envelope,
        public_key,
        fingerprint,
        _private_key,
        artifact_bytes,
    ) = _independent_signed_build_pair(manifest)
    (
        first_manifest_signature,
        second_manifest_signature,
        manifest_public_key,
        manifest_fingerprint,
        _manifest_private_key,
    ) = _signed_manifest_pair(first_manifest, second_manifest)
    with pytest.raises(GceImageManifestError, match="second artifact bytes"):
        verify_gce_image_reproducibility_pair(
            build_policy=_build_policy_for_manifest(manifest),
            reproducibility_recipe=_reproducibility_recipe_for_manifest(manifest),
            first_release_manifest=first_manifest,
            first_provenance_envelope=first_envelope,
            second_release_manifest=second_manifest,
            second_provenance_envelope=second_envelope,
            first_manifest_signature_base64=first_manifest_signature,
            second_manifest_signature_base64=second_manifest_signature,
            manifest_public_key_pem=manifest_public_key,
            expected_manifest_public_key_sha256=manifest_fingerprint,
            first_artifact_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
            second_artifact_sha256=hashlib.sha256(b"tampered artifact bytes").hexdigest(),
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )


def test_streaming_artifact_hash_matches_in_memory_hash(tmp_path):
    artifact = tmp_path / "large-image.img"
    content = b"artifact-data-" * 200_000
    artifact.write_bytes(content)

    digest, size = sha256_artifact_file(artifact)

    assert digest == hashlib.sha256(content).hexdigest()
    assert size == len(content)


def test_streaming_artifact_hash_rejects_empty_file(tmp_path):
    artifact = tmp_path / "empty.img"
    artifact.write_bytes(b"")

    with pytest.raises(GceImageManifestError, match="must not be empty"):
        sha256_artifact_file(artifact)


def test_streaming_artifact_hash_rejects_symlink(tmp_path):
    artifact = tmp_path / "artifact.img"
    artifact.write_bytes(b"artifact")
    link = tmp_path / "artifact-link.img"
    link.symlink_to(artifact)

    with pytest.raises(GceImageManifestError, match="regular, non-symlink file"):
        sha256_artifact_file(link)


def test_streaming_artifact_hash_rejects_directory(tmp_path):
    with pytest.raises(GceImageManifestError, match="regular, non-symlink file"):
        sha256_artifact_file(tmp_path)


def test_streaming_artifact_hash_rejects_file_changed_during_read(
    tmp_path, monkeypatch
):
    artifact = tmp_path / "changing.img"
    artifact.write_bytes(b"stable initial bytes")
    original_fstat = os.fstat
    calls = 0

    def changing_fstat(descriptor):
        nonlocal calls
        result = original_fstat(descriptor)
        calls += 1
        if calls == 2:
            values = {
                field: getattr(result, field)
                for field in dir(result)
                if field.startswith("st_")
            }
            values["st_mtime_ns"] += 1
            return SimpleNamespace(**values)
        return result

    monkeypatch.setattr("os.fstat", changing_fstat)
    with pytest.raises(GceImageManifestError, match="changed while"):
        sha256_artifact_file(artifact)


def test_rejects_manifest_without_scanner_version(manifest):
    candidate = deepcopy(manifest)
    del candidate["vulnerability_scan"]["scanner_version"]
    with pytest.raises(GceImageManifestError, match="scanner_version"):
        validate_gce_image_release_manifest(candidate)


def test_recipe_provenance_rejects_manifest_scanner_drift(manifest):
    envelope, public_key, fingerprint, _private_key = _signed_dsse_envelope(manifest)
    policy = _build_policy_for_manifest(manifest)
    policy["scanner_version"] = "9.9.9"
    with pytest.raises(GceImageManifestError, match="scanner_version"):
        verify_dsse_slsa_provenance_for_reproducible_recipe(
            envelope,
            release_manifest=manifest,
            build_policy=policy,
            reproducibility_recipe=_reproducibility_recipe_for_manifest(manifest),
            public_key_pem=public_key,
            expected_public_key_sha256=fingerprint,
        )
