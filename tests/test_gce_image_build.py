import pytest

from vulnresearch.execution.gce_image_build import (
    GceImageBuildPolicyError,
    validate_gce_image_build_policy,
)


@pytest.fixture
def policy():
    return {
        "schema_version": 1,
        "base_image_self_link": "projects/cybergym-base/global/images/ubuntu-2404-v20261001",
        "source_commit": "a" * 40,
        "input_lock_sha256": "b" * 64,
        "builder_id": "https://builder.example.invalid/production",
        "build_type": "https://build.example.invalid/gce-image/v1",
        "scanner_name": "approved-image-scanner",
        "scanner_version": "1.2.3",
        "max_critical_findings": 0,
        "max_high_findings": 0,
    }


def test_accepts_fully_pinned_build_inputs_and_zero_finding_thresholds(policy):
    result = validate_gce_image_build_policy(policy)
    assert result.base_image_self_link == policy["base_image_self_link"]
    assert result.source_commit == policy["source_commit"]
    assert result.max_critical_findings == 0
    assert result.max_high_findings == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("base_image_self_link", "projects/cybergym-base/global/images/family/ubuntu"),
        ("base_image_self_link", "ubuntu-2404"),
        ("source_commit", "main"),
        ("source_commit", "a" * 39),
        ("input_lock_sha256", "B" * 64),
        ("input_lock_sha256", "unlocked"),
        ("builder_id", "http://builder.example.invalid/production"),
        ("builder_id", "https://user:secret@builder.example.invalid/production"),
        ("build_type", "file:///tmp/build"),
        ("scanner_name", ""),
        ("scanner_version", ""),
        ("max_critical_findings", 1),
        ("max_high_findings", 1),
        ("max_critical_findings", True),
        ("max_high_findings", "0"),
    ],
)
def test_rejects_unpinned_or_noncompliant_build_policy(policy, field, value):
    policy[field] = value
    with pytest.raises(GceImageBuildPolicyError):
        validate_gce_image_build_policy(policy)


def test_rejects_missing_build_policy():
    with pytest.raises(GceImageBuildPolicyError, match="object"):
        validate_gce_image_build_policy(None)


def test_rejects_whitespace_padded_builder_identity(policy):
    policy["builder_id"] = " https://builder.example.invalid/production"
    with pytest.raises(GceImageBuildPolicyError, match="surrounding whitespace"):
        validate_gce_image_build_policy(policy)


@pytest.mark.parametrize("unknown_field", ["base_image", "builder", "allow_critical_findings"])
def test_rejects_unknown_build_policy_fields(policy, unknown_field):
    policy[unknown_field] = "unexpected"
    with pytest.raises(GceImageBuildPolicyError, match="unknown fields"):
        validate_gce_image_build_policy(policy)


def test_rejects_unknown_fields_even_when_all_required_fields_are_valid(policy):
    policy["release_override"] = True
    with pytest.raises(GceImageBuildPolicyError, match="release_override"):
        validate_gce_image_build_policy(policy)


@pytest.mark.parametrize("version", [0, 2, "1", True, None])
def test_rejects_missing_or_unsupported_schema_version(policy, version):
    policy["schema_version"] = version
    with pytest.raises(GceImageBuildPolicyError, match="schema_version"):
        validate_gce_image_build_policy(policy)


def test_rejects_policy_without_schema_version(policy):
    del policy["schema_version"]
    with pytest.raises(GceImageBuildPolicyError, match="schema_version"):
        validate_gce_image_build_policy(policy)
