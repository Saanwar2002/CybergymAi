import hashlib
import json

import pytest

from vulnresearch.execution.gce_image_recipe import (
    GceImageRecipeError,
    validate_gce_image_reproducibility_recipe,
)


@pytest.fixture
def recipe():
    return {
        "schema_version": 1,
        "base_image_self_link": "projects/cybergym-base/global/images/ubuntu-2404-v20261001",
        "source_commit": "a" * 40,
        "input_lock_sha256": "b" * 64,
        "builder_image": "us-docker.pkg.dev/cybergym/builders/packer@sha256:" + "c" * 64,
        "toolchain_version": "1.2.3",
        "build_type": "https://build.example.invalid/gce-image/v1",
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


def test_accepts_fully_pinned_deterministic_recipe(recipe):
    result = validate_gce_image_reproducibility_recipe(recipe)
    assert result.builder_image == recipe["builder_image"]
    assert result.toolchain_version == "1.2.3"
    assert result.source_date_epoch == recipe["source_date_epoch"]
    assert len(result.recipe_sha256) == 64


def test_recipe_digest_is_canonical_across_mapping_order(recipe):
    result = validate_gce_image_reproducibility_recipe(recipe)
    reordered = dict(reversed(list(recipe.items())))
    assert validate_gce_image_reproducibility_recipe(reordered).recipe_sha256 == result.recipe_sha256


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", True, "schema_version"),
        ("base_image_self_link", "projects/cybergym-base/global/images/family/ubuntu", "base_image"),
        ("source_commit", "main", "source_commit"),
        ("input_lock_sha256", "B" * 64, "input_lock_sha256"),
        ("builder_image", "us-docker.pkg.dev/cybergym/builders/packer:latest", "pinned by sha256"),
        ("builder_image", "packer@sha256:" + "c" * 64, "pinned by sha256"),
        ("toolchain_version", "latest", "x.y.z"),
        ("toolchain_version", "1.2", "x.y.z"),
        ("build_type", "http://build.example.invalid/type", "HTTPS URI"),
        ("source_date_epoch", True, "source_date_epoch"),
        ("source_date_epoch", -1, "source_date_epoch"),
        ("platform", "linux/unknown", "platform"),
        ("network_access", True, "network_access"),
    ],
)
def test_rejects_mutable_or_nondeterministic_recipe_inputs(recipe, field, value, message):
    recipe[field] = value
    with pytest.raises(GceImageRecipeError, match=message):
        validate_gce_image_reproducibility_recipe(recipe)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("LANG", "en_US.UTF-8"),
        ("LC_ALL", "en_US.UTF-8"),
        ("TZ", "Europe/London"),
        ("umask", "0000"),
        ("extra", "value"),
    ],
)
def test_rejects_environment_drift(recipe, field, value):
    recipe["environment"][field] = value
    with pytest.raises(GceImageRecipeError, match="environment must set exactly"):
        validate_gce_image_reproducibility_recipe(recipe)


def test_rejects_unknown_recipe_fields(recipe):
    recipe["allow_network_fallback"] = True
    with pytest.raises(GceImageRecipeError, match="unknown fields"):
        validate_gce_image_reproducibility_recipe(recipe)


def test_recipe_digest_matches_canonical_json(recipe):
    result = validate_gce_image_reproducibility_recipe(recipe)
    expected = hashlib.sha256(
        json.dumps(recipe, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    assert result.recipe_sha256 == expected
