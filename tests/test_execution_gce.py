from __future__ import annotations

from copy import deepcopy

import pytest

from vulnresearch.execution.gce import (
    GceCanaryConfig,
    GceConfigurationError,
    build_canary_instance_resource,
    canary_instance_name,
    validate_canary_instance_resource,
)


@pytest.fixture
def config() -> GceCanaryConfig:
    return GceCanaryConfig(
        project_id="cybergym-sandbox",
        zone="europe-west2-b",
        subnetwork="projects/cybergym-sandbox/regions/europe-west2/subnetworks/canary-subnet",
        approved_image="projects/cybergym-images/global/images/canary-image-20261104",
    )


def test_config_accepts_exact_project_zone_subnet_and_image(config):
    assert config.project_id == "cybergym-sandbox"
    assert config.zone == "europe-west2-b"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("project_id", "MyProject", "project ID"),
        ("zone", "europe-west2", "explicit Compute Engine zone"),
        (
            "subnetwork",
            "projects/other-project/regions/europe-west2/subnetworks/canary-subnet",
            "must match the canary",
        ),
        (
            "subnetwork",
            "projects/cybergym-sandbox/regions/us-central1/subnetworks/canary-subnet",
            "must match the canary",
        ),
        (
            "approved_image",
            "projects/cybergym-images/global/images/family/canary",
            "exact Compute Engine image",
        ),
        ("boot_disk_size_gb", 101, "between 10 and 100"),
        ("max_runtime_seconds", 601, "between 30 and 600"),
        ("max_console_output_bytes", 1024 * 1024 + 1, "between 1 KiB and 1 MiB"),
    ],
)
def test_config_rejects_invalid_or_unbounded_values(config, field, value, message):
    values = {
        "project_id": config.project_id,
        "zone": config.zone,
        "subnetwork": config.subnetwork,
        "approved_image": config.approved_image,
        "machine_type": config.machine_type,
        "boot_disk_size_gb": config.boot_disk_size_gb,
        "max_runtime_seconds": config.max_runtime_seconds,
        "max_console_output_bytes": config.max_console_output_bytes,
    }
    values[field] = value
    with pytest.raises(GceConfigurationError, match=message):
        GceCanaryConfig(**values)


def test_config_rejects_bool_for_integer_limits(config):
    with pytest.raises(GceConfigurationError, match="boot_disk_size_gb"):
        GceCanaryConfig(
            project_id=config.project_id,
            zone=config.zone,
            subnetwork=config.subnetwork,
            approved_image=config.approved_image,
            boot_disk_size_gb=True,
        )


def test_instance_name_is_valid_deterministic_and_does_not_expose_run_id():
    first = canary_instance_name("customer-ticket/secret-run-id")
    second = canary_instance_name("customer-ticket/secret-run-id")

    assert first == second
    assert first.startswith("cybergym-canary-")
    assert "secret-run-id" not in first
    assert len(first) <= 63


def test_instance_name_rejects_invalid_run_ids():
    with pytest.raises(GceConfigurationError):
        canary_instance_name("")
    with pytest.raises(GceConfigurationError):
        canary_instance_name("x" * 257)


def test_resource_has_no_public_ip_guest_service_account_or_metadata(config):
    resource = build_canary_instance_resource(config, run_id="run-001")

    assert resource["networkInterfaces"] == [{"subnetwork": config.subnetwork}]
    assert "serviceAccounts" not in resource
    assert "metadata" not in resource
    assert resource["shieldedInstanceConfig"] == {
        "enableSecureBoot": True,
        "enableVtpm": True,
        "enableIntegrityMonitoring": True,
    }
    assert resource["disks"][0]["autoDelete"] is True
    assert resource["disks"][0]["initializeParams"]["sourceImage"] == config.approved_image
    assert resource["scheduling"]["automaticRestart"] is False
    assert resource["canIpForward"] is False


def test_observed_instance_must_match_expected_policy(config):
    resource = build_canary_instance_resource(config, run_id="run-001")

    validate_canary_instance_resource(resource, config, run_id="run-001")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(machineType="zones/europe-west2-b/machineTypes/e2-micro"), "machineType"),
        (lambda value: value.update(shieldedInstanceConfig={"enableSecureBoot": False}), "shieldedInstanceConfig"),
        (lambda value: value.update(serviceAccounts=[{"email": "guest@example.invalid"}]), "service accounts"),
        (lambda value: value.update(metadata={"items": [{"key": "secret", "value": "x"}]}), "metadata"),
        (lambda value: value["networkInterfaces"][0].update(accessConfigs=[{"type": "ONE_TO_ONE_NAT"}]), "public IP"),
        (lambda value: value["networkInterfaces"][0].update(subnetwork="projects/other/regions/europe-west2/subnetworks/other"), "unexpected subnet"),
        (lambda value: value["disks"][0].update(autoDelete=False), "disks"),
        (lambda value: value.update(canIpForward=True), "canIpForward"),
    ],
)
def test_observed_instance_policy_drift_is_rejected(config, mutate, message):
    resource = deepcopy(build_canary_instance_resource(config, run_id="run-001"))
    mutate(resource)

    with pytest.raises(GceConfigurationError, match=message):
        validate_canary_instance_resource(resource, config, run_id="run-001")


def test_observed_instance_must_have_exactly_one_network_interface(config):
    resource = build_canary_instance_resource(config, run_id="run-001")
    resource["networkInterfaces"].append({"subnetwork": config.subnetwork})

    with pytest.raises(GceConfigurationError, match="exactly one network interface"):
        validate_canary_instance_resource(resource, config, run_id="run-001")
