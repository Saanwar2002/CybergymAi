from __future__ import annotations

from copy import deepcopy

import pytest

from vulnresearch.execution.gce import (
    GceCanaryConfig,
    GceConfigurationError,
    GceNetworkConfig,
    build_canary_instance_resource,
    build_gce_default_deny_firewall_resources,
    build_gce_network_resource,
    build_gce_subnetwork_resource,
    canary_instance_name,
    validate_canary_instance_resource,
    validate_gce_network_policy,
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
    assert resource["serviceAccounts"] == []
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

def test_observed_instance_accepts_compute_api_self_links_and_empty_metadata(config):
    resource = build_canary_instance_resource(config, run_id="run-001")
    resource["machineType"] = (
        "https://www.googleapis.com/compute/v1/projects/cybergym-sandbox/"
        "zones/europe-west2-b/machineTypes/e2-standard-2"
    )
    resource["disks"][0]["initializeParams"]["sourceImage"] = (
        "https://www.googleapis.com/compute/v1/projects/cybergym-images/"
        "global/images/canary-image-20261104"
    )
    resource["disks"][0]["initializeParams"]["diskType"] = (
        "https://www.googleapis.com/compute/v1/projects/cybergym-sandbox/"
        "zones/europe-west2-b/diskTypes/pd-balanced"
    )
    resource["networkInterfaces"][0]["subnetwork"] = (
        "https://www.googleapis.com/compute/v1/projects/cybergym-sandbox/"
        "regions/europe-west2/subnetworks/canary-subnet"
    )
    resource["metadata"] = {"fingerprint": "empty-metadata", "items": []}
    resource["disks"][0]["source"] = (
        "https://www.googleapis.com/compute/v1/projects/cybergym-sandbox/"
        "zones/europe-west2-b/disks/cybergym-canary-example"
    )

    validate_canary_instance_resource(resource, config, run_id="run-001")


def test_observed_instance_rejects_untrusted_compute_self_link_host(config):
    resource = build_canary_instance_resource(config, run_id="run-001")
    resource["networkInterfaces"][0]["subnetwork"] = (
        "https://attacker.invalid/compute/v1/projects/cybergym-sandbox/"
        "regions/europe-west2/subnetworks/canary-subnet"
    )

    with pytest.raises(GceConfigurationError, match="unexpected subnet"):
        validate_canary_instance_resource(resource, config, run_id="run-001")



@pytest.fixture
def network_config() -> GceNetworkConfig:
    return GceNetworkConfig(
        project_id="cybergym-sandbox",
        region="europe-west2",
        network_name="cybergym-sandbox",
        subnet_name="cybergym-canary",
        ipv4_cidr="10.240.0.0/24",
    )


def test_gce_network_config_accepts_private_bounded_ipv4_subnet(network_config):
    assert network_config.ipv4_cidr == "10.240.0.0/24"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("region", "europe-west2-b", "explicit GCP region"),
        ("network_name", "Default_Network", "resource name"),
        ("subnet_name", "subnet/", "resource name"),
        ("ipv4_cidr", "10.240.0.1/24", "canonical IPv4 network"),
        ("ipv4_cidr", "10.0.0.0/23", "between /24 and /28"),
        ("ipv4_cidr", "8.8.8.0/24", "RFC 1918"),
        ("ipv4_cidr", "2001:db8::/64", "canonical IPv4 network"),
    ],
)
def test_gce_network_config_rejects_unsafe_values(network_config, field, value, message):
    values = {
        "project_id": network_config.project_id,
        "region": network_config.region,
        "network_name": network_config.network_name,
        "subnet_name": network_config.subnet_name,
        "ipv4_cidr": network_config.ipv4_cidr,
    }
    values[field] = value
    with pytest.raises(GceConfigurationError, match=message):
        GceNetworkConfig(**values)


def test_gce_network_resources_are_custom_ipv4_only_and_private(network_config):
    network = build_gce_network_resource(network_config)
    subnet = build_gce_subnetwork_resource(network_config)

    assert network == {
        "name": "cybergym-sandbox",
        "autoCreateSubnetworks": False,
        "routingConfig": {"routingMode": "REGIONAL"},
    }
    assert subnet == {
        "name": "cybergym-canary",
        "network": "projects/cybergym-sandbox/global/networks/cybergym-sandbox",
        "region": "regions/europe-west2",
        "ipCidrRange": "10.240.0.0/24",
        "stackType": "IPV4_ONLY",
        "privateIpGoogleAccess": False,
    }


def test_gce_firewall_rules_deny_all_ipv4_for_all_vpc_instances(network_config):
    ingress, egress = build_gce_default_deny_firewall_resources(network_config)

    assert ingress["direction"] == "INGRESS"
    assert ingress["sourceRanges"] == ["0.0.0.0/0"]
    assert egress["direction"] == "EGRESS"
    assert egress["destinationRanges"] == ["0.0.0.0/0"]
    for rule in (ingress, egress):
        assert rule["priority"] == 0
        assert rule["disabled"] is False
        assert rule["denied"] == [{"IPProtocol": "all"}]
        assert "allowed" not in rule
        assert "targetTags" not in rule
        assert "targetServiceAccounts" not in rule


def _valid_gce_network_policy(network_config):
    return (
        {
            "name": network_config.network_name,
            "autoCreateSubnetworks": False,
            "routingConfig": {"routingMode": "REGIONAL"},
            "peerings": [],
        },
        build_gce_subnetwork_resource(network_config),
        list(build_gce_default_deny_firewall_resources(network_config)),
        [],
    )


def test_gce_network_policy_accepts_isolated_vpc_and_no_default_routes(network_config):
    network, subnet, firewalls, routes = _valid_gce_network_policy(network_config)

    validate_gce_network_policy(network, subnet, firewalls, routes, network_config)


@pytest.mark.parametrize(
    ("mutate_network", "mutate_subnet", "mutate_firewalls", "mutate_routes", "message"),
    [
        (lambda n, s, f, r: n.update(autoCreateSubnetworks=True), lambda s: None, lambda f: None, lambda r: None, "custom-network policy"),
        (lambda n, s, f, r: n.update(peerings=[{"name": "external-peer"}]), lambda s: None, lambda f: None, lambda r: None, "custom-network policy"),
        (lambda n, s, f, r: None, lambda s: s.update(privateIpGoogleAccess=True), lambda f: None, lambda r: None, "IPv4-only policy"),
        (lambda n, s, f, r: None, lambda s: s.update(stackType="IPV4_IPV6"), lambda f: None, lambda r: None, "IPv4-only policy"),
        (lambda n, s, f, r: None, lambda s: s.update(network="projects/other/global/networks/other"), lambda f: None, lambda r: None, "unexpected VPC"),
        (lambda n, s, f, r: None, lambda s: None, lambda f: f[1].update(priority=1000), lambda r: None, "unexpected priority"),
        (lambda n, s, f, r: None, lambda s: None, lambda f: f[1].update(allowed=[{"IPProtocol": "tcp"}]), lambda r: None, "unsafe allow"),
        (lambda n, s, f, r: None, lambda s: None, lambda f: f[1].update(targetTags=["canary"]), lambda r: None, "unsafe allow"),
        (lambda n, s, f, r: None, lambda s: None, lambda f: f[1].update(destinationRanges=["10.0.0.0/8"]), lambda r: None, "unexpected destinationRanges"),
        (lambda n, s, f, r: None, lambda s: None, lambda f: f.append({"name": "extra-allow", "network": "projects/cybergym-sandbox/global/networks/cybergym-sandbox"}), lambda r: None, "exactly the two"),
        (lambda n, s, f, r: None, lambda s: None, lambda f: None, lambda r: r.append({"network": "projects/cybergym-sandbox/global/networks/cybergym-sandbox", "destRange": "0.0.0.0/0", "nextHopGateway": "projects/cybergym-sandbox/global/gateways/default-internet-gateway"}), "default internet route"),
        (lambda n, s, f, r: None, lambda s: None, lambda f: None, lambda r: r.append({"network": "projects/cybergym-sandbox/global/networks/cybergym-sandbox", "destRange": "10.0.0.0/8", "nextHopIp": "10.240.0.2"}), "default internet route"),
    ],
)
def test_gce_network_policy_rejects_drift(
    network_config, mutate_network, mutate_subnet, mutate_firewalls, mutate_routes, message
):
    network, subnet, firewalls, routes = _valid_gce_network_policy(network_config)
    mutate_network(network, subnet, firewalls, routes)
    mutate_subnet(subnet)
    mutate_firewalls(firewalls)
    mutate_routes(routes)

    with pytest.raises(GceConfigurationError, match=message):
        validate_gce_network_policy(network, subnet, firewalls, routes, network_config)
