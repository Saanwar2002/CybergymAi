"""Fail-closed Google Compute Engine configuration for the offline VM canary.

This module builds and verifies instance resources only. It does not call Google Cloud,
provision infrastructure, or enable benchmark execution.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol


class GceConfigurationError(ValueError):
    """Raised when a GCE canary configuration or instance violates the reviewed policy."""


_PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_ZONE = re.compile(r"^[a-z]+-[a-z0-9]+[0-9]-[a-z]$")
_IMAGE = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z0-9][a-z0-9-]{0,62}$"
)
_SUBNETWORK = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/regions/"
    r"[a-z]+-[a-z0-9]+[0-9]/subnetworks/[a-z][a-z0-9-]{0,61}[a-z0-9]$"
)
_MACHINE_TYPE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")


@dataclass(frozen=True)
class GceCanaryConfig:
    """Explicit, bounded configuration for one offline harmless GCE canary."""

    project_id: str
    zone: str
    subnetwork: str
    approved_image: str
    machine_type: str = "e2-standard-2"
    boot_disk_size_gb: int = 20
    max_runtime_seconds: int = 300
    max_console_output_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, str) or not _PROJECT_ID.fullmatch(self.project_id):
            raise GceConfigurationError("project_id must be a valid lowercase GCP project ID")
        if not isinstance(self.zone, str) or not _ZONE.fullmatch(self.zone):
            raise GceConfigurationError("zone must be an explicit Compute Engine zone")
        if not isinstance(self.subnetwork, str) or not _SUBNETWORK.fullmatch(self.subnetwork):
            raise GceConfigurationError("subnetwork must be a canonical subnet resource path")
        subnet_parts = self.subnetwork.split("/")
        zone_region = self.zone.rsplit("-", 1)[0]
        if subnet_parts[1] != self.project_id or subnet_parts[3] != zone_region:
            raise GceConfigurationError("subnetwork project and region must match the canary")
        if not isinstance(self.approved_image, str) or not _IMAGE.fullmatch(self.approved_image):
            raise GceConfigurationError(
                "approved_image must identify one exact Compute Engine image, not an image family"
            )
        if not isinstance(self.machine_type, str) or not _MACHINE_TYPE.fullmatch(self.machine_type):
            raise GceConfigurationError("machine_type must be an explicit machine type")
        if type(self.boot_disk_size_gb) is not int or not 10 <= self.boot_disk_size_gb <= 100:
            raise GceConfigurationError("boot_disk_size_gb must be between 10 and 100")
        if type(self.max_runtime_seconds) is not int or not 30 <= self.max_runtime_seconds <= 600:
            raise GceConfigurationError("max_runtime_seconds must be between 30 and 600")
        if (
            type(self.max_console_output_bytes) is not int
            or not 1024 <= self.max_console_output_bytes <= 1024 * 1024
        ):
            raise GceConfigurationError(
                "max_console_output_bytes must be between 1 KiB and 1 MiB"
            )


def canary_instance_name(run_id: str) -> str:
    """Derive a valid, non-sensitive, deterministic GCE name from an opaque run ID."""
    if not isinstance(run_id, str) or not run_id or len(run_id) > 256 or "\x00" in run_id:
        raise GceConfigurationError("run_id must be a non-empty opaque string of at most 256 chars")
    digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:20]
    return f"cybergym-canary-{digest}"


def build_canary_instance_resource(
    config: GceCanaryConfig, *, run_id: str
) -> dict[str, object]:
    """Build a minimal GCE instance resource with no public IP or guest identity."""
    if not isinstance(config, GceCanaryConfig):
        raise TypeError("config must be a GceCanaryConfig")
    return {
        "name": canary_instance_name(run_id),
        "machineType": f"projects/{config.project_id}/zones/{config.zone}/machineTypes/{config.machine_type}",
        "disks": [
            {
                "boot": True,
                "autoDelete": True,
                "initializeParams": {
                    "sourceImage": config.approved_image,
                    "diskSizeGb": config.boot_disk_size_gb,
                    "diskType": f"projects/{config.project_id}/zones/{config.zone}/diskTypes/pd-balanced",
                },
            }
        ],
        "networkInterfaces": [{"subnetwork": config.subnetwork}],
        "serviceAccounts": [],
        "shieldedInstanceConfig": {
            "enableSecureBoot": True,
            "enableVtpm": True,
            "enableIntegrityMonitoring": True,
        },
        "canIpForward": False,
        "deletionProtection": False,
        "scheduling": {
            "automaticRestart": False,
            "onHostMaintenance": "TERMINATE",
        },
        "tags": {"items": ["cybergym-offline-canary"]},
        "labels": {
            "managed-by": "cybergym-ai",
            "purpose": "offline-canary",
            "run": hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:20],
        },
    }


def _canonical_resource_path(value: object) -> str | None:
    """Normalize a Compute Engine selfLink or relative resource path."""
    if not isinstance(value, str) or not value:
        return None
    if "://" in value:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        if parsed.scheme != "https" or parsed.hostname not in {
            "www.googleapis.com",
            "compute.googleapis.com",
        }:
            return None
        prefix = "/compute/v1/"
        if not parsed.path.startswith(prefix):
            return None
        return parsed.path[len(prefix) :]
    return value.lstrip("/")


def _matches_resource_path(observed: object, expected: str) -> bool:
    path = _canonical_resource_path(observed)
    if path is None:
        return False
    return path == expected


def validate_canary_instance_resource(
    resource: Mapping[str, object], config: GceCanaryConfig, *, run_id: str
) -> None:
    """Reject an observed instance unless it retains the reviewed canary security policy."""
    if not isinstance(resource, Mapping):
        raise GceConfigurationError("instance resource must be a mapping")

    expected = build_canary_instance_resource(config, run_id=run_id)
    if resource.get("name") != expected["name"]:
        raise GceConfigurationError("observed instance has an unexpected name")
    if not _matches_resource_path(resource.get("machineType"), str(expected["machineType"])):
        raise GceConfigurationError("observed instance has an unexpected machineType")
    if resource.get("canIpForward") is not False:
        raise GceConfigurationError("observed instance has an unexpected canIpForward value")
    if resource.get("deletionProtection") is not False:
        raise GceConfigurationError("observed instance has an unexpected deletionProtection value")

    shielded = resource.get("shieldedInstanceConfig")
    if not isinstance(shielded, Mapping) or any(
        shielded.get(field) is not True
        for field in ("enableSecureBoot", "enableVtpm", "enableIntegrityMonitoring")
    ):
        raise GceConfigurationError("observed instance has an unexpected shieldedInstanceConfig")

    scheduling = resource.get("scheduling")
    if not isinstance(scheduling, Mapping) or (
        scheduling.get("automaticRestart") is not False
        or scheduling.get("onHostMaintenance") != "TERMINATE"
    ):
        raise GceConfigurationError("observed instance has an unexpected scheduling value")

    disks = resource.get("disks")
    if not isinstance(disks, list) or len(disks) != 1 or not isinstance(disks[0], Mapping):
        raise GceConfigurationError("observed instance must have exactly one boot disk")
    disk = disks[0]
    init = disk.get("initializeParams")
    if (
        disk.get("boot") is not True
        or disk.get("autoDelete") is not True
        or not isinstance(init, Mapping)
        or not _matches_resource_path(init.get("sourceImage"), config.approved_image)
        or init.get("diskSizeGb") != config.boot_disk_size_gb
        or not _matches_resource_path(
            init.get("diskType"),
            f"projects/{config.project_id}/zones/{config.zone}/diskTypes/pd-balanced",
        )
    ):
        raise GceConfigurationError("observed instance has an unexpected disks value")

    interfaces = resource.get("networkInterfaces")
    if not isinstance(interfaces, list) or len(interfaces) != 1:
        raise GceConfigurationError("observed instance must have exactly one network interface")
    interface = interfaces[0]
    if not isinstance(interface, Mapping) or not _matches_resource_path(
        interface.get("subnetwork"), config.subnetwork
    ):
        raise GceConfigurationError("observed instance is attached to an unexpected subnet")
    if interface.get("accessConfigs") or interface.get("ipv6AccessConfigs"):
        raise GceConfigurationError("observed instance must not have a public IP configuration")

    service_accounts = resource.get("serviceAccounts")
    if service_accounts:
        raise GceConfigurationError("guest service accounts are forbidden")
    metadata = resource.get("metadata")
    if isinstance(metadata, Mapping) and metadata.get("items"):
        raise GceConfigurationError("guest-visible instance metadata is forbidden")
    if metadata and not isinstance(metadata, Mapping):
        raise GceConfigurationError("observed instance metadata has an invalid shape")

    tags = resource.get("tags")
    tag_items = tags.get("items", []) if isinstance(tags, Mapping) else []
    if "cybergym-offline-canary" not in tag_items:
        raise GceConfigurationError("observed instance is missing the canary network tag")
    labels = resource.get("labels")
    if not isinstance(labels, Mapping) or any(
        labels.get(key) != value for key, value in expected["labels"].items()
    ):
        raise GceConfigurationError("observed instance has unexpected canary labels")


_NETWORK_NAME = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")
_REGION = re.compile(r"^[a-z]+-[a-z0-9]+[0-9]$")
_PRIVATE_IPV4_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


@dataclass(frozen=True)
class GceNetworkConfig:
    """Dedicated, IPv4-only GCE VPC and subnet for offline canary instances."""

    project_id: str
    region: str
    network_name: str = "cybergym-sandbox"
    subnet_name: str = "cybergym-canary"
    ipv4_cidr: str = "10.240.0.0/24"

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, str) or not _PROJECT_ID.fullmatch(self.project_id):
            raise GceConfigurationError("network project_id must be a valid lowercase GCP project ID")
        if not isinstance(self.region, str) or not _REGION.fullmatch(self.region):
            raise GceConfigurationError("region must be an explicit GCP region")
        for field in ("network_name", "subnet_name"):
            value = getattr(self, field)
            if not isinstance(value, str) or not _NETWORK_NAME.fullmatch(value):
                raise GceConfigurationError(f"{field} must be a valid lowercase GCP resource name")
        try:
            network = ipaddress.ip_network(self.ipv4_cidr, strict=True)
        except (TypeError, ValueError) as exc:
            raise GceConfigurationError("ipv4_cidr must be a canonical IPv4 network") from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise GceConfigurationError("ipv4_cidr must be a canonical IPv4 network")
        if not 24 <= network.prefixlen <= 28:
            raise GceConfigurationError("ipv4_cidr must be an IPv4 subnet between /24 and /28")
        if not any(network.subnet_of(private_range) for private_range in _PRIVATE_IPV4_RANGES):
            raise GceConfigurationError("ipv4_cidr must be inside an RFC 1918 private range")


def _network_resource_path(config: GceNetworkConfig) -> str:
    return f"projects/{config.project_id}/global/networks/{config.network_name}"


def _subnetwork_resource_path(config: GceNetworkConfig) -> str:
    return (
        f"projects/{config.project_id}/regions/{config.region}/"
        f"subnetworks/{config.subnet_name}"
    )


def build_gce_network_resource(config: GceNetworkConfig) -> dict[str, object]:
    """Build a custom-mode regional VPC; never use or mutate the default network."""
    if not isinstance(config, GceNetworkConfig):
        raise TypeError("config must be a GceNetworkConfig")
    return {
        "name": config.network_name,
        "autoCreateSubnetworks": False,
        "routingConfig": {"routingMode": "REGIONAL"},
    }


def build_gce_subnetwork_resource(config: GceNetworkConfig) -> dict[str, object]:
    """Build an IPv4-only subnet with Private Google Access disabled."""
    if not isinstance(config, GceNetworkConfig):
        raise TypeError("config must be a GceNetworkConfig")
    return {
        "name": config.subnet_name,
        "network": _network_resource_path(config),
        "region": f"regions/{config.region}",
        "ipCidrRange": config.ipv4_cidr,
        "stackType": "IPV4_ONLY",
        "privateIpGoogleAccess": False,
    }


def build_gce_default_deny_firewall_resources(
    config: GceNetworkConfig,
) -> tuple[dict[str, object], dict[str, object]]:
    """Build IPv4 deny-all ingress and egress rules for every VM in the dedicated VPC."""
    if not isinstance(config, GceNetworkConfig):
        raise TypeError("config must be a GceNetworkConfig")
    network = _network_resource_path(config)
    ingress = {
        "name": "cybergym-deny-all-ingress-v4",
        "network": network,
        "direction": "INGRESS",
        "priority": 0,
        "disabled": False,
        "sourceRanges": ["0.0.0.0/0"],
        "denied": [{"IPProtocol": "all"}],
    }
    egress = {
        "name": "cybergym-deny-all-egress-v4",
        "network": network,
        "direction": "EGRESS",
        "priority": 0,
        "disabled": False,
        "destinationRanges": ["0.0.0.0/0"],
        "denied": [{"IPProtocol": "all"}],
    }
    return ingress, egress


def validate_gce_network_policy(
    network: Mapping[str, object],
    subnetwork: Mapping[str, object],
    firewall_rules: list[Mapping[str, object]],
    routes: list[Mapping[str, object]],
    config: GceNetworkConfig,
) -> None:
    """Verify dedicated VPC, IPv4-only subnet, deny-all firewalls, and no default route."""
    if not isinstance(network, Mapping) or (
        network.get("name") != config.network_name
        or network.get("autoCreateSubnetworks") is not False
        or network.get("peerings")
        or not isinstance(network.get("routingConfig"), Mapping)
        or network["routingConfig"].get("routingMode") != "REGIONAL"
    ):
        raise GceConfigurationError("observed VPC does not match the isolated custom-network policy")

    expected_subnet = build_gce_subnetwork_resource(config)
    if not isinstance(subnetwork, Mapping) or any(
        subnetwork.get(field) != expected_subnet[field]
        for field in ("name", "ipCidrRange", "stackType", "privateIpGoogleAccess")
    ):
        raise GceConfigurationError("observed subnet does not match the IPv4-only policy")
    if not _matches_resource_path(subnetwork.get("network"), _network_resource_path(config)):
        raise GceConfigurationError("observed subnet belongs to an unexpected VPC")
    if not _matches_resource_path(
        subnetwork.get("region"), f"projects/{config.project_id}/regions/{config.region}"
    ):
        raise GceConfigurationError("observed subnet belongs to an unexpected region")

    expected_rules = {
        "cybergym-deny-all-ingress-v4": build_gce_default_deny_firewall_resources(config)[0],
        "cybergym-deny-all-egress-v4": build_gce_default_deny_firewall_resources(config)[1],
    }
    observed_rules = {
        rule.get("name"): rule
        for rule in firewall_rules
        if isinstance(rule, Mapping)
        and _matches_resource_path(rule.get("network"), _network_resource_path(config))
    }
    if set(observed_rules) != set(expected_rules):
        raise GceConfigurationError("VPC must have exactly the two reviewed deny-all firewall rules")

    for name, expected in expected_rules.items():
        observed = observed_rules[name]
        for field in ("direction", "priority", "disabled", "denied"):
            if observed.get(field) != expected[field]:
                raise GceConfigurationError(f"firewall rule {name} has unexpected {field}")
        range_field = "sourceRanges" if name.endswith("ingress-v4") else "destinationRanges"
        if observed.get(range_field) != expected[range_field]:
            raise GceConfigurationError(f"firewall rule {name} has unexpected {range_field}")
        if observed.get("allowed") or observed.get("targetTags") or observed.get("targetServiceAccounts"):
            raise GceConfigurationError(f"firewall rule {name} contains an unsafe allow or target override")

    for route in routes:
        if not isinstance(route, Mapping) or not _matches_resource_path(
            route.get("network"), _network_resource_path(config)
        ):
            continue
        if route.get("destRange") in {"0.0.0.0/0", "::/0"} or any(
            route.get(field)
            for field in (
                "nextHopGateway",
                "nextHopInstance",
                "nextHopIp",
                "nextHopVpnTunnel",
                "nextHopIlb",
                "nextHopHub",
            )
        ):
            raise GceConfigurationError(
                "VPC must not have a default internet route or custom egress route"
            )


CANARY_FIXTURE_MARKER = b"CYBERGYM_OFFLINE_CANARY_OK"


class GceCanaryError(RuntimeError):
    """Raised when the harmless GCE canary does not complete its expected checks."""


class GceCleanupUnconfirmed(GceCanaryError):
    """Raised when the canary VM's deletion cannot be confirmed."""


class GceCanaryClient(Protocol):
    """Narrow control-plane interface; implementations must map 404 instance reads to None."""

    def verify_network_policy(self, config: GceNetworkConfig) -> None: ...

    def create_instance(
        self, project_id: str, zone: str, resource: Mapping[str, object]
    ) -> str: ...

    def get_zone_operation(
        self, project_id: str, zone: str, operation_name: str
    ) -> Mapping[str, object]: ...

    def get_instance(
        self, project_id: str, zone: str, instance_name: str
    ) -> Mapping[str, object] | None: ...

    def get_serial_port_output(
        self, project_id: str, zone: str, instance_name: str, max_bytes: int
    ) -> bytes: ...

    def delete_instance(self, project_id: str, zone: str, instance_name: str) -> str: ...


@dataclass(frozen=True)
class GceCanaryResult:
    """Minimal trusted summary; raw guest-controlled console output is not returned."""

    instance_name: str
    console_output_bytes: int
    fixture_marker_found: bool
    cleanup_confirmed: bool


class GceCanaryProvisioner:
    """Run one fixed, offline canary fixture and always confirm VM deletion."""

    def __init__(
        self,
        client: GceCanaryClient,
        instance_config: GceCanaryConfig,
        network_config: GceNetworkConfig,
        *,
        operation_timeout_seconds: float = 120.0,
        cleanup_timeout_seconds: float = 120.0,
        poll_interval_seconds: float = 1.0,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(instance_config, GceCanaryConfig):
            raise TypeError("instance_config must be a GceCanaryConfig")
        if not isinstance(network_config, GceNetworkConfig):
            raise TypeError("network_config must be a GceNetworkConfig")
        if instance_config.project_id != network_config.project_id:
            raise GceConfigurationError("instance and network projects must match")
        if instance_config.subnetwork != _subnetwork_resource_path(network_config):
            raise GceConfigurationError("instance subnet must match the isolated GCE network")
        if not 1 <= operation_timeout_seconds <= 600:
            raise GceConfigurationError("operation_timeout_seconds must be between 1 and 600")
        if not 1 <= cleanup_timeout_seconds <= 600:
            raise GceConfigurationError("cleanup_timeout_seconds must be between 1 and 600")
        if not 0.05 <= poll_interval_seconds <= 10:
            raise GceConfigurationError("poll_interval_seconds must be between 0.05 and 10")
        self._client = client
        self._instance_config = instance_config
        self._network_config = network_config
        self._operation_timeout = operation_timeout_seconds
        self._cleanup_timeout = cleanup_timeout_seconds
        self._poll_interval = poll_interval_seconds
        self._monotonic = monotonic
        self._sleep = sleep

    def run(self, run_id: str) -> GceCanaryResult:
        """Verify isolation, boot the baked-in fixture, capture bounded evidence, and delete."""
        instance_name = canary_instance_name(run_id)
        resource = build_canary_instance_resource(self._instance_config, run_id=run_id)
        created = False
        result: GceCanaryResult | None = None

        try:
            self._client.verify_network_policy(self._network_config)
            created = True
            create_operation = self._client.create_instance(
                self._instance_config.project_id,
                self._instance_config.zone,
                resource,
            )
            self._wait_for_operation(create_operation, self._operation_timeout)
            observed = self._client.get_instance(
                self._instance_config.project_id,
                self._instance_config.zone,
                instance_name,
            )
            if observed is None:
                raise GceCanaryError("GCE canary instance was not visible after creation")
            validate_canary_instance_resource(observed, self._instance_config, run_id=run_id)

            console = self._client.get_serial_port_output(
                self._instance_config.project_id,
                self._instance_config.zone,
                instance_name,
                self._instance_config.max_console_output_bytes,
            )
            if not isinstance(console, bytes):
                raise GceCanaryError("GCE serial-console output must be bytes")
            if len(console) > self._instance_config.max_console_output_bytes:
                raise GceCanaryError("GCE serial-console output exceeded the configured byte limit")
            if CANARY_FIXTURE_MARKER not in console:
                raise GceCanaryError("harmless GCE canary fixture marker was not observed")
            result = GceCanaryResult(
                instance_name=instance_name,
                console_output_bytes=len(console),
                fixture_marker_found=True,
                cleanup_confirmed=True,
            )
        finally:
            if created:
                self._delete_and_confirm(instance_name)

        if result is None:
            raise GceCanaryError("GCE canary did not produce a verified result")
        return result

    def _wait_for_operation(self, operation_name: str, timeout_seconds: float) -> None:
        if not isinstance(operation_name, str) or not operation_name:
            raise GceCanaryError("GCE operation returned an invalid operation name")
        deadline = self._monotonic() + timeout_seconds
        while self._monotonic() < deadline:
            operation = self._client.get_zone_operation(
                self._instance_config.project_id,
                self._instance_config.zone,
                operation_name,
            )
            if operation.get("status") == "DONE":
                if operation.get("error"):
                    raise GceCanaryError("GCE operation completed with an error")
                return
            self._sleep(min(self._poll_interval, max(0.0, deadline - self._monotonic())))
        raise GceCanaryError("GCE operation timed out")

    def _delete_and_confirm(self, instance_name: str) -> None:
        project_id = self._instance_config.project_id
        zone = self._instance_config.zone
        try:
            delete_operation = self._client.delete_instance(project_id, zone, instance_name)
            self._wait_for_operation(delete_operation, self._cleanup_timeout)
        except (GceCanaryError, TimeoutError, OSError) as exc:
            try:
                instance = self._client.get_instance(project_id, zone, instance_name)
            except (GceCanaryError, TimeoutError, OSError) as check_error:
                raise GceCleanupUnconfirmed(
                    "GCE canary deletion failed and instance absence could not be checked"
                ) from check_error
            if instance is None:
                return
            raise GceCleanupUnconfirmed(
                "GCE canary deletion failed and the instance still exists"
            ) from exc

        deadline = self._monotonic() + self._cleanup_timeout
        try:
            while self._monotonic() < deadline:
                if self._client.get_instance(project_id, zone, instance_name) is None:
                    return
                self._sleep(min(self._poll_interval, max(0.0, deadline - self._monotonic())))
        except (GceCanaryError, TimeoutError, OSError) as exc:
            raise GceCleanupUnconfirmed(
                "GCE canary deletion completed but instance absence could not be checked"
            ) from exc
        raise GceCleanupUnconfirmed(
            "GCE canary deletion operation completed but the instance still exists"
        )
