"""Fail-closed Google Compute Engine configuration for the offline VM canary.

This module builds and verifies instance resources only. It does not call Google Cloud,
provision infrastructure, or enable benchmark execution.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Mapping


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
    return path == expected or path.endswith("/" + expected)


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
