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
        "machineType": f"zones/{config.zone}/machineTypes/{config.machine_type}",
        "disks": [
            {
                "boot": True,
                "autoDelete": True,
                "initializeParams": {
                    "sourceImage": config.approved_image,
                    "diskSizeGb": config.boot_disk_size_gb,
                    "diskType": f"zones/{config.zone}/diskTypes/pd-balanced",
                },
            }
        ],
        "networkInterfaces": [{"subnetwork": config.subnetwork}],
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


def validate_canary_instance_resource(
    resource: Mapping[str, object], config: GceCanaryConfig, *, run_id: str
) -> None:
    """Reject an observed instance unless it exactly retains the canary security policy."""
    if not isinstance(resource, Mapping):
        raise GceConfigurationError("instance resource must be a mapping")

    expected = build_canary_instance_resource(config, run_id=run_id)
    for field in (
        "name",
        "machineType",
        "disks",
        "shieldedInstanceConfig",
        "canIpForward",
        "deletionProtection",
        "scheduling",
        "tags",
        "labels",
    ):
        if resource.get(field) != expected[field]:
            raise GceConfigurationError(f"observed instance has an unexpected {field} value")

    interfaces = resource.get("networkInterfaces")
    if not isinstance(interfaces, list) or len(interfaces) != 1:
        raise GceConfigurationError("observed instance must have exactly one network interface")
    interface = interfaces[0]
    if not isinstance(interface, Mapping) or interface.get("subnetwork") != config.subnetwork:
        raise GceConfigurationError("observed instance is attached to an unexpected subnet")
    if interface.get("accessConfigs") or interface.get("ipv6AccessConfigs"):
        raise GceConfigurationError("observed instance must not have a public IP configuration")

    if resource.get("serviceAccounts"):
        raise GceConfigurationError("guest service accounts are forbidden")
    if resource.get("metadata"):
        raise GceConfigurationError("guest-visible instance metadata is forbidden")
    if resource.get("hostname"):
        raise GceConfigurationError("custom guest hostnames are not permitted")
