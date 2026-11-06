"""Authenticated Google Compute Engine REST adapter for the disposable canary.

The adapter is opt-in: importing this module does not load credentials or contact GCP.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from vulnresearch.execution.gce import (
    GceCanaryClient,
    GceCanaryError,
    GceNetworkConfig,
    _matches_resource_path,
    _subnetwork_resource_path,
    validate_gce_network_policy,
)


class GceRestClient(GceCanaryClient):
    """Minimal authenticated REST client for one isolated GCE canary project."""

    API_ROOT = "https://compute.googleapis.com/compute/v1"
    BETA_API_ROOT = "https://compute.googleapis.com/compute/beta"
    COMPUTE_SCOPE = "https://www.googleapis.com/auth/compute"
    MAX_LIST_PAGES = 100
    MAX_LIST_ITEMS = 10_000

    def __init__(self, session: Any | None = None, *, request_timeout_seconds: float = 20.0):
        if not 1 <= request_timeout_seconds <= 60:
            raise ValueError("request_timeout_seconds must be between 1 and 60")
        self._transport_errors: tuple[type[BaseException], ...] = (
            TimeoutError,
            OSError,
            ConnectionError,
        )
        if session is None:
            try:
                import google.auth
                from google.auth.exceptions import GoogleAuthError
                from google.auth.transport.requests import AuthorizedSession
                from requests import RequestException
            except ImportError as exc:
                raise GceCanaryError(
                    "GCP client dependencies are unavailable; install the gcp extra"
                ) from exc
            self._transport_errors += (GoogleAuthError, RequestException)
            try:
                credentials, _ = google.auth.default(scopes=[self.COMPUTE_SCOPE])
            except (GoogleAuthError, OSError) as exc:
                raise GceCanaryError(
                    "GCP Application Default Credentials are unavailable"
                ) from exc
            session = AuthorizedSession(credentials)
        self._session = session
        self._timeout = request_timeout_seconds

    @staticmethod
    def _segment(value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 256:
            raise GceCanaryError("GCE resource path segment is invalid")
        return quote(value, safe="")

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, object] | None = None,
        body: Mapping[str, object] | None = None,
        allow_not_found: bool = False,
        beta: bool = False,
    ) -> Mapping[str, object] | None:
        root = self.BETA_API_ROOT if beta else self.API_ROOT
        try:
            response = self._session.request(
                method,
                f"{root}{path}",
                params=dict(params) if params is not None else None,
                json=dict(body) if body is not None else None,
                timeout=self._timeout,
            )
        except self._transport_errors as exc:
            raise GceCanaryError("GCE API request failed") from exc

        status = getattr(response, "status_code", None)
        if allow_not_found and status == 404:
            return None
        if not isinstance(status, int) or status < 200 or status >= 300:
            raise GceCanaryError(f"GCE API returned HTTP {status} for {method} request")
        try:
            payload = response.json()
        except ValueError as exc:
            raise GceCanaryError("GCE API returned invalid JSON") from exc
        if not isinstance(payload, Mapping):
            raise GceCanaryError("GCE API returned an unexpected response shape")
        return payload

    def _list_all(self, path: str, *, beta: bool = False) -> list[Mapping[str, object]]:
        items: list[Mapping[str, object]] = []
        page_token: str | None = None
        seen_tokens: set[str] = set()
        page_count = 0
        while True:
            if page_count >= self.MAX_LIST_PAGES:
                raise GceCanaryError("GCE list API exceeded the configured page limit")
            page_count += 1
            params = {"pageToken": page_token} if page_token else None
            payload = self._request("GET", path, params=params, beta=beta)
            assert payload is not None
            page_items = payload.get("items", [])
            if not isinstance(page_items, list) or any(
                not isinstance(item, Mapping) for item in page_items
            ):
                raise GceCanaryError("GCE list API returned an invalid items collection")
            if len(items) + len(page_items) > self.MAX_LIST_ITEMS:
                raise GceCanaryError("GCE list API exceeded the configured item limit")
            items.extend(page_items)
            next_token = payload.get("nextPageToken")
            if not next_token:
                return items
            if not isinstance(next_token, str) or not next_token:
                raise GceCanaryError("GCE list API returned an invalid page token")
            if next_token in seen_tokens:
                raise GceCanaryError("GCE list API returned a repeated page token")
            seen_tokens.add(next_token)
            page_token = next_token

    @staticmethod
    def _operation_name(payload: Mapping[str, object]) -> str:
        name = payload.get("name")
        if not isinstance(name, str) or not name:
            raise GceCanaryError("GCE API did not return an operation name")
        return name

    def create_instance(
        self, project_id: str, zone: str, resource: Mapping[str, object]
    ) -> str:
        payload = self._request(
            "POST",
            f"/projects/{self._segment(project_id)}/zones/{self._segment(zone)}/instances",
            body=resource,
        )
        assert payload is not None
        return self._operation_name(payload)

    def get_zone_operation(
        self, project_id: str, zone: str, operation_name: str
    ) -> Mapping[str, object]:
        payload = self._request(
            "GET",
            f"/projects/{self._segment(project_id)}/zones/{self._segment(zone)}"
            f"/operations/{self._segment(operation_name)}",
        )
        assert payload is not None
        return payload

    def get_instance(
        self, project_id: str, zone: str, instance_name: str
    ) -> Mapping[str, object] | None:
        return self._request(
            "GET",
            f"/projects/{self._segment(project_id)}/zones/{self._segment(zone)}"
            f"/instances/{self._segment(instance_name)}",
            allow_not_found=True,
        )

    def get_serial_port_output(
        self, project_id: str, zone: str, instance_name: str, max_bytes: int
    ) -> bytes:
        if type(max_bytes) is not int or not 1 <= max_bytes <= 1024 * 1024:
            raise GceCanaryError("serial-console byte limit is invalid")
        payload = self._request(
            "GET",
            f"/projects/{self._segment(project_id)}/zones/{self._segment(zone)}"
            f"/instances/{self._segment(instance_name)}/serialPort",
            params={"port": 1, "start": 0},
        )
        assert payload is not None
        try:
            start = int(payload.get("start", "0"))
        except (TypeError, ValueError) as exc:
            raise GceCanaryError("GCE serial-console response has an invalid start offset") from exc
        contents = payload.get("contents")
        if start != 0 or not isinstance(contents, str):
            raise GceCanaryError("GCE serial-console buffer was truncated or malformed")
        output = contents.encode("utf-8")
        if len(output) > max_bytes:
            raise GceCanaryError("GCE serial-console output exceeded the configured byte limit")
        return output

    def delete_instance(self, project_id: str, zone: str, instance_name: str) -> str:
        payload = self._request(
            "DELETE",
            f"/projects/{self._segment(project_id)}/zones/{self._segment(zone)}"
            f"/instances/{self._segment(instance_name)}",
        )
        assert payload is not None
        return self._operation_name(payload)

    def verify_network_policy(self, config: GceNetworkConfig) -> None:
        project = self._segment(config.project_id)
        network_name = self._segment(config.network_name)
        region = self._segment(config.region)
        subnet_name = self._segment(config.subnet_name)
        network = self._request(
            "GET", f"/projects/{project}/global/networks/{network_name}"
        )
        subnet = self._request(
            "GET", f"/projects/{project}/regions/{region}/subnetworks/{subnet_name}"
        )
        assert network is not None and subnet is not None
        subnetworks = network.get("subnetworks", [])
        if (
            not isinstance(subnetworks, list)
            or len(subnetworks) != 1
            or not _matches_resource_path(subnetworks[0], _subnetwork_resource_path(config))
        ):
            raise GceCanaryError("dedicated GCE VPC must contain only the approved canary subnet")

        firewalls = self._list_all(f"/projects/{project}/global/firewalls")
        routes = self._list_all(f"/projects/{project}/global/routes")
        validate_gce_network_policy(network, subnet, firewalls, routes, config)

        effective = self._request(
            "GET",
            f"/projects/{project}/global/networks/{network_name}/getEffectiveFirewalls",
            beta=True,
        )
        assert effective is not None
        policies = effective.get("firewallPolicys", [])
        if not isinstance(policies, list):
            raise GceCanaryError("effective GCE firewall policy response is malformed")
        for policy in policies:
            if not isinstance(policy, Mapping):
                raise GceCanaryError("effective GCE firewall policy entry is malformed")
            rules = policy.get("rules", [])
            if not isinstance(rules, list):
                raise GceCanaryError("effective GCE firewall policy rules are malformed")
            for rule in rules:
                if not isinstance(rule, Mapping):
                    raise GceCanaryError("effective GCE firewall policy rule is malformed")
                if rule.get("disabled") is True:
                    continue
                if rule.get("action") not in {"deny", "goto_next"}:
                    raise GceCanaryError(
                        "effective hierarchical firewall policy contains a non-deny action"
                    )

        regions = self._list_all(f"/projects/{project}/regions")
        if not regions:
            raise GceCanaryError("GCE project returned no regions for isolation verification")
        for region_item in regions:
            region_name = region_item.get("name")
            if not isinstance(region_name, str) or not region_name:
                raise GceCanaryError("GCE region list contains an invalid resource")
            region_segment = self._segment(region_name)
            for collection in ("routers", "forwardingRules", "vpnGateways", "targetVpnGateways"):
                resources = self._list_all(
                    f"/projects/{project}/regions/{region_segment}/{collection}"
                )
                if resources:
                    raise GceCanaryError(
                        f"dedicated GCE sandbox project must not contain regional {collection}"
                    )

        global_forwarding_rules = self._list_all(
            f"/projects/{project}/global/forwardingRules"
        )
        if global_forwarding_rules:
            raise GceCanaryError(
                "dedicated GCE sandbox project must not contain global forwarding rules"
            )
