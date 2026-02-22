# Copyright (c) 2025, zupersero
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from typing import Any
import os

from ansible.errors import AnsibleError
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable

from ansible_collections.zupersero.tailscale.plugins.module_utils.tailscale import (
    TailscaleClient,
    TailscaleError,
    TAILSCALE_API_DEFAULT_URL,
)


DOCUMENTATION = r"""
name: tailscale
plugin_type: inventory
short_description: Inventory from Tailscale tailnet devices.
description:
  - Fetches devices from the Tailscale API and exposes them as inventory hosts.
  - Uses a Tailscale API key with read access to devices.
options:
  plugin:
    description: Token that ensures this is a source file for the C(tailscale) plugin.
    required: true
    choices: ["zupersero.tailscale.tailscale"]
  api_key:
    description:
      - Tailscale API key (C(tskey-api-...)).
      - If unset, the C(TAILSCALE_AUTH_KEY) environment variable is used.
    required: false
    type: str
  tailnet:
    description:
      - Tailnet ID to query (from the Tailscale admin console).
      - If unset, the C(TAILSCALE_TAILNET_ID) environment variable is used.
    required: false
    type: str
  api_url:
    description:
      - Base URL for the Tailscale API.
    required: false
    type: str
    default: https://api.tailscale.com/api/v2
  validate_certs:
    description:
      - Whether to validate SSL certificates.
    type: bool
    default: true
  timeout:
    description:
      - Timeout in seconds for API requests.
    type: int
    default: 30
  retries:
    description:
      - Number of times to retry failed requests.
    type: int
    default: 3
  retry_pause:
    description:
      - Seconds to wait between retry attempts.
    type: float
    default: 1.0
  fields:
    description:
      - Controls device field selection in API responses.
    type: str
    choices: [default, all]
    default: all
  filters:
    description:
      - Optional server-side filters passed as query parameters.
    type: dict
    required: false
  hostname_source:
    description:
      - Which device field to use as the Ansible inventory hostname.
    type: str
    choices: [hostname, name, nodeId, id]
    default: hostname
  use_tailscale_ip:
    description:
      - Whether to set C(ansible_host) from device addresses.
    type: bool
    default: true
  ip_version:
    description:
      - Which Tailscale IP address to prefer when setting C(ansible_host).
    type: str
    choices: [auto, ipv4, ipv6]
    default: auto
  include_services:
    description:
      - Whether to attach the list of Tailscale services hosted on each device.
    type: bool
    default: false
  group_by_tag:
    description:
      - Whether to add each host to groups based on its Tailscale tags.
      - Tag groups are prefixed with C(tag_) and strip the leading C(tag:) marker.
    type: bool
    default: true
  strict:
    description:
      - Strict mode for Jinja2 expressions in C(compose/groups/keyed_groups).
    type: bool
    default: true
  compose:
    description:
      - Create vars using Jinja2 expressions.
    type: dict
    required: false
  groups:
    description:
      - Add hosts to groups based on Jinja2 conditions.
    type: dict
    required: false
  keyed_groups:
    description:
      - Add hosts to groups based on the values of a variable.
    type: list
    required: false
  cache:
    description:
      - Cache the inventory results.
    type: bool
    default: false
  cache_timeout:
    description:
      - Cache timeout in seconds.
    type: int
    default: 3600
"""

EXAMPLES = r"""
- name: Use Tailscale as inventory
  plugin: zupersero.tailscale.tailscale
  tailnet: "example.com"
  api_key: "{{ lookup('env', 'TAILSCALE_AUTH_KEY') }}"

- name: Filter devices by tag and set ansible_host
  plugin: zupersero.tailscale.tailscale
  tailnet: "example.com"
  api_key: "{{ lookup('env', 'TAILSCALE_AUTH_KEY') }}"
  filters:
    tags: "tag:prod"
  hostname_source: name
  use_tailscale_ip: true
  ip_version: ipv4

- name: Group by OS using keyed_groups
  plugin: zupersero.tailscale.tailscale
  tailnet: "example.com"
  api_key: "{{ lookup('env', 'TAILSCALE_AUTH_KEY') }}"
  keyed_groups:
    - key: tailscale_device.os
      prefix: os

- name: Group by tag automatically
  plugin: zupersero.tailscale.tailscale
  tailnet: "example.com"
  api_key: "{{ lookup('env', 'TAILSCALE_AUTH_KEY') }}"
  group_by_tag: true

- name: Include services for each device
  plugin: zupersero.tailscale.tailscale
  tailnet: "example.com"
  api_key: "{{ lookup('env', 'TAILSCALE_AUTH_KEY') }}"
  include_services: true
"""


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    NAME = "tailscale"

    def _template_value(self, value: Any) -> Any:
        if value is None:
            return value
        if isinstance(value, str):
            return self.templar.template(value)
        if isinstance(value, list):
            return [self._template_value(item) for item in value]
        if isinstance(value, dict):
            return {key: self._template_value(val) for key, val in value.items()}
        return value

    def verify_file(self, path: str) -> bool:
        if not super().verify_file(path):
            return False
        return path.endswith((".yml", ".yaml"))

    def parse(self, inventory: Any, loader: Any, path: str, cache: bool = True) -> None:
        super().parse(inventory, loader, path)
        self._read_config_data(path)

        cache_key = self.get_cache_key(path)
        use_cache = cache and self.get_option("cache")

        if use_cache and cache_key in self._cache:
            devices = self._cache[cache_key]
        else:
            devices = self._fetch_devices()
            if use_cache:
                self._cache[cache_key] = devices

        services_by_node = {}
        if self.get_option("include_services"):
            services_by_node = self._fetch_services_by_node()

        for device in devices:
            sanitized = self._sanitize_device(device)
            host = self._get_hostname(sanitized)
            if not host:
                continue

            self.inventory.add_host(host)
            self.inventory.set_variable(host, "tailscale_device", sanitized)

            if self.get_option("use_tailscale_ip"):
                address = self._select_address(sanitized.get("addresses", []))
                if address:
                    self.inventory.set_variable(host, "ansible_host", address)

            if services_by_node:
                node_id = sanitized.get("nodeId")
                if node_id:
                    self.inventory.set_variable(host, "tailscale_services", services_by_node.get(node_id, []))

            os_value = sanitized.get("os")
            if os_value:
                group_name = self._sanitize_group_name(f"os_{str(os_value).lower().replace(' ', '_')}")
                self.inventory.add_group(group_name)
                self.inventory.add_host(host, group_name)

            if self.get_option("group_by_tag"):
                self._add_host_to_tag_groups(host, sanitized.get("tags", []))

            self._set_composite_vars(self.get_option("compose"), sanitized, host, strict=self.get_option("strict"))
            self._add_host_to_composed_groups(self.get_option("groups"), sanitized, host, strict=self.get_option("strict"))
            self._add_host_to_keyed_groups(self.get_option("keyed_groups"), sanitized, host, strict=self.get_option("strict"))

    def _fetch_devices(self) -> list[dict[str, Any]]:
        api_key = self._template_value(self.get_option("api_key")) or os.environ.get("TAILSCALE_AUTH_KEY")
        tailnet = self._template_value(self.get_option("tailnet")) or os.environ.get("TAILSCALE_TAILNET_ID")
        if not api_key:
            raise AnsibleError("Tailscale API key is required (api_key or TAILSCALE_AUTH_KEY).")
        if not tailnet:
            raise AnsibleError("Tailscale tailnet ID is required (tailnet or TAILSCALE_TAILNET_ID).")

        api_url = self._template_value(self.get_option("api_url")) or TAILSCALE_API_DEFAULT_URL
        fields = self._template_value(self.get_option("fields"))
        filters = self._template_value(self.get_option("filters"))

        client = TailscaleClient(
            module=None,
            api_key=api_key,
            tailnet=tailnet,
            url=api_url,
            validate_certs=self.get_option("validate_certs"),
            timeout=self.get_option("timeout"),
            retries=self.get_option("retries"),
            retry_pause=self.get_option("retry_pause"),
        )

        try:
            status, data = client.list_devices(fields=fields, filters=filters)
        except TailscaleError as e:
            raise AnsibleError(str(e))

        if status >= 400:
            error_msg = "Tailscale API returned an error"
            if isinstance(data, dict):
                error_msg = data.get("error", error_msg)
            raise AnsibleError(error_msg)

        if isinstance(data, dict):
            devices = data.get("devices", [])
        else:
            devices = []
        if not isinstance(devices, list):
            raise AnsibleError("Unexpected response from Tailscale API.")
        return devices

    def _fetch_services_by_node(self) -> dict[str, list[str]]:
        api_key = self._template_value(self.get_option("api_key")) or os.environ.get("TAILSCALE_AUTH_KEY")
        tailnet = self._template_value(self.get_option("tailnet")) or os.environ.get("TAILSCALE_TAILNET_ID")
        if not api_key:
            raise AnsibleError("Tailscale API key is required (api_key or TAILSCALE_AUTH_KEY).")
        if not tailnet:
            raise AnsibleError("Tailscale tailnet ID is required (tailnet or TAILSCALE_TAILNET_ID).")

        api_url = self._template_value(self.get_option("api_url")) or TAILSCALE_API_DEFAULT_URL

        client = TailscaleClient(
            module=None,
            api_key=api_key,
            tailnet=tailnet,
            url=api_url,
            validate_certs=self.get_option("validate_certs"),
            timeout=self.get_option("timeout"),
            retries=self.get_option("retries"),
            retry_pause=self.get_option("retry_pause"),
        )

        try:
            status, data = client.list_services()
        except TailscaleError as e:
            raise AnsibleError(str(e))

        if status >= 400:
            error_msg = "Tailscale API returned an error"
            if isinstance(data, dict):
                error_msg = data.get("error", error_msg)
            raise AnsibleError(error_msg)

        services = []
        if isinstance(data, dict):
            services = data.get("vipServices", [])
        if not isinstance(services, list):
            return {}

        services_by_node: dict[str, list[str]] = {}
        for service in services:
            service_name = service.get("name")
            if not service_name:
                continue
            try:
                host_status, host_data = client.list_service_hosts(service_name)
            except TailscaleError as e:
                raise AnsibleError(str(e))
            if host_status >= 400:
                continue
            if not isinstance(host_data, dict):
                continue
            hosts = host_data.get("hosts", [])
            if not isinstance(hosts, list):
                continue
            for host_info in hosts:
                node_id = host_info.get("stableNodeID")
                if not node_id:
                    continue
                services_by_node.setdefault(node_id, []).append(service_name)

        return services_by_node

    def _get_hostname(self, device: dict[str, Any]) -> str:
        source = self.get_option("hostname_source")
        value = device.get(source)
        if not value and source != "hostname":
            value = device.get("hostname") or device.get("name") or device.get("nodeId") or device.get("id")
        if not value:
            return ""
        return str(value)

    def _sanitize_device(self, device: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "hostname",
            "name",
            "nodeId",
            "id",
            "os",
            "user",
            "tags",
            "addresses",
        }
        return {key: device.get(key) for key in allowed if key in device}

    def _select_address(self, addresses: list[str]) -> str | None:
        ip_version = self.get_option("ip_version")
        if ip_version == "ipv4":
            for addr in addresses:
                if ":" not in addr:
                    return addr
        elif ip_version == "ipv6":
            for addr in addresses:
                if ":" in addr:
                    return addr
        else:
            for addr in addresses:
                if ":" not in addr:
                    return addr
            for addr in addresses:
                if ":" in addr:
                    return addr
        return None

    def _add_host_to_tag_groups(self, host: str, tags: Any) -> None:
        if not isinstance(tags, list):
            return
        for tag in tags:
            if not tag:
                continue
            tag_value = str(tag)
            if tag_value.startswith("tag:"):
                tag_value = tag_value[4:]
            normalized = tag_value.lower().replace(" ", "_")
            if not normalized:
                continue
            group_name = self._sanitize_group_name(f"tag_{normalized}")
            self.inventory.add_group(group_name)
            self.inventory.add_host(host, group_name)
