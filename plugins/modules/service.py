#!/usr/bin/python
# Copyright (c) 2025, zupersero
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r"""
---
module: service
short_description: Manage Tailscale service records
description:
  - Creates, updates, or deletes Tailscale service records in a tailnet.
  - Uses the Tailscale API services endpoints.
options:
  name:
    description:
      - Unique service name.
      - Tailscale service names must be prefixed with C(svc:).
    type: str
    required: true
  state:
    description:
      - Whether the Tailscale service record should exist.
    type: str
    choices: [present, absent]
    default: present
  ports:
    description:
      - Ports exposed by the service.
      - Values are sent to Tailscale as TCP service ports, for example C(443) becomes C(tcp:443).
      - Required when C(state=present).
    type: list
    elements: int
  tags:
    description:
      - Tags associated with the service.
      - Tags must be prefixed with C(tag:).
      - If omitted, existing tags are preserved when updating an existing service.
    type: list
    elements: str
  comment:
    description:
      - Optional comment for the service.
      - If omitted, the existing comment is preserved when updating an existing service.
    type: str
  url:
    description:
      - Base URL for the Tailscale API.
      - If unset, the C(TAILSCALE_API_URL) environment variable is used.
    type: str
    default: https://api.tailscale.com/api/v2
  api_key:
    description:
      - Tailscale API key.
      - If unset, the C(TAILSCALE_AUTH_KEY) environment variable is used.
    type: str
  tailnet:
    description:
      - Tailnet ID or organization name to manage.
      - If unset, the C(TAILSCALE_TAILNET_ID) environment variable is used.
    type: str
  validate_certs:
    description:
      - Whether to validate SSL certificates.
      - If unset, the C(TAILSCALE_VALIDATE_CERTS) environment variable is used.
    type: bool
    default: true
  timeout:
    description:
      - Timeout in seconds for API requests.
    type: int
    default: 30
  retries:
    description:
      - Number of times to retry retryable API failures.
    type: int
    default: 3
  retry_pause:
    description:
      - Base delay in seconds between retry attempts.
    type: float
    default: 1
  client_cert:
    description:
      - PEM formatted client certificate chain file for SSL client authentication.
    type: path
  client_key:
    description:
      - PEM formatted private key file for SSL client authentication.
    type: path
  force_basic_auth:
    description:
      - Whether to send basic authentication credentials before receiving a C(401) response.
    type: bool
    default: false
  url_username:
    description:
      - Username for basic authentication.
    type: str
  url_password:
    description:
      - Password for basic authentication.
    type: str
author:
  - Zupersero (@zupersero)
notes:
  - This module manages service records only. It does not approve or revoke service hosting devices.
  - The Tailscale API assigns service addresses; C(addrs) is returned but not managed.
"""

EXAMPLES = r"""
- name: Create a Tailscale service
  zupersero.tailscale.service:
    tailnet: "example.com"
    api_key: "{{ lookup('env', 'TAILSCALE_AUTH_KEY') }}"
    name: svc:web
    ports:
      - 80
      - 443
    tags:
      - tag:prod
    comment: Production web service

- name: Remove a Tailscale service
  zupersero.tailscale.service:
    tailnet: "example.com"
    api_key: "{{ lookup('env', 'TAILSCALE_AUTH_KEY') }}"
    name: svc:web
    state: absent
"""

RETURN = r"""
service:
  description: Service object returned by the Tailscale API.
  type: dict
  returned: when available
previous_service:
  description: Existing service object before an update or delete.
  type: dict
  returned: when available
"""

from typing import Any, Optional, Union  # noqa: E402

from ansible.module_utils.basic import AnsibleModule  # noqa: E402

from ansible_collections.zupersero.tailscale.plugins.module_utils.tailscale import (  # noqa: E402
    TailscaleClient,
    TailscaleError,
    tailscale_argument_spec,
    tailscale_mutually_exclusive,
    tailscale_required_if,
    tailscale_required_together,
)


def _validate_service_name(module: AnsibleModule, name: str) -> None:
    if not name.startswith("svc:") or name == "svc:":
        module.fail_json(msg="name must be a Tailscale service name prefixed with 'svc:'")


ResponseData = Union[dict, list, str, None]


def _validate_ports(module: AnsibleModule, ports: Optional[list[int]], state: str) -> list[int]:
    if state == "present" and not ports:
        module.fail_json(msg="ports is required when state=present")
    if not ports:
        return []

    normalized = []
    for port in ports:
        if port < 1 or port > 65535:
            module.fail_json(msg=f"ports entries must be between 1 and 65535, got {port}")
        normalized.append(port)
    return normalized


def _validate_tags(module: AnsibleModule, tags: Optional[list[str]]) -> Optional[list[str]]:
    if tags is None:
        return None
    for tag in tags:
        if not tag.startswith("tag:") or tag == "tag:":
            module.fail_json(msg="tags entries must be prefixed with 'tag:'")
    return tags


def _normalize_ports(ports: Any) -> list[str]:
    if not ports:
        return []
    normalized = []
    for port in ports:
        value = str(port)
        if value.isdigit():
            value = f"tcp:{value}"
        normalized.append(value)
    return sorted(normalized)


def _service_payload(
    name: str,
    ports: list[int],
    tags: Optional[list[str]],
    comment: Optional[str],
    current: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    payload = {
        "name": name,
        "ports": _normalize_ports(ports),
    }
    if current and current.get("addrs"):
        payload["addrs"] = current["addrs"]
    if tags is not None:
        payload["tags"] = tags
    elif current and "tags" in current:
        payload["tags"] = current.get("tags") or []
    if comment is not None:
        payload["comment"] = comment
    elif current and "comment" in current:
        payload["comment"] = current.get("comment") or ""
    return payload


def _normalize_service(service: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "name": service.get("name"),
        "ports": _normalize_ports(service.get("ports")),
    }
    if "tags" in service:
        normalized["tags"] = sorted(service.get("tags") or [])
    if "comment" in service:
        normalized["comment"] = service.get("comment") or ""
    return normalized


def _service_matches(current: dict[str, Any], desired: dict[str, Any]) -> bool:
    normalized_current = _normalize_service(current)
    normalized_desired = {
        "name": desired["name"],
        "ports": _normalize_ports(desired["ports"]),
    }
    if "tags" in desired:
        normalized_desired["tags"] = sorted(desired["tags"])
    if "comment" in desired:
        normalized_desired["comment"] = desired["comment"]
    for key, value in normalized_desired.items():
        if normalized_current.get(key) != value:
            return False
    return True


def _api_error(data: ResponseData, default: str) -> str:
    if isinstance(data, dict):
        return str(data.get("error") or data.get("message") or default)
    if data is not None:
        return str(data)
    return default


def _get_current_service(module: AnsibleModule, client: TailscaleClient, name: str) -> Optional[dict[str, Any]]:
    status, data = client.get_service(name)
    if status == 404:
        return None
    if status >= 400:
        module.fail_json(msg=_api_error(data, "Tailscale API returned an error while fetching the service"))
    if not isinstance(data, dict):
        module.fail_json(msg="Unexpected response from Tailscale API while fetching the service")
    return data


def _update_service(
    module: AnsibleModule,
    client: TailscaleClient,
    name: str,
    payload: dict[str, Any],
) -> Optional[dict[str, Any]]:
    status, data = client.update_service(name, payload)
    if status >= 400:
        module.fail_json(msg=_api_error(data, "Tailscale API returned an error while updating the service"))
    if data is not None and not isinstance(data, dict):
        module.fail_json(msg="Unexpected response from Tailscale API while updating the service")
    return data


def _delete_service(module: AnsibleModule, client: TailscaleClient, name: str) -> None:
    status, data = client.delete_service(name)
    if status == 404:
        return
    if status >= 400:
        module.fail_json(msg=_api_error(data, "Tailscale API returned an error while deleting the service"))


def main() -> None:
    argument_spec = tailscale_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
        ports=dict(type="list", elements="int"),
        tags=dict(type="list", elements="str"),
        comment=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=tailscale_required_together(),
        required_if=tailscale_required_if(),
        mutually_exclusive=tailscale_mutually_exclusive(),
    )

    name = module.params["name"]
    state = module.params["state"]
    ports = _validate_ports(module, module.params.get("ports"), state)
    tags = _validate_tags(module, module.params["tags"])
    comment = module.params.get("comment")

    _validate_service_name(module, name)

    client = TailscaleClient(module)

    try:
        current = _get_current_service(module, client, name)
    except TailscaleError as exc:
        module.fail_json(msg=str(exc))

    result: dict[str, Any] = {"changed": False}
    if current is not None:
        result["previous_service"] = current

    if state == "absent":
        if current is None:
            module.exit_json(**result)
        result["changed"] = True
        if module.check_mode:
            module.exit_json(**result)
        try:
            _delete_service(module, client, name)
        except TailscaleError as exc:
            module.fail_json(msg=str(exc))
        module.exit_json(**result)

    desired = _service_payload(name, ports, tags, comment, current=current)
    if current is not None and _service_matches(current, desired):
        result["service"] = current
        module.exit_json(**result)

    result["changed"] = True
    if module.check_mode:
        result["service"] = desired
        module.exit_json(**result)

    try:
        service = _update_service(module, client, name, desired)
    except TailscaleError as exc:
        module.fail_json(msg=str(exc))

    if service is not None:
        result["service"] = service

    module.exit_json(**result)


if __name__ == "__main__":
    main()
