#!/usr/bin/python
# Copyright (c) 2025, zupersero
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r"""
---
module: serve
short_description: Manage Tailscale Serve endpoints on a host
description:
  - Starts or stops a local Tailscale Serve endpoint using the C(tailscale) CLI.
  - Can serve from the node itself or from a Tailscale Service when C(service) is set.
options:
  state:
    description:
      - Whether the Serve endpoint should be configured.
    type: str
    choices: [present, absent]
    default: present
  target:
    description:
      - Local target to serve, such as C(3000), C(localhost:3000), C(http://127.0.0.1:3000), a file, or a directory.
      - Required when C(state=present).
    type: str
  service:
    description:
      - Optional Tailscale Service name to serve for instead of the node itself.
      - Service names must be prefixed with C(svc:).
    type: str
  protocol:
    description:
      - Public listener type to configure.
    type: str
    choices: [https, http, tcp, tls_terminated_tcp]
    default: https
  port:
    description:
      - Public port to expose on the node or service.
    type: int
    default: 443
  path:
    description:
      - Web path to attach the handler to.
      - Applies to C(http) and C(https) listeners.
    type: str
    default: /
  background:
    description:
      - Run Serve persistently in the background.
    type: bool
    default: true
  accept_app_caps:
    description:
      - App capabilities to forward to the backend.
    type: list
    elements: str
    default: []
  proxy_protocol:
    description:
      - PROXY protocol version for TCP forwarding.
    type: int
    choices: [1, 2]
  tun:
    description:
      - Forward all traffic to the local machine.
      - Only supported when C(service) is set.
    type: bool
    default: false
  tailscale_bin:
    description:
      - Path to the C(tailscale) CLI binary.
    type: str
    default: tailscale
author:
  - Zupersero (@zupersero)
requirements:
  - tailscale CLI available locally
notes:
  - This module runs locally on the target host.
  - Tailscale Serve requires HTTPS certificates to be enabled in the tailnet for HTTPS listeners.
"""

EXAMPLES = r"""
- name: Serve a local development server over HTTPS
  zupersero.tailscale.serve:
    target: "3000"

- name: Serve a backend for a Tailscale Service
  zupersero.tailscale.serve:
    service: svc:web
    target: "http://127.0.0.1:8080"
    port: 443

- name: Stop serving the HTTPS listener
  zupersero.tailscale.serve:
    state: absent
    port: 443
"""

RETURN = r"""
configured:
  description: Whether the requested endpoint appears configured after the module runs.
  type: bool
  returned: always
status:
  description: Parsed C(tailscale serve status --json) output after the module runs, when available.
  type: dict
  returned: when available
"""

from typing import Any, Optional  # noqa: E402

from ansible.module_utils.basic import AnsibleModule  # noqa: E402

from ansible_collections.zupersero.tailscale.plugins.module_utils.tailscale import TailscaleError  # noqa: E402
from ansible_collections.zupersero.tailscale.plugins.module_utils.tailscale_cli import (  # noqa: E402
    TailscaleCliClient,
    tailscale_cli_argument_spec,
    tailscale_cli_mutually_exclusive,
    tailscale_cli_required_if,
    tailscale_cli_required_together,
)


PROTOCOL_FLAGS = {
    "https": "--https",
    "http": "--http",
    "tcp": "--tcp",
    "tls_terminated_tcp": "--tls-terminated-tcp",
}

PROTOCOL_KEYS = {
    "https": "HTTPS",
    "http": "HTTP",
    "tcp": "TCPForward",
    "tls_terminated_tcp": "TLS",
}


def _validate_params(module: AnsibleModule) -> None:
    state = module.params["state"]
    target = module.params.get("target")
    service = module.params.get("service")
    protocol = module.params["protocol"]
    port = module.params["port"]
    path = module.params["path"]
    tun = module.params["tun"]

    if state == "present" and not target:
        module.fail_json(msg="target is required when state=present")
    if service and (not service.startswith("svc:") or service == "svc:"):
        module.fail_json(msg="service must be a Tailscale service name prefixed with 'svc:'")
    if port < 1 or port > 65535:
        module.fail_json(msg=f"port must be between 1 and 65535, got {port}")
    if not path.startswith("/"):
        module.fail_json(msg="path must start with '/'")
    if protocol in ("tcp", "tls_terminated_tcp") and path != "/":
        module.fail_json(msg="path can only be set for http and https listeners")
    if tun and not service:
        module.fail_json(msg="tun is only supported when service is set")


def _serve_args(module: AnsibleModule, disable: bool = False) -> list[str]:
    protocol = module.params["protocol"]
    port = module.params["port"]
    service = module.params.get("service")
    path = module.params["path"]
    target = module.params.get("target")
    background = module.params["background"]
    accept_app_caps = module.params["accept_app_caps"]
    proxy_protocol = module.params.get("proxy_protocol")
    tun = module.params["tun"]

    args = ["serve", f"{PROTOCOL_FLAGS[protocol]}={port}", "--yes"]
    if background and not disable:
        args.append("--bg")
    if service:
        args.append(f"--service={service}")
    if path != "/":
        args.append(f"--set-path={path}")
    if accept_app_caps:
        args.append(f"--accept-app-caps={','.join(accept_app_caps)}")
    if proxy_protocol is not None:
        args.append(f"--proxy-protocol={proxy_protocol}")
    if tun:
        args.append("--tun")
    if disable:
        args.append("off")
    elif target:
        args.append(target)
    return args


def _status(client: TailscaleCliClient) -> dict[str, Any]:
    data = client.run_json(["serve", "status", "--json"])
    if not isinstance(data, dict):
        raise TailscaleError("Unexpected response from tailscale serve status --json")
    return data


def _service_status(status: dict[str, Any], service: Optional[str]) -> dict[str, Any]:
    if service:
        services = status.get("Services")
        if isinstance(services, dict):
            value = services.get(service)
            if isinstance(value, dict):
                return value
        return {}
    return status


def _target_candidates(target: Optional[str]) -> set[str]:
    if not target:
        return set()
    candidates = {target}
    if target.isdigit():
        candidates.add(f"http://127.0.0.1:{target}")
        candidates.add(f"http://localhost:{target}")
    if target.startswith("localhost:"):
        candidates.add(f"http://{target}")
    if target.startswith("127.0.0.1:"):
        candidates.add(f"http://{target}")
    return candidates


def _handler_matches(handler: Any, target_candidates: set[str]) -> bool:
    if not target_candidates:
        return True
    if not isinstance(handler, dict):
        return False
    for key in ("Proxy", "Path", "Text", "TCPForward", "TCP", "Target"):
        value = handler.get(key)
        if isinstance(value, str) and value in target_candidates:
            return True
    return False


def _is_configured(status: dict[str, Any], module: AnsibleModule) -> bool:
    service_status = _service_status(status, module.params.get("service"))
    port = str(module.params["port"])
    protocol = module.params["protocol"]
    protocol_key = PROTOCOL_KEYS[protocol]
    path = module.params["path"]
    target_candidates = _target_candidates(module.params.get("target"))

    tcp = service_status.get("TCP")
    if not isinstance(tcp, dict) or port not in tcp:
        return False

    port_config = tcp.get(port)
    if isinstance(port_config, dict) and protocol_key not in port_config:
        return False

    if protocol in ("tcp", "tls_terminated_tcp"):
        return True

    web = service_status.get("Web")
    if not isinstance(web, dict):
        return False
    for web_config in web.values():
        if not isinstance(web_config, dict):
            continue
        handlers = web_config.get("Handlers")
        if not isinstance(handlers, dict):
            continue
        handler = handlers.get(path)
        if _handler_matches(handler, target_candidates):
            return True
    return False


def main() -> None:
    argument_spec = dict(
        state=dict(type="str", choices=["present", "absent"], default="present"),
        target=dict(type="str"),
        service=dict(type="str"),
        protocol=dict(type="str", choices=["https", "http", "tcp", "tls_terminated_tcp"], default="https"),
        port=dict(type="int", default=443),
        path=dict(type="str", default="/"),
        background=dict(type="bool", default=True),
        accept_app_caps=dict(type="list", elements="str", default=[]),
        proxy_protocol=dict(type="int", choices=[1, 2]),
        tun=dict(type="bool", default=False),
    )
    argument_spec.update(tailscale_cli_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=tailscale_cli_required_together(),
        required_if=tailscale_cli_required_if(),
        mutually_exclusive=tailscale_cli_mutually_exclusive(),
    )

    _validate_params(module)

    client = TailscaleCliClient(module)
    try:
        status = _status(client)
        configured = _is_configured(status, module)
    except TailscaleError as exc:
        module.fail_json(msg=str(exc))

    state = module.params["state"]
    desired = state == "present"
    result: dict[str, Any] = {
        "changed": configured != desired,
        "configured": configured,
        "status": status,
    }

    if configured == desired:
        module.exit_json(**result)
    if module.check_mode:
        result["configured"] = desired
        module.exit_json(**result)

    args = _serve_args(module, disable=not desired)
    try:
        client.run(args, check_rc=True)
        status = _status(client)
    except TailscaleError as exc:
        module.fail_json(msg=str(exc))

    result["status"] = status
    result["configured"] = _is_configured(status, module)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
