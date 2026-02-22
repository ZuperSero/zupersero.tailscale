#!/usr/bin/python
# Copyright (c) 2025, zupersero
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r"""
---
module: exit_node
short_description: Advertise this host as a Tailscale exit node
description:
  - Enables or disables advertising this host as an exit node using the local Tailscale CLI.
  - The exit node must still be approved by an admin in the tailnet before it can be used.
options:
  state:
    description:
      - Whether to advertise this host as an exit node.
    type: str
    choices: [present, absent]
    default: present
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
  - IP forwarding must be enabled on the host for exit node traffic to work.
"""

EXAMPLES = r"""
- name: Advertise this host as an exit node
  zupersero.tailscale.exit_node:
    state: present

- name: Stop advertising this host as an exit node
  zupersero.tailscale.exit_node:
    state: absent
"""

RETURN = r"""
changed:
  description: Whether any change was made.
  type: bool
advertised:
  description: Whether the host is advertising itself as an exit node after the module runs.
  type: bool
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


def _current_advertise_exit_node(status: dict[str, Any]) -> Optional[bool]:
    if not isinstance(status, dict):
        return None

    self_info = status.get("Self")
    if isinstance(self_info, dict):
        for key in ("AdvertiseExitNode", "ExitNodeOption", "ExitNode"):
            value = self_info.get(key)
            if isinstance(value, bool):
                return value

    prefs = status.get("Prefs")
    if isinstance(prefs, dict):
        value = prefs.get("AdvertiseExitNode")
        if isinstance(value, bool):
            return value

    return None


def main() -> None:
    argument_spec = tailscale_cli_argument_spec()
    argument_spec.update(
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=tailscale_cli_required_together(),
        required_if=tailscale_cli_required_if(),
        mutually_exclusive=tailscale_cli_mutually_exclusive(),
    )

    state = module.params["state"]
    desired = state == "present"

    client = TailscaleCliClient(module)

    try:
        status = client.status()
    except TailscaleError as exc:
        module.fail_json(msg=str(exc))

    current = _current_advertise_exit_node(status)

    if module.check_mode:
        changed = current is None or current != desired
        result = {"changed": changed}
        if current is not None:
            result["advertised"] = desired if changed else current
        module.exit_json(**result)

    changed = False
    if current is None or current != desired:
        args = ["set", "--advertise-exit-node" if desired else "--advertise-exit-node=false"]
        try:
            client.run(args, check_rc=True)
        except TailscaleError as exc:
            module.fail_json(msg=str(exc))
        changed = True

    advertised: Optional[bool] = None
    try:
        status_after = client.status()
        advertised = _current_advertise_exit_node(status_after)
    except TailscaleError:
        status_after = None

    result = {"changed": changed}
    if advertised is not None:
        result["advertised"] = advertised

    module.exit_json(**result)


if __name__ == "__main__":
    main()
