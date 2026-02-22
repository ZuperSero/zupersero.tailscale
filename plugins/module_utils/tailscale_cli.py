# Copyright (c) 2025, zupersero
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from typing import Any, Iterable, TYPE_CHECKING
import json


from ansible.module_utils.basic import AnsibleModule
if TYPE_CHECKING:
    from .tailscale import TailscaleError
else:
    from ansible_collections.zupersero.tailscale.plugins.module_utils.tailscale import TailscaleError


TAILSCALE_CLI_DEFAULT_BIN = "tailscale"


def tailscale_cli_argument_spec() -> dict[str, dict[str, Any]]:
    """Argument spec for invoking the local tailscale CLI."""
    return dict(
        tailscale_bin=dict(type="str", default=TAILSCALE_CLI_DEFAULT_BIN),
    )


def tailscale_cli_required_together() -> list[list[str]]:
    return []


def tailscale_cli_required_if() -> list[list[str]]:
    return []


def tailscale_cli_mutually_exclusive() -> list[list[str]]:
    return []


class TailscaleCliClient:
    """Client for running local tailscale CLI commands."""

    def __init__(self, module: AnsibleModule, **options: Any) -> None:
        if module is None:
            raise TailscaleError("TailscaleCliClient requires an AnsibleModule")
        self.module = module
        params = getattr(module, "params", {})

        self.tailscale_bin = options.get("tailscale_bin") or params.get("tailscale_bin") or TAILSCALE_CLI_DEFAULT_BIN

    def _run(self, args: Iterable[str]) -> tuple[int, str, str]:
        cmd = [self.tailscale_bin, *args]
        return self.module.run_command(cmd, check_rc=False)

    def run(self, args: Iterable[str], check_rc: bool = True) -> str:
        rc, out, err = self._run(args)
        if check_rc and rc != 0:
            raise TailscaleError(f"tailscale CLI failed (rc={rc}): {err.strip() or 'unknown error'}")
        return out

    def run_json(self, args: Iterable[str]) -> dict | list:
        output = self.run(args, check_rc=True)
        try:
            return json.loads(output)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise TailscaleError(f"Invalid JSON from tailscale CLI: {exc}")

    def status(self) -> dict:
        return self.run_json(["status", "--json"])
