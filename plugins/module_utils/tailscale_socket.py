# Copyright (c) 2025, zupersero
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from typing import Any, TYPE_CHECKING
import json
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, open_url

if TYPE_CHECKING:
    from .tailscale import TailscaleError
else:
    from ansible_collections.zupersero.tailscale.plugins.module_utils.tailscale import TailscaleError


TAILSCALE_SOCKET_DEFAULT_PATH = "/run/tailscale/tailscaled.sock"
TAILSCALE_SOCKET_BASE_URL = "http://local-tailscaled.sock"


def tailscale_socket_argument_spec() -> dict[str, dict[str, Any]]:
    """Argument spec for talking to the local tailscaled socket."""
    return dict(
        socket_path=dict(type="str", default=TAILSCALE_SOCKET_DEFAULT_PATH),
        timeout=dict(type="int", default=30),
    )


def tailscale_socket_required_together() -> list[list[str]]:
    return []


def tailscale_socket_required_if() -> list[list[str]]:
    return []


def tailscale_socket_mutually_exclusive() -> list[list[str]]:
    return []


class TailscaleSocketClient:
    """Client for talking to the local tailscaled HTTP API over a unix socket."""

    def __init__(self, module: AnsibleModule | None = None, **options: Any) -> None:
        self.module = module
        params = getattr(module, "params", {}) if module else {}

        self.socket_path = options.get("socket_path") or params.get("socket_path") or TAILSCALE_SOCKET_DEFAULT_PATH
        self.timeout = int(options.get("timeout") or params.get("timeout") or 30)

    def _build_url(self, path: str, params: dict | None = None) -> str:
        if not path.startswith("/"):
            raise TailscaleError("path must start with '/' for tailscaled socket requests")
        url = f"{TAILSCALE_SOCKET_BASE_URL}{path}"
        if params:
            url = f"{url}?{urlencode(params, doseq=True)}"
        return url

    def _parse_response(self, response_bytes: bytes | str | None) -> dict | list | str | None:
        if not response_bytes:
            return None
        if isinstance(response_bytes, bytes):
            response_text = response_bytes.decode("utf-8", errors="replace")
        else:
            response_text = response_bytes
        try:
            return json.loads(response_text)
        except (ValueError, json.JSONDecodeError):
            return response_text

    def request(
        self,
        path: str,
        method: str = "GET",
        params: dict | None = None,
        data: dict | None = None,
        headers: dict | None = None,
    ) -> tuple[int, dict | list | str | None]:
        url = self._build_url(path, params)
        payload = json.dumps(data).encode("utf-8") if data is not None else None

        request_headers = {"Accept": "application/json"}
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)

        if self.module:
            resp, info = fetch_url(
                self.module,
                url,
                data=payload,
                headers=request_headers,
                method=method,
                timeout=self.timeout,
                unix_socket=self.socket_path,
            )
            status_code = info.get("status", 0)
            response_bytes = resp.read() if resp else b""
        else:
            try:
                resp = open_url(
                    url,
                    data=payload,
                    headers=request_headers,
                    method=method,
                    timeout=self.timeout,
                    unix_socket=self.socket_path,
                )
                status_code = resp.getcode()
                response_bytes = resp.read() if resp else b""
            except HTTPError as e:
                status_code = e.code
                response_bytes = e.read() if e.fp else b""
            except URLError as e:
                raise TailscaleError(f"Socket connection error: {e}")

        response_data = self._parse_response(response_bytes)

        if 200 <= status_code < 300:
            return status_code, response_data

        error_detail = response_data
        if isinstance(response_data, dict):
            error_detail = response_data.get("message") or response_data
        raise TailscaleError(f"tailscaled socket request failed (HTTP {status_code}): {error_detail}")

    def get_json(self, path: str, params: dict | None = None) -> dict | list:
        status_code, data = self.request(path, method="GET", params=params)
        if isinstance(data, (dict, list)):
            return data
        raise TailscaleError(f"Expected JSON response from tailscaled socket (HTTP {status_code})")

    def status(self) -> dict:
        data = self.get_json("/localapi/v0/status")
        if not isinstance(data, dict):
            raise TailscaleError("Unexpected status response type from tailscaled socket")
        return data
