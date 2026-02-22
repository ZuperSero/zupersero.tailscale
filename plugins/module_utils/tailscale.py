# Copyright (c) 2025, zupersero
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from typing import Any
import json
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError

from ansible.module_utils.basic import env_fallback
from ansible.module_utils.urls import url_argument_spec, fetch_url, open_url
from ansible.module_utils.api import retry_argument_spec, retry_with_delays_and_condition, generate_jittered_backoff


TAILSCALE_API_DEFAULT_URL = "https://api.tailscale.com/api/v2"


class TailscaleError(Exception):
    """Base exception for Tailscale client errors."""


class TailscaleRetryableError(TailscaleError):
    """Exception raised for errors that should trigger a retry."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def tailscale_argument_spec() -> dict[str, dict[str, Any]]:
    """
    Build the argument specification for Tailscale modules.

    Returns:
        dict[str, dict[str, Any]]: Ansible argument specification dictionary
    """
    argument_spec = url_argument_spec()

    # Delete unused parameters from url_argument_spec
    for key in ("force", "http_agent", "use_proxy"):
        if key in argument_spec:
            del argument_spec[key]
    if "use_gssapi" in argument_spec:
        del argument_spec["use_gssapi"]

    retry_spec = retry_argument_spec()
    retry_spec["retries"]["default"] = 3

    argument_spec.update(retry_spec)
    argument_spec.update(
        url=dict(type="str", required=False, default=TAILSCALE_API_DEFAULT_URL, fallback=(env_fallback, ["TAILSCALE_API_URL"])),
        api_key=dict(type="str", required=False, no_log=True, fallback=(env_fallback, ["TAILSCALE_AUTH_KEY"])),
        tailnet=dict(type="str", required=False, fallback=(env_fallback, ["TAILSCALE_TAILNET_ID"])),
        validate_certs=dict(type="bool", default=True, fallback=(env_fallback, ["TAILSCALE_VALIDATE_CERTS"])),
        timeout=dict(type="int", default=30),
    )
    return argument_spec


def tailscale_required_together() -> list[list[str]]:
    """Define required_together constraints for Tailscale modules."""
    return []


def tailscale_required_if() -> list[list[str]]:
    """Define required_if constraints for Tailscale modules."""
    return []


def tailscale_mutually_exclusive() -> list[list[str]]:
    """Define mutually_exclusive constraints for Tailscale modules."""
    return []


class TailscaleClient:
    """
    Client for interacting with the Tailscale API.

    This client handles authentication, request retries, and response parsing.
    """

    def __init__(self, module: Any | None = None, **options: Any) -> None:
        """
        Initialize the TailscaleClient.

        Args:
            module (Any | None): Ansible module instance, or None for standalone use.
            options (Any): Optional overrides when module is not provided.
        """
        self.module = module
        params = getattr(module, "params", {}) if module else {}

        self.url = options.get("url") or params.get("url") or TAILSCALE_API_DEFAULT_URL
        self.api_key = options.get("api_key") or params.get("api_key")
        self.tailnet = options.get("tailnet") or params.get("tailnet")
        self.validate_certs = options.get("validate_certs")
        if self.validate_certs is None:
            self.validate_certs = params.get("validate_certs", True)
        self.timeout = int(options.get("timeout") or params.get("timeout") or 30)
        self.retries = int(options.get("retries") or params.get("retries") or 3)
        self.retry_pause = int(options.get("retry_pause") or params.get("retry_pause") or 1)

        if not self.api_key:
            self._fail("Tailscale API key is required")
        if not self.tailnet:
            self._fail("Tailscale tailnet ID is required")
        if not self.url:
            self._fail("Tailscale API URL is required")

        backoff_iterator = generate_jittered_backoff(
            retries=self.retries,
            delay_base=self.retry_pause,
            delay_threshold=60,
        )
        self._retry_decorator = retry_with_delays_and_condition(
            backoff_iterator=backoff_iterator,
            should_retry_error=lambda e: isinstance(e, TailscaleRetryableError),
        )

    def _fail(self, message: str) -> None:
        if self.module:
            self.module.fail_json(msg=message)
        raise TailscaleError(message)

    def _build_headers(self, extra_headers: dict | None = None) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

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

    def _send_request_impl(
        self,
        path: str,
        method: str = "GET",
        params: dict | None = None,
        data: dict | None = None,
        extra_headers: dict | None = None,
    ) -> tuple[int, dict | list | str | None]:
        url = f"{self.url.rstrip('/')}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{urlencode(params, doseq=True)}"

        headers = self._build_headers(extra_headers)
        body = json.dumps(data).encode("utf-8") if data is not None else None

        if self.module:
            resp, info = fetch_url(
                self.module,
                url,
                data=body,
                headers=headers,
                method=method,
                timeout=self.timeout,
                validate_certs=self.validate_certs,
            )
            status_code = info.get("status", 0)
            response_bytes = resp.read() if resp else b""
        else:
            try:
                resp = open_url(
                    url,
                    data=body,
                    headers=headers,
                    method=method,
                    timeout=self.timeout,
                    validate_certs=self.validate_certs,
                )
                status_code = resp.getcode()
                response_bytes = resp.read() if resp else b""
            except HTTPError as e:
                status_code = e.code
                response_bytes = e.read() if e.fp else b""
            except URLError as e:
                raise TailscaleRetryableError(f"Connection error: {e}")

        response_data = self._parse_response(response_bytes)

        if 200 <= status_code < 300:
            return status_code, response_data

        if status_code == 429:
            error_msg = "Rate limited by Tailscale API"
            if isinstance(response_data, dict):
                error_msg = response_data.get("message", error_msg)
            raise TailscaleRetryableError(error_msg, status_code)

        if 400 <= status_code < 500:
            if isinstance(response_data, dict):
                error_msg = response_data.get("message") or response_data.get("error") or "Client error"
            else:
                error_msg = str(response_data) if response_data is not None else "Client error"
            return status_code, {"error": error_msg, "status": status_code}

        error_msg = f"HTTP {status_code}: Server error"
        if isinstance(response_data, dict):
            error_msg = response_data.get("message", error_msg)
        raise TailscaleRetryableError(error_msg, status_code)

    def _send_request(
        self,
        path: str,
        method: str = "GET",
        params: dict | None = None,
        data: dict | None = None,
        extra_headers: dict | None = None,
    ) -> tuple[int, dict | list | str | None]:
        retrying_func = self._retry_decorator(self._send_request_impl)
        try:
            return retrying_func(path, method, params, data, extra_headers)
        except TailscaleRetryableError as e:
            self._fail(f"Failed to connect to Tailscale after {self.retries} attempts: {str(e)}")
        return 0, None

    def get(self, path: str, params: dict | None = None, headers: dict | None = None) -> tuple[int, dict | list | str | None]:
        return self._send_request(path, method="GET", params=params, extra_headers=headers)

    def post(
        self,
        path: str,
        data: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> tuple[int, dict | list | str | None]:
        return self._send_request(path, method="POST", params=params, data=data, extra_headers=headers)

    def put(
        self,
        path: str,
        data: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> tuple[int, dict | list | str | None]:
        return self._send_request(path, method="PUT", params=params, data=data, extra_headers=headers)

    def patch(
        self,
        path: str,
        data: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> tuple[int, dict | list | str | None]:
        return self._send_request(path, method="PATCH", params=params, data=data, extra_headers=headers)

    def delete(self, path: str, params: dict | None = None, headers: dict | None = None) -> tuple[int, dict | list | str | None]:
        return self._send_request(path, method="DELETE", params=params, extra_headers=headers)

    def list_devices(
        self,
        fields: str | None = None,
        filters: dict | None = None,
    ) -> tuple[int, dict | list | str | None]:
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filters:
            params.update(filters)
        return self.get(f"/tailnet/{self.tailnet}/devices", params=params)

    def list_services(self) -> tuple[int, dict | list | str | None]:
        return self.get(f"/tailnet/{self.tailnet}/services")

    def list_service_hosts(self, service_name: str) -> tuple[int, dict | list | str | None]:
        return self.get(f"/tailnet/{self.tailnet}/services/{service_name}/devices")
