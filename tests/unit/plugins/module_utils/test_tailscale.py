from __future__ import annotations

import unittest
from unittest.mock import patch

from ansible_collections.zupersero.tailscale.plugins.module_utils import tailscale


class FakeModule:
    params = {
        "url": "https://api.example.test",
        "api_key": "tskey-api-test",
        "tailnet": "tailnet-test",
        "validate_certs": True,
        "timeout": 30,
        "retries": 1,
        "retry_pause": 1,
    }

    def fail_json(self, **kwargs):
        raise AssertionError(kwargs["msg"])


class FakeResponse:
    def read(self):
        return b'{"ok": true}'


class TailscaleClientTest(unittest.TestCase):
    def test_fetch_url_call_uses_supported_keywords(self) -> None:
        client = tailscale.TailscaleClient(FakeModule())

        with patch.object(tailscale, "fetch_url", return_value=(FakeResponse(), {"status": 200})) as fetch_url:
            status, data = client._send_request_impl("/tailnet/tailnet-test/services")

        self.assertEqual(status, 200)
        self.assertEqual(data, {"ok": True})
        self.assertNotIn("validate_certs", fetch_url.call_args.kwargs)

    def test_fetch_url_error_body_is_preserved(self) -> None:
        client = tailscale.TailscaleClient(FakeModule())

        with patch.object(
            tailscale,
            "fetch_url",
            return_value=(None, {"status": 400, "body": b'{"message": "invalid service"}'}),
        ):
            status, data = client._send_request_impl("/tailnet/tailnet-test/services/svc:web")

        self.assertEqual(status, 400)
        self.assertEqual(data, {"error": "invalid service", "status": 400})

    def test_fetch_url_error_msg_is_preserved_when_body_missing(self) -> None:
        client = tailscale.TailscaleClient(FakeModule())

        with patch.object(
            tailscale,
            "fetch_url",
            return_value=(None, {"status": 403, "msg": "forbidden"}),
        ):
            status, data = client._send_request_impl("/tailnet/tailnet-test/services/svc:web")

        self.assertEqual(status, 403)
        self.assertEqual(data, {"error": "forbidden", "status": 403})

    def test_fetch_url_empty_error_includes_status_method_and_path(self) -> None:
        client = tailscale.TailscaleClient(FakeModule())

        with patch.object(
            tailscale,
            "fetch_url",
            return_value=(None, {"status": 400}),
        ):
            status, data = client._send_request_impl("/tailnet/tailnet-test/services/svc:web", method="PUT")

        self.assertEqual(status, 400)
        self.assertEqual(data, {"error": "Client error (HTTP 400 during PUT /tailnet/tailnet-test/services/svc:web)", "status": 400})

    def test_fetch_url_generic_client_error_includes_status_method_and_path(self) -> None:
        client = tailscale.TailscaleClient(FakeModule())

        with patch.object(
            tailscale,
            "fetch_url",
            return_value=(None, {"status": 400, "body": b'{"message": "Client error"}'}),
        ):
            status, data = client._send_request_impl("/tailnet/tailnet-test/services/svc:web", method="PUT")

        self.assertEqual(status, 400)
        self.assertEqual(data, {"error": "Client error (HTTP 400 during PUT /tailnet/tailnet-test/services/svc:web)", "status": 400})


if __name__ == "__main__":
    unittest.main()
