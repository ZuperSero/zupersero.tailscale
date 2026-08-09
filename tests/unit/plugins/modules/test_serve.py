from __future__ import annotations

import unittest

from ansible_collections.zupersero.tailscale.plugins.modules import serve


class FakeModule:
    def __init__(self, params):
        self.params = params

    def fail_json(self, **kwargs):
        raise AssertionError(kwargs["msg"])


def module_params(**overrides):
    params = {
        "state": "present",
        "target": "3000",
        "service": None,
        "protocol": "https",
        "port": 443,
        "path": "/",
        "background": True,
        "accept_app_caps": [],
        "proxy_protocol": None,
        "tun": False,
    }
    params.update(overrides)
    return params


class ServeModuleTest(unittest.TestCase):
    def test_serve_args_for_background_https(self) -> None:
        module = FakeModule(module_params())

        self.assertEqual(
            serve._serve_args(module),
            ["serve", "--https=443", "--yes", "--bg", "3000"],
        )

    def test_serve_args_for_service_path_and_caps(self) -> None:
        module = FakeModule(
            module_params(
                target="http://127.0.0.1:8080",
                service="svc:web",
                path="/app",
                accept_app_caps=["cap:a", "cap:b"],
            )
        )

        self.assertEqual(
            serve._serve_args(module),
            [
                "serve",
                "--https=443",
                "--yes",
                "--bg",
                "--service=svc:web",
                "--set-path=/app",
                "--accept-app-caps=cap:a,cap:b",
                "http://127.0.0.1:8080",
            ],
        )

    def test_serve_args_for_disable_without_target(self) -> None:
        module = FakeModule(module_params(target=None, state="absent"))

        self.assertEqual(
            serve._serve_args(module, disable=True),
            ["serve", "--https=443", "--yes", "off"],
        )

    def test_status_match_for_node_https_proxy(self) -> None:
        module = FakeModule(module_params())
        status = {
            "TCP": {"443": {"HTTPS": True}},
            "Web": {
                "host.tailnet.ts.net:443": {
                    "Handlers": {
                        "/": {"Proxy": "http://127.0.0.1:3000"},
                    },
                },
            },
        }

        self.assertTrue(serve._is_configured(status, module))

    def test_status_match_for_service_https_proxy(self) -> None:
        module = FakeModule(module_params(service="svc:web", target="http://127.0.0.1:8080"))
        status = {
            "Services": {
                "svc:web": {
                    "TCP": {"443": {"HTTPS": True}},
                    "Web": {
                        "web.tailnet.ts.net:443": {
                            "Handlers": {
                                "/": {"Proxy": "http://127.0.0.1:8080"},
                            },
                        },
                    },
                },
            },
        }

        self.assertTrue(serve._is_configured(status, module))

    def test_service_requires_svc_prefix(self) -> None:
        module = FakeModule(module_params(service="web"))

        with self.assertRaisesRegex(AssertionError, "prefixed with 'svc:'"):
            serve._validate_params(module)

    def test_tun_requires_service(self) -> None:
        module = FakeModule(module_params(tun=True))

        with self.assertRaisesRegex(AssertionError, "tun is only supported"):
            serve._validate_params(module)


if __name__ == "__main__":
    unittest.main()
