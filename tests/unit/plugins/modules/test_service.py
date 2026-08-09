from __future__ import annotations

import unittest

from ansible_collections.zupersero.tailscale.plugins.modules import service


class FakeModule:
    def fail_json(self, **kwargs):
        raise AssertionError(kwargs["msg"])


class ServiceModuleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = FakeModule()

    def test_service_matches_ignores_ports_and_tags_order(self) -> None:
        current = {
            "name": "svc:web",
            "ports": [443, 80],
            "tags": ["tag:prod", "tag:web"],
            "comment": "Production web",
            "addrs": ["100.64.0.1"],
        }
        desired = {
            "name": "svc:web",
            "ports": [80, 443],
            "tags": ["tag:web", "tag:prod"],
            "comment": "Production web",
        }

        self.assertTrue(service._service_matches(current, desired))

    def test_service_does_not_match_changed_comment(self) -> None:
        current = {
            "name": "svc:web",
            "ports": [80],
            "tags": ["tag:web"],
            "comment": "old",
        }
        desired = {
            "name": "svc:web",
            "ports": [80],
            "tags": ["tag:web"],
            "comment": "new",
        }

        self.assertFalse(service._service_matches(current, desired))

    def test_service_name_requires_svc_prefix(self) -> None:
        with self.assertRaisesRegex(AssertionError, "prefixed with 'svc:'"):
            service._validate_service_name(self.module, "web")

    def test_tags_require_tag_prefix(self) -> None:
        with self.assertRaisesRegex(AssertionError, "prefixed with 'tag:'"):
            service._validate_tags(self.module, ["prod"])

    def test_ports_required_when_present(self) -> None:
        with self.assertRaisesRegex(AssertionError, "ports is required"):
            service._validate_ports(self.module, None, "present")

    def test_ports_must_be_valid_range(self) -> None:
        with self.assertRaisesRegex(AssertionError, "between 1 and 65535"):
            service._validate_ports(self.module, [0], "present")


if __name__ == "__main__":
    unittest.main()
