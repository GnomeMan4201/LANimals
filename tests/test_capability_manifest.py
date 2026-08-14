from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.nexus_api import app
from core.nexus_terminal import scan_commands, simple_commands
from core.version import VERSION


class CapabilityManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(
            (ROOT / "capabilities.json").read_text(encoding="utf-8")
        )

    def test_manifest_version_and_hosted_boundary(self) -> None:
        self.assertEqual(self.manifest["version"], VERSION)
        hosted = self.manifest["surfaces"]["hosted_site"]
        self.assertFalse(hosted["network_access"])
        self.assertEqual(hosted["mode"], "representative_workflow")
        self.assertEqual(hosted["state"], "in_memory_page_session")

    def test_operator_command_contract_matches_parser(self) -> None:
        bridge = self.manifest["operator_bridge"]
        self.assertEqual(set(bridge["simple_commands"]), simple_commands())
        self.assertEqual(set(bridge["scan_commands"]), scan_commands())
        self.assertFalse(bridge["system_shell"])

    def test_capabilities_have_known_status_unique_ids_and_real_evidence(self) -> None:
        allowed = set(self.manifest["status_definitions"])
        capabilities = self.manifest["capabilities"]
        ids = [item["id"] for item in capabilities]
        self.assertEqual(len(ids), len(set(ids)))
        for item in capabilities:
            with self.subTest(capability=item["id"]):
                self.assertIn(item["status"], allowed)
                self.assertTrue(item["evidence"])
                for evidence in item["evidence"]:
                    self.assertTrue((ROOT / evidence).exists(), evidence)

    def test_manifest_routes_exist_in_fastapi(self) -> None:
        actual = {route.path for route in app.routes}
        declared = {
            route
            for item in self.manifest["capabilities"]
            for route in item["routes"]
        }
        self.assertEqual(declared - actual, set())


if __name__ == "__main__":
    unittest.main()
