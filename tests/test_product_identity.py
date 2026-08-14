from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "lanimals"


class ProductIdentityTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as home:
            env = os.environ.copy()
            env.update({"HOME": home, "TERM": "dumb"})
            return subprocess.run(
                [str(BIN), *args],
                cwd=home,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_help_uses_canonical_product_identity(self) -> None:
        result = self.run_cli("help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("LANimals Command Center", result.stdout)
        self.assertIn("Local Network Intelligence Platform", result.stdout)
        self.assertNotIn("LANimals Nexus Command Center", result.stdout)

    def test_help_separates_supported_and_legacy_surfaces(self) -> None:
        result = self.run_cli("help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SUPPORTED APPLIANCE COMMANDS", result.stdout)
        self.assertIn("EXPERIMENTAL / LEGACY RESEARCH TOOLS", result.stdout)

    def test_version_uses_current_product_description(self) -> None:
        result = self.run_cli("version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Local Network Intelligence Platform", result.stdout)
        self.assertNotIn("Network Security Toolkit", result.stdout)

    def test_readme_points_to_machine_readable_contract(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("capabilities.json", readme)
        self.assertIn("experimental_legacy", readme)
        self.assertIn("hosted browser cannot directly inspect", readme)


if __name__ == "__main__":
    unittest.main()
