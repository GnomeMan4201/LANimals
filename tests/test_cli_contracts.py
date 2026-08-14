from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.nexus_scope import ScopeError
from core.validate_scope_cli import validate_target


BIN = ROOT / "bin"


class CliContractTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as home:
            env = os.environ.copy()
            env.update({"HOME": home, "TERM": "dumb"})
            return subprocess.run(
                [str(BIN / "lanimals"), *args],
                cwd=home,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_dispatcher_version_comes_from_version_file(self) -> None:
        expected = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        for option in ("version", "--version", "-V"):
            with self.subTest(option=option):
                result = self.run_cli(option)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"Version {expected}", result.stdout)

    def test_dispatcher_targets_exist_and_are_executable(self) -> None:
        targets = {
            "lanimals_dashboard",
            "lanimals_recon",
            "lanimals_alert",
            "lanimals_traffic",
            "lanimals_netmap",
            "lanimals_viznet",
            "lanimals_fortress",
            "lanimals_sysinfo",
            "lanimals_hunter",
            "lanimals_vulscan",
        }
        for target in targets:
            with self.subTest(target=target):
                path = BIN / target
                self.assertTrue(path.is_file(), f"missing dispatcher target: {target}")
                self.assertTrue(os.access(path, os.X_OK), f"target is not executable: {target}")

    def test_unknown_command_fails_instead_of_showing_help_as_success(self) -> None:
        result = self.run_cli("definitely-not-a-command")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Unknown LANimals command", result.stderr)

    def test_python_wrappers_resolve_modules_outside_checkout(self) -> None:
        wrappers = {
            "lanimals_anomalydetector": "modules/anomalydetector.py",
            "lanimals_asciiroll": "modules/asciiroll.py",
            "lanimals_darkwebhost": "modules/darkwebhost.py",
            "lanimals_ghostscan": "modules/ghostscan.py",
            "lanimals_hunter": "modules/arp_hunter.py",
            "lanimals_lootlog": "modules/loot_log.py",
            "lanimals_lootsummary": "modules/lootsummary.py",
            "lanimals_roguescan": "modules/roguescan.py",
            "lanimals_sessionlogger": "modules/sessionlogger.py",
            "lanimals_sysinfo": "modules/sysinfo.py",
            "lanimals_threatenrich": "modules/threatenrich.py",
            "lanimals_traffic": "modules/traffic_tap.py",
            "lanimals_tripwire": "modules/tripwire_monitor.py",
            "lanimals_wlanbeacon": "modules/wlanbeacon.py",
        }
        with tempfile.TemporaryDirectory() as tempdir:
            temp = Path(tempdir)
            fake_python = temp / "python3"
            fake_python.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
            fake_python.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{temp}:{env['PATH']}"
            for wrapper, module in wrappers.items():
                with self.subTest(wrapper=wrapper):
                    result = subprocess.run(
                        [str(BIN / wrapper), "contract-argument"],
                        cwd=temp,
                        env=env,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        result.stdout.splitlines(),
                        [str(ROOT / module), "contract-argument"],
                    )

    def test_checkout_is_not_misrepresented_as_a_python_package(self) -> None:
        self.assertFalse((ROOT / "setup.py").exists())
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("checkout-first", readme)

    def test_dispatcher_exposes_appliance_lifecycle(self) -> None:
        result = self.run_cli("help")
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in ("start", "stop", "status", "open", "setup", "doctor"):
            with self.subTest(command=command):
                self.assertIn(command, result.stdout)

    def test_malformed_self_gitlink_is_absent(self) -> None:
        result = subprocess.run(
            ["git", "ls-files", "--stage", "LANimals"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout, "")

    def test_cli_target_validator_reuses_operator_scope(self) -> None:
        with patch.dict(
            os.environ,
            {
                "LANIMALS_ALLOWED_CIDRS": "192.168.50.0/24",
                "LANIMALS_MAX_SCAN_ADDRESSES": "256",
            },
            clear=False,
        ):
            self.assertEqual(validate_target("192.168.50.9"), "192.168.50.9")
            self.assertEqual(validate_target("192.168.50.0/24"), "192.168.50.0/24")
            for target in ("example.com", "8.8.8.8", "192.168.51.0/24"):
                with self.subTest(target=target), self.assertRaises(ScopeError):
                    validate_target(target)

    def test_targeted_shell_scanners_call_scope_validator(self) -> None:
        for script in ("lanimals_netmap", "lanimals_vulscan"):
            with self.subTest(script=script):
                source = (BIN / script).read_text(encoding="utf-8")
                self.assertIn("core.validate_scope_cli", source)
                self.assertIn("Refusing target outside the approved LAN scope", source)

    def test_installer_isolated_runtime_and_fail_closed_linking(self) -> None:
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('python3 -m venv "$ROOT/.venv"', source)
        self.assertIn("Refusing to replace existing file", source)
        self.assertNotIn("curl |", source)
        self.assertNotIn("wget |", source)


if __name__ == "__main__":
    unittest.main()
