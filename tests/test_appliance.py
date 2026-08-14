from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import appliance


class ApplianceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.env = patch.dict(
            os.environ,
            {
                "HOME": str(root / "home"),
                "XDG_CONFIG_HOME": str(root / "config"),
                "XDG_DATA_HOME": str(root / "data"),
                "XDG_CACHE_HOME": str(root / "cache"),
                "XDG_STATE_HOME": str(root / "state"),
            },
            clear=False,
        )
        self.env.start()
        for key in (
            "LANIMALS_ALLOWED_CIDRS",
            "LANIMALS_MAX_SCAN_ADDRESSES",
            "LANIMALS_CONFIG_DIR",
            "LANIMALS_DATA_DIR",
            "LANIMALS_CACHE_DIR",
            "LANIMALS_STATE_DIR",
            "LANIMALS_REPORTS_DIR",
            "LANIMALS_HOST",
            "LANIMALS_PORT",
            "LANIMALS_ALLOW_REMOTE",
        ):
            os.environ.pop(key, None)

    def tearDown(self) -> None:
        self.env.stop()
        self.tempdir.cleanup()

    def test_setup_persists_only_an_approved_private_scope(self) -> None:
        self.assertEqual(appliance.setup_scope("192.168.50.0/24"), 0)
        path = appliance.config_path()
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["allowed_cidrs"], ["192.168.50.0/24"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for value in ("8.8.8.0/24", "192.168.0.0/16", "not-a-network"):
            with self.subTest(value=value), self.assertRaises(appliance.ApplianceError):
                appliance.setup_scope(value)

    def test_configuration_schema_and_symlink_fail_closed(self) -> None:
        path = appliance.config_path()
        path.parent.mkdir(parents=True)
        path.write_text('{"schema_version": 999}')
        with self.assertRaises(appliance.ApplianceError):
            appliance.show_config()
        path.unlink()
        target = Path(self.tempdir.name) / "outside.json"
        target.write_text("{}")
        path.symlink_to(target)
        with self.assertRaises(appliance.ApplianceError):
            appliance.setup_scope("192.168.50.0/24")

    def test_start_refuses_to_run_before_scope_approval(self) -> None:
        with patch("core.appliance.subprocess.Popen") as popen:
            with self.assertRaises(appliance.ApplianceError):
                appliance.start(no_browser=True)
        popen.assert_not_called()

    def test_start_uses_loopback_and_xdg_local_state(self) -> None:
        appliance.setup_scope("192.168.50.0/24")
        process = Mock(pid=4123)
        process.poll.return_value = None
        with (
            patch("core.appliance._preflight_runtime"),
            patch("core.appliance._read_pid", return_value=None),
            patch("core.appliance._health", side_effect=[False, True]),
            patch("core.appliance.subprocess.Popen", return_value=process) as popen,
        ):
            self.assertEqual(appliance.start(no_browser=True), 0)
        argv = popen.call_args.args[0]
        environment = popen.call_args.kwargs["env"]
        self.assertEqual(argv[argv.index("--host") + 1], "127.0.0.1")
        self.assertEqual(argv[argv.index("--port") + 1], "8080")
        self.assertEqual(environment["LANIMALS_ALLOWED_CIDRS"], "192.168.50.0/24")
        self.assertTrue(environment["LANIMALS_DATA_DIR"].endswith("/lanimals"))
        self.assertNotIn("/api/scan/arp", " ".join(argv))

    def test_non_loopback_bind_requires_explicit_override(self) -> None:
        with patch.dict(os.environ, {"LANIMALS_HOST": "0.0.0.0"}, clear=False):
            with self.assertRaises(appliance.ApplianceError):
                appliance._host()

    def test_legacy_state_migration_never_overwrites_destination(self) -> None:
        root = Path(self.tempdir.name) / "checkout"
        legacy = root / "tmp"
        legacy.mkdir(parents=True)
        old_db = legacy / "lanimals.db"
        import sqlite3

        connection = sqlite3.connect(old_db)
        connection.execute("CREATE TABLE marker (value TEXT)")
        connection.execute("INSERT INTO marker VALUES ('preserved')")
        connection.commit()
        connection.close()
        (legacy / "network_snapshot.json").write_text('{"hosts": {}}')
        with patch.object(appliance, "ROOT", root):
            migrated = appliance.migrate_legacy_state()
            second = appliance.migrate_legacy_state()
        self.assertEqual(set(migrated), {"lanimals.db", "network_snapshot.json"})
        self.assertEqual(second, [])
        copied = sqlite3.connect(appliance.data_dir() / "lanimals.db")
        self.assertEqual(copied.execute("SELECT value FROM marker").fetchone()[0], "preserved")
        copied.close()

    def test_path_contract_honors_xdg_directories_in_fresh_process(self) -> None:
        environment = os.environ.copy()
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from core.nexus_paths import DATA_DIR, CACHE_DIR; "
                "print(DATA_DIR); print(CACHE_DIR)",
            ],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        lines = result.stdout.splitlines()
        self.assertTrue(lines[0].startswith(os.environ["XDG_DATA_HOME"]))
        self.assertTrue(lines[1].startswith(os.environ["XDG_CACHE_HOME"]))


if __name__ == "__main__":
    unittest.main()
