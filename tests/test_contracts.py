from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import nexus_builder, nexus_collectors, nexus_db, nexus_scope, nexus_state
from core.nexus_scope import ScopeError
from core.nexus_terminal import TerminalCommandError, parse_terminal_command


class TemporaryDatabaseTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "lanimals.db"
        self.db_patch = patch.object(nexus_db, "DB_PATH", self.db_path)
        self.db_patch.start()
        nexus_db.init_db()

    def tearDown(self) -> None:
        self.db_patch.stop()
        self.tempdir.cleanup()


class BaselineContractTests(TemporaryDatabaseTestCase):
    def test_baseline_requires_explicit_accept_and_defer_is_fail_closed(self) -> None:
        ip = "192.168.50.10"
        nexus_db.upsert_host({
            "ip": ip,
            "mac": "AA:BB:CC:DD:EE:01",
            "hostname": "workstation",
        })

        pending = nexus_db.get_pending_baseline_changes()
        self.assertEqual([(item["ip"], item["status"]) for item in pending], [(ip, "new")])
        self.assertEqual(pending[0]["observed_mac"], "AA:BB:CC:DD:EE:01")

        deferred = nexus_db.defer_baseline_observation(ip, "investigate first")
        self.assertEqual(deferred["action"], "defer")
        self.assertEqual(nexus_db.get_mac_baseline(), {})
        self.assertEqual(nexus_db.get_pending_baseline_changes()[0]["ip"], ip)

        accepted = nexus_db.accept_baseline_observation(ip, "known device")
        self.assertEqual(accepted["action"], "accept")
        self.assertEqual(
            nexus_db.get_mac_baseline()[ip]["mac"],
            "AA:BB:CC:DD:EE:01",
        )
        self.assertEqual(nexus_db.get_pending_baseline_changes(), [])

        nexus_db.upsert_host({
            "ip": ip,
            "mac": "AA:BB:CC:DD:EE:02",
            "hostname": "workstation",
        })
        changed = nexus_db.get_pending_baseline_changes()
        self.assertEqual(changed[0]["status"], "changed")
        self.assertEqual(changed[0]["baseline_mac"], "AA:BB:CC:DD:EE:01")

        actions = [item["action"] for item in nexus_db.get_baseline_decisions()]
        self.assertEqual(actions, ["accept", "defer"])

    def test_rogue_scan_does_not_auto_accept_observations(self) -> None:
        observed = {
            "ip": "192.168.50.12",
            "mac": "AA:BB:CC:DD:EE:12",
            "hostname": "unknown",
        }
        with (
            patch.object(nexus_collectors, "collect_arp_neighbors", return_value=[observed]),
            patch.object(nexus_collectors, "collect_nmap_ping_sweep", return_value=[]),
        ):
            result = nexus_collectors.collect_rogue_scan("192.168.50.0/24")

        self.assertEqual(result["rogues"][0]["ip"], observed["ip"])
        self.assertEqual(nexus_db.get_mac_baseline(), {})


class SnapshotContractTests(unittest.TestCase):
    def test_snapshot_state_is_separate_and_shape_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            snapshot = Path(tempdir) / "network_snapshot.json"
            legacy = Path(tempdir) / "nexus_state.json"
            with (
                patch.object(nexus_state, "SNAPSHOT_STATE_FILE", snapshot),
                patch.object(nexus_state, "LEGACY_STATE_FILE", legacy),
            ):
                nexus_state.save_snapshot_state({
                    "hosts": {"192.168.50.10": {"status": "normal"}},
                    "saved_at": "2026-08-14T00:00:00Z",
                    "baseline": {"must": "not leak"},
                })
                loaded = nexus_state.load_snapshot_state()

            self.assertEqual(set(loaded), {"hosts", "saved_at"})
            self.assertNotIn("baseline", json.loads(snapshot.read_text()))

    def test_operational_graph_does_not_invent_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            with (
                patch.dict(os.environ, {"LANIMALS_DEMO_MODE": "0"}, clear=False),
                patch.object(nexus_builder, "_latest_reports", return_value=[]),
                patch.object(nexus_builder, "_load_discovery_cache", return_value={}),
                patch.object(nexus_builder, "_merge_cached_services"),
                patch.object(nexus_collectors, "collect_arp_neighbors", return_value=[]),
                patch.object(nexus_collectors, "collect_local_interfaces", return_value=[]),
                patch("core.nexus_traps.get_all_traps", return_value=[]),
                patch.object(
                    nexus_state,
                    "SNAPSHOT_STATE_FILE",
                    Path(tempdir) / "network_snapshot.json",
                ),
                patch.object(
                    nexus_state,
                    "LEGACY_STATE_FILE",
                    Path(tempdir) / "legacy.json",
                ),
            ):
                snapshot = nexus_builder.build_snapshot()

        self.assertEqual(snapshot.nodes, [])
        self.assertEqual(snapshot.stats["hosts"], 0)
        self.assertTrue(any(event.title == "No Observations Yet" for event in snapshot.events))


class ScopeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = patch.dict(os.environ, {
            "LANIMALS_ALLOWED_CIDRS": "192.168.50.0/24",
            "LANIMALS_MAX_SCAN_ADDRESSES": "256",
        }, clear=False)
        self.env.start()

    def tearDown(self) -> None:
        self.env.stop()

    def test_scope_allows_only_configured_private_targets(self) -> None:
        self.assertEqual(nexus_scope.validate_scan_cidr("192.168.50.0/24"), "192.168.50.0/24")
        self.assertEqual(nexus_scope.validate_host_target("192.168.50.9"), "192.168.50.9")
        for target in ("192.168.51.0/24", "8.8.8.0/24", "192.168.0.0/16"):
            with self.subTest(target=target), self.assertRaises(ScopeError):
                nexus_scope.validate_scan_cidr(target)
        for target in ("192.168.50.0", "192.168.50.255", "192.168.51.9", "8.8.8.8"):
            with self.subTest(target=target), self.assertRaises(ScopeError):
                nexus_scope.validate_host_target(target)


class TerminalContractTests(unittest.TestCase):
    def test_allowlisted_parser(self) -> None:
        self.assertEqual(parse_terminal_command("lanimals status").action, "status")
        parsed = parse_terminal_command("scan services 192.168.50.9")
        self.assertEqual((parsed.action, parsed.target), ("scan:services", "192.168.50.9"))
        for raw in ("bash", "cat /etc/passwd", "status; id", "scan arp 192.168.50.9"):
            with self.subTest(raw=raw), self.assertRaises(TerminalCommandError):
                parse_terminal_command(raw)

    def test_api_has_one_bridge_and_no_pty_shell(self) -> None:
        source = (Path(__file__).parents[1] / "core" / "nexus_api.py").read_text()
        self.assertEqual(source.count('@app.websocket("/ws/terminal")'), 1)
        self.assertEqual(source.count('@app.get("/api/audit")'), 1)
        self.assertNotIn("ptyprocess", source)
        self.assertNotIn("PtyProcess", source)
        self.assertIn("x-lanimals-operator", source)
        self.assertIn("cross-origin terminal connection refused", source)

    def test_launcher_is_loopback_by_default(self) -> None:
        root = Path(__file__).parents[1]
        source = (root / "lan.sh").read_text()
        self.assertIn('HOST="${LANIMALS_HOST:-127.0.0.1}"', source)
        self.assertNotIn("--host 0.0.0.0", source)
        compatibility = (root / "launch_live_map.sh").read_text()
        self.assertNotIn("0.0.0.0", compatibility)
        self.assertIn('exec bash "$ROOT/lan.sh"', compatibility)


if __name__ == "__main__":
    unittest.main()
