from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["LANIMALS_ALLOWED_CIDRS"] = "192.168.50.0/24"
os.environ["LANIMALS_MAX_SCAN_ADDRESSES"] = "256"

from fastapi.testclient import TestClient

from core import nexus_api, nexus_builder, nexus_db, nexus_state, nexus_traps, personality_engine
from core.nexus_api import app
from core.nexus_risk import rescore_all_hosts


class StateEvidenceIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.patchers = [
            patch.object(nexus_db, "DB_PATH", self.root / "lanimals.db"),
            patch.object(personality_engine, "DB_PATH", self.root / "lanimals.db"),
            patch.object(nexus_state, "SNAPSHOT_STATE_FILE", self.root / "network_snapshot.json"),
            patch.object(nexus_state, "LEGACY_STATE_FILE", self.root / "legacy_snapshot.json"),
            patch.object(nexus_builder, "DISCOVERY_CACHE", self.root / "discovery_cache.json"),
            patch.object(nexus_builder, "REPORTS_DIR", self.root / "reports"),
            patch.object(nexus_traps, "TRAPS_FILE", self.root / "traps.json"),
        ]
        for patcher in self.patchers:
            patcher.start()
        nexus_traps._ACTIVE_TRAPS.clear()
        if hasattr(nexus_traps, "_TRAPS_LOADED"):
            nexus_traps._TRAPS_LOADED = False
        nexus_db.init_db()

    def tearDown(self) -> None:
        nexus_traps._ACTIVE_TRAPS.clear()
        if hasattr(nexus_traps, "_TRAPS_LOADED"):
            nexus_traps._TRAPS_LOADED = False
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.tempdir.cleanup()

    def test_read_only_graph_routes_never_collect_or_advance_snapshot(self) -> None:
        state_path = nexus_state.SNAPSHOT_STATE_FILE
        self.assertFalse(state_path.exists())
        with (
            patch("core.nexus_collectors.collect_arp_neighbors", side_effect=AssertionError("GET collected ARP")),
            patch("core.nexus_collectors.collect_local_interfaces", side_effect=AssertionError("GET collected interfaces")),
        ):
            self.assertEqual(self.client.get("/api/graph").status_code, 200)
            self.assertEqual(self.client.get("/api/stats").status_code, 200)
            self.assertEqual(self.client.get("/api/logs").status_code, 200)
        self.assertFalse(state_path.exists(), "read-only endpoints advanced observation state")

    def test_graph_hydrates_authoritative_db_risk_meta_and_services(self) -> None:
        nexus_builder.DISCOVERY_CACHE.write_text(json.dumps({
            "arp_neighbors": [{
                "ip": "192.168.50.10",
                "mac": "AA:BB:CC:DD:EE:10",
                "hostname": "sensor-10",
                "state": "REACHABLE",
                "source": "ip-neigh",
            }],
            "local_interfaces": [],
            "nmap_hosts": [],
            "cidr": "192.168.50.0/24",
        }))
        nexus_db.upsert_host({
            "ip": "192.168.50.10",
            "mac": "AA:BB:CC:DD:EE:10",
            "hostname": "sensor-10",
            "vendor": "Example Vendor",
            "status": "critical",
            "risk_score": 91,
            "group_cidr": "192.168.50.0/24",
            "meta": {
                "risk_reasons": ["durable reason"],
                "honeypot_hits": 2,
                "evidence_tag": "db-authority",
            },
        })
        nexus_db.upsert_services([{
            "ip": "192.168.50.10",
            "port": "445",
            "protocol": "tcp",
            "service_name": "microsoft-ds",
            "product": "Samba",
            "version": "4",
            "source": "nmap",
        }])

        snapshot = nexus_builder.build_snapshot()
        host = next(node for node in snapshot.nodes if node.id == "host:192.168.50.10")
        self.assertEqual(host.status, "critical")
        self.assertEqual(host.risk_score, 91)
        self.assertEqual(host.meta.get("risk_reasons"), ["durable reason"])
        self.assertEqual(host.meta.get("honeypot_hits"), 2)
        self.assertEqual(host.meta.get("evidence_tag"), "db-authority")
        self.assertEqual(host.meta.get("observation_source"), "ip-neigh")
        self.assertTrue(any(node.id == "service:192.168.50.10:tcp:445" for node in snapshot.nodes))

        db_host = nexus_db.get_host("192.168.50.10")
        self.assertEqual(host.risk_score, db_host["risk_score"])
        self.assertEqual(host.status, db_host["status"])

    def test_meta_round_trip_and_repeated_rescore_preserve_evidence(self) -> None:
        cves = [
            {"cve": "CVE-2026-0001", "score": "9.8", "port": "445"},
            {"cve": "CVE-2026-0002", "score": "5.0", "port": "445"},
        ]
        nexus_db.upsert_host({
            "ip": "192.168.50.20",
            "mac": "AA:BB:CC:DD:EE:20",
            "hostname": "host-20",
            "meta": {
                "cve_count": 2,
                "cves": cves,
                "honeypot_hits": 3,
                "risk_reasons": ["original reason"],
                "evidence_tag": "round-trip",
            },
        })

        for _ in range(2):
            rescore_all_hosts()

        row = nexus_db.get_host("192.168.50.20")
        meta = json.loads(row["meta"])
        self.assertNotIn("meta", meta, "metadata recursively nested")
        self.assertEqual(meta.get("cve_count"), 2)
        self.assertEqual(meta.get("cves"), cves)
        self.assertEqual(meta.get("honeypot_hits"), 3)
        self.assertEqual(meta.get("evidence_tag"), "round-trip")
        self.assertTrue(meta.get("risk_reasons"))
        self.assertGreaterEqual(row["risk_score"], 65)

    def test_diff_compares_explicit_observation_snapshots_and_reads_do_not_move_it(self) -> None:
        first = {
            "hosts": {
                "192.168.50.10": {
                    "ip": "192.168.50.10", "hostname": "alpha",
                    "label": "alpha", "mac": "AA:AA:AA:AA:AA:10",
                    "status": "normal", "risk_score": 10,
                    "group": "192.168.50.0/24", "last_seen": "t1",
                    "observed_at": "2026-08-14T20:00:00Z", "source": "discovery",
                },
                "192.168.50.20": {
                    "ip": "192.168.50.20", "hostname": "gone",
                    "label": "gone", "mac": "AA:AA:AA:AA:AA:20",
                    "status": "normal", "risk_score": 10,
                    "group": "192.168.50.0/24", "last_seen": "t1",
                    "observed_at": "2026-08-14T20:00:00Z", "source": "discovery",
                },
            },
            "saved_at": "2026-08-14T20:00:00Z",
            "source": "discovery",
            "scope": "192.168.50.0/24",
        }
        second = {
            "hosts": {
                "192.168.50.10": {
                    "ip": "192.168.50.10", "hostname": "alpha",
                    "label": "alpha", "mac": "BB:BB:BB:BB:BB:10",
                    "status": "critical", "risk_score": 90,
                    "group": "192.168.50.0/24", "last_seen": "t2",
                    "observed_at": "2026-08-14T21:00:00Z", "source": "discovery",
                },
                "192.168.50.30": {
                    "ip": "192.168.50.30", "hostname": "new",
                    "label": "new", "mac": "AA:AA:AA:AA:AA:30",
                    "status": "normal", "risk_score": 10,
                    "group": "192.168.50.0/24", "last_seen": "t2",
                    "observed_at": "2026-08-14T21:00:00Z", "source": "discovery",
                },
            },
            "saved_at": "2026-08-14T21:00:00Z",
            "source": "discovery",
            "scope": "192.168.50.0/24",
        }
        nexus_state.advance_snapshot_state(first)
        nexus_state.advance_snapshot_state(second)

        response = self.client.get("/api/diff")
        self.assertEqual(response.status_code, 200)
        diff = response.json()
        self.assertTrue(diff.get("comparable"))
        self.assertEqual([item["ip"] for item in diff["appeared"]], ["192.168.50.30"])
        self.assertEqual([item["ip"] for item in diff["disappeared"]], ["192.168.50.20"])
        self.assertEqual([item["ip"] for item in diff["changed"]], ["192.168.50.10"])
        changes = " | ".join(diff["changed"][0]["changes"])
        self.assertIn("MAC:", changes)
        self.assertIn("status:", changes)
        self.assertIn("risk:", changes)

        before = nexus_state.SNAPSHOT_STATE_FILE.read_text()
        self.client.get("/api/graph")
        self.client.get("/api/stats")
        self.client.get("/api/logs")
        self.assertEqual(nexus_state.SNAPSHOT_STATE_FILE.read_text(), before)

    def test_trap_history_restores_without_restarting_listener(self) -> None:
        nexus_traps.TRAPS_FILE.write_text(json.dumps({
            "deadbeef": {
                "id": "deadbeef",
                "type": "http",
                "name": "Historical Admin",
                "port": 8888,
                "banner": "http",
                "status": "active",
                "deployed_at": "2026-08-14T20:00:00Z",
                "hit_count": 1,
                "last_hit": "2026-08-14T20:05:00Z",
                "hits": [{
                    "ts": "2026-08-14T20:05:00Z",
                    "source_ip": "192.168.50.99",
                    "source_port": 50000,
                    "data": "probe",
                    "trap_name": "Historical Admin",
                    "trap_port": 8888,
                }],
                "error": None,
            }
        }))
        nexus_traps._ACTIVE_TRAPS.clear()
        nexus_traps._TRAPS_LOADED = False

        traps = nexus_traps.get_all_traps()
        self.assertEqual(len(traps), 1)
        self.assertEqual(traps[0]["id"], "deadbeef")
        self.assertNotIn(traps[0]["status"], {"active", "starting"})
        self.assertEqual(traps[0]["hit_count"], 1)
        self.assertEqual(len(traps[0]["hits"]), 1)
        self.assertEqual(nexus_traps.get_all_hits()[0]["source_ip"], "192.168.50.99")
        self.assertNotIn("thread", nexus_traps._ACTIVE_TRAPS["deadbeef"])
        self.assertNotIn("stop_event", nexus_traps._ACTIVE_TRAPS["deadbeef"])

    def test_personality_records_reproducible_input_summary(self) -> None:
        personality_engine.init_personality_tables()
        personality, _ = personality_engine.assign_personality(
            "192.168.50.40",
            risk_score=72,
            services=[{"port": "445"}, {"port": "22"}],
            meta={"honeypot_hits": 0, "cve_count": 2},
        )
        self.assertEqual(personality, "parasite")
        record = personality_engine.get_personality("192.168.50.40")
        self.assertTrue(record.get("rule_version"))
        inputs = json.loads(record["input_summary"])
        self.assertEqual(inputs["risk_score"], 72)
        self.assertEqual(inputs["open_ports"], ["22", "445"])
        self.assertEqual(inputs["cve_count"], 2)


if __name__ == "__main__":
    unittest.main()
