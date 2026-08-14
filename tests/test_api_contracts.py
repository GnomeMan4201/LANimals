from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["LANIMALS_ALLOWED_CIDRS"] = "192.168.50.0/24"
os.environ["LANIMALS_MAX_SCAN_ADDRESSES"] = "256"

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from core import nexus_db
from core.nexus_api import app


OPERATOR_HEADERS = {"X-LANimals-Operator": "1"}


class ApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(
            nexus_db,
            "DB_PATH",
            Path(self.tempdir.name) / "lanimals.db",
        )
        self.db_patch.start()
        nexus_db.init_db()

    def tearDown(self) -> None:
        self.db_patch.stop()
        self.tempdir.cleanup()

    def test_ui_health_and_scope_are_live(self) -> None:
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertTrue(health.json()["ok"])

        scope = self.client.get("/api/scope")
        self.assertEqual(scope.status_code, 200)
        self.assertEqual(scope.json()["default_cidr"], "192.168.50.0/24")

        ui = self.client.get("/")
        self.assertEqual(ui.status_code, 200)
        self.assertIn("LANimals Operator Command Bridge", ui.text)

    def test_mutations_require_operator_header(self) -> None:
        response = self.client.post(
            "/api/baseline/defer",
            json={"ip": "192.168.50.10", "note": "test"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("X-LANimals-Operator", response.json()["detail"])

    def test_scan_targets_are_rejected_outside_scope(self) -> None:
        response = self.client.post(
            "/api/scan/discovery?cidr=8.8.8.0/24",
            headers=OPERATOR_HEADERS,
        )
        self.assertEqual(response.status_code, 422)
        self.assertIn("RFC1918", response.json()["detail"])

    def test_baseline_defer_then_accept_through_api(self) -> None:
        ip = "192.168.50.10"
        nexus_db.upsert_host({
            "ip": ip,
            "mac": "AA:BB:CC:DD:EE:10",
            "hostname": "operator-test",
        })

        pending = self.client.get("/api/baseline").json()["pending"]
        self.assertEqual(pending[0]["ip"], ip)

        deferred = self.client.post(
            "/api/baseline/defer",
            headers=OPERATOR_HEADERS,
            json={"ip": ip, "note": "investigate"},
        )
        self.assertEqual(deferred.status_code, 200)
        self.assertFalse(deferred.json()["baseline_changed"])
        self.assertEqual(nexus_db.get_mac_baseline(), {})

        accepted = self.client.post(
            "/api/baseline/accept",
            headers=OPERATOR_HEADERS,
            json={"ip": ip, "note": "known device"},
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.json()["decision"]["action"], "accept")
        self.assertEqual(self.client.get("/api/baseline").json()["pending"], [])

    def test_terminal_rejects_shell_commands(self) -> None:
        with self.client.websocket_connect("/ws/terminal") as websocket:
            greeting = websocket.receive_text()
            self.assertIn("not a system shell", greeting)
            websocket.send_text("bash\r")
            output = "".join(websocket.receive_text() for _ in range(7))
        self.assertIn("unsupported command", output)

    def test_terminal_rejects_cross_origin_browser(self) -> None:
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect(
                "/ws/terminal",
                headers={"Origin": "https://attacker.example"},
            ):
                pass


if __name__ == "__main__":
    unittest.main()
