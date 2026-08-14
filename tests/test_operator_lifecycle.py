from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["LANIMALS_ALLOWED_CIDRS"] = "192.168.50.0/24"
os.environ["LANIMALS_MAX_SCAN_ADDRESSES"] = "256"

from fastapi.testclient import TestClient

from core import nexus_db
from core import nexus_api
from core.nexus_api import app


class OperatorLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.db_patch = patch.object(nexus_db, "DB_PATH", root / "lanimals.db")
        self.reports_patch = patch.object(nexus_api, "REPORTS_DIR", root / "reports")
        self.db_patch.start()
        self.reports_patch.start()
        nexus_db.init_db()

    def tearDown(self) -> None:
        self.reports_patch.stop()
        self.db_patch.stop()
        self.tempdir.cleanup()

    def test_report_escapes_untrusted_network_and_event_strings_and_persists(self) -> None:
        nexus_db.upsert_host({
            "ip": "192.168.50.10",
            "hostname": "<script>alert(1)</script>",
            "mac": "AA:BB:CC:DD:EE:10",
            "vendor": 'Bad & <img src=x onerror="alert(2)">',
        })
        nexus_db.insert_events([{
            "id": "evt:xss",
            "ts": "2026-08-14T22:00:00Z",
            "severity": "warning",
            "title": "<script>event()</script>",
            "summary": 'quote=" & <img onerror=boom>',
            "ip": "192.168.50.10",
        }])

        response = self.client.get("/api/export/report")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("<script>alert(1)</script>", response.text)
        self.assertNotIn("<script>event()</script>", response.text)
        self.assertNotIn("<img src=x", response.text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", response.text)
        self.assertIn("Bad &amp; &lt;img", response.text)

        name = response.headers.get("X-LANimals-Report")
        self.assertTrue(name and name.startswith("report_") and name.endswith(".html"))

        listing = self.client.get("/api/reports")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["reports"][0]["name"], name)
        stored = self.client.get(f"/api/reports/{name}")
        self.assertEqual(stored.status_code, 200)
        self.assertEqual(stored.text, response.text)

    def test_report_name_validation_is_fail_closed(self) -> None:
        response = self.client.get("/api/reports/not-a-report.html")
        self.assertEqual(response.status_code, 400)

    def test_unknown_cvss_is_stable_warning(self) -> None:
        self.assertIsNone(nexus_api._parse_cvss("?"))
        self.assertEqual(nexus_api._cve_severity("?"), "warning")
        self.assertEqual(nexus_api._cve_severity("9.8"), "critical")
        self.assertEqual(nexus_api._cve_severity("5.0"), "warning")
        self.assertEqual(nexus_api._cve_severity("2.0"), "info")

    def test_health_uses_canonical_product_identity(self) -> None:
        payload = self.client.get("/api/health").json()
        self.assertEqual(payload["service"], "lanimals")
        self.assertEqual(payload["product"], "LANimals")

    def test_ui_never_starts_collection_on_page_open(self) -> None:
        ui = (Path(__file__).resolve().parents[1] / "ui" / "lanimals_live_map.html").read_text(encoding="utf-8")
        self.assertNotIn("setInterval(()=>apiPost('/api/scan/arp')", ui)
        self.assertNotIn("without service data — scan services`,action:()=>{}", ui)
        self.assertIn("without service data — inspect first host", ui)
        self.assertIn("window.open(r.url", ui)


if __name__ == "__main__":
    unittest.main()


class TrapBundleResultContractTests(unittest.TestCase):
    def test_bundle_counts_status_not_presence_of_error_key(self) -> None:
        fake = [
            {"id": "ok1", "name": "one", "port": 1, "status": "active", "error": None},
            {"id": "ok2", "name": "two", "port": 2, "status": "active", "error": None},
            {"id": "bad", "name": "three", "port": 3, "status": "error", "error": "busy"},
        ]
        client = TestClient(app)
        with (
            patch.object(nexus_api, "deploy_bundle", return_value=fake),
            patch.object(nexus_api, "insert_events"),
        ):
            payload = client.post(
                "/api/traps/bundle/default",
                headers={"X-LANimals-Operator": "1"},
            ).json()

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["active_count"], 2)
        self.assertEqual(payload["failure_count"], 1)
