from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ["LANIMALS_ALLOWED_CIDRS"] = "192.168.50.0/24"
os.environ["LANIMALS_MAX_SCAN_ADDRESSES"] = "256"

from core import nexus_collectors as collectors


class CollectorCommandTests(unittest.TestCase):
    def test_successful_command_preserves_output(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout="observed\n", stderr="")
        with patch.object(collectors.subprocess, "run", return_value=completed):
            self.assertEqual(collectors._run(["ip", "neigh"]), "observed")

    def test_successful_empty_command_is_valid_empty_output(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(collectors.subprocess, "run", return_value=completed):
            self.assertEqual(collectors._run(["ip", "neigh"]), "")

    def test_timeout_is_typed_failure(self) -> None:
        with patch.object(
            collectors.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["ip", "neigh"], 30),
        ):
            with self.assertRaisesRegex(collectors.CollectorError, "timed out"):
                collectors._run(["ip", "neigh"], timeout=30)

    def test_nonzero_exit_is_typed_failure_with_stderr(self) -> None:
        completed = SimpleNamespace(
            returncode=2,
            stdout="",
            stderr="permission denied",
        )
        with patch.object(collectors.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(collectors.CollectorError, "permission denied"):
                collectors._run(["ip", "neigh"])

    def test_launch_failure_is_typed_failure(self) -> None:
        with patch.object(
            collectors.subprocess,
            "run",
            side_effect=FileNotFoundError("ip"),
        ):
            with self.assertRaisesRegex(collectors.CollectorError, "failed to start"):
                collectors._run(["ip", "neigh"])

    def test_required_nmap_unavailable_is_failure(self) -> None:
        with patch.object(collectors.shutil, "which", return_value=None):
            with self.assertRaisesRegex(collectors.CollectorError, "unavailable: nmap"):
                collectors.collect_nmap_ping_sweep("192.168.50.0/24")

    def test_valid_zero_host_nmap_xml_is_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            xml_path = tmp_path / "nexus_ping_scan.xml"

            def successful_empty_scan(*args, **kwargs):
                xml_path.write_text("<nmaprun></nmaprun>", encoding="utf-8")
                return ""

            with patch.object(collectors, "TMP_DIR", tmp_path), patch.object(
                collectors.shutil,
                "which",
                return_value="/usr/bin/nmap",
            ), patch.object(collectors, "_run", side_effect=successful_empty_scan):
                self.assertEqual(
                    collectors.collect_nmap_ping_sweep("192.168.50.0/24"),
                    [],
                )

    def test_scope_rejection_happens_before_subprocess(self) -> None:
        with patch.object(collectors, "_run") as run_mock:
            with self.assertRaises(Exception):
                collectors.collect_nmap_ping_sweep("8.8.8.0/24")
        run_mock.assert_not_called()


class DiscoveryFailureTests(unittest.TestCase):
    def test_required_collector_failure_marks_discovery_job_error(self) -> None:
        from core import nexus_api

        jid = nexus_api._job_create("discovery", {"cidr": "192.168.50.0/24"})
        with patch.object(
            nexus_api,
            "collect_arp_neighbors",
            side_effect=collectors.CollectorError("ip neigh failed"),
        ):
            nexus_api._run_discovery(jid, "192.168.50.0/24")

        job = nexus_api._job_get(jid)
        self.assertEqual(job["status"], "error")
        self.assertIsNone(job["result"])
        self.assertIn("ip neigh failed", job["error"])


if __name__ == "__main__":
    unittest.main()
