from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
INDEX = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
APP_JS = (ROOT / "docs" / "app.js").read_text(encoding="utf-8")
APP_CSS = (ROOT / "docs" / "app.css").read_text(encoding="utf-8")


class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.styles = []

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if tag == "script" and data.get("src"):
            self.scripts.append(data["src"])
        if tag == "link" and data.get("rel") == "stylesheet" and data.get("href"):
            self.styles.append(data["href"])


def test_public_page_is_operator_console_not_legacy_marketing():
    assert "LANimals" in INDEX
    assert "REPRESENTATIVE / NO LIVE LAN ACCESS" in INDEX
    assert "Network topology" in INDEX
    assert "Selected host / representative" in INDEX

    for legacy_claim in (
        "Autonomous Recon",
        "Live Threat Monitoring",
        "maps your prey",
        "Terminal-Only, Operator Focused",
        "LAN Threat Recon + Subnet Mapping Toolkit",
    ):
        assert legacy_claim not in INDEX


def test_public_page_cannot_open_live_network_connections():
    assert "connect-src 'none'" in INDEX
    forbidden_js_primitives = (
        "fetch(",
        "XMLHttpRequest",
        "WebSocket(",
        "EventSource(",
        "sendBeacon(",
    )
    for primitive in forbidden_js_primitives:
        assert primitive not in APP_JS

    assert "Go Live" not in INDEX
    assert "go live" not in APP_JS.lower()
    assert "This page never becomes live." in INDEX


def test_public_assets_are_local_and_dependency_free():
    parser = AssetParser()
    parser.feed(INDEX)
    assert parser.scripts == ["./app.js"]
    assert parser.styles == ["./app.css"]
    assert "@import" not in APP_CSS
    assert "url(http" not in APP_CSS.lower()


def test_hosted_actions_match_representative_contract():
    for action in ("discovery", "arp", "hostmap", "rogue", "rescore", "diff", "audit", "traps", "report"):
        assert f'data-action="{action}"' in INDEX

    for local_only_label in (
        "Service Fingerprinting",
        "CVE Correlation",
        "System Inventory",
        "Anomaly Scan",
        "Watchdog",
        "VirusTotal Enrichment",
        "Deploy / Stop Trap",
    ):
        assert local_only_label in INDEX

    assert "UNAVAILABLE IN HOSTED MODE" in APP_JS
    assert "Representative session mutation only" in APP_JS
    assert "no network request" in APP_JS.lower()


def test_terminal_is_allowlisted_and_not_a_shell():
    assert "allowed: help status hosts events baseline traps audit discovery arp hostmap rogue rescore report clear" in APP_JS
    assert "self-hosted only: services cve inventory anomaly watchdog vt trap-deploy trap-stop" in APP_JS
    assert "eval(" not in APP_JS
    assert "new Function" not in APP_JS
    assert "child_process" not in APP_JS


def test_public_console_preserves_mobile_and_accessibility_contracts():
    assert "max-width: 760px" in APP_CSS
    assert "prefers-reduced-motion" in APP_CSS
    assert "focus-visible" in APP_CSS
    assert "aria-label=\"Open operations\"" in INDEX
    assert "aria-label=\"Open selected host\"" in INDEX
    assert "Use Tab to reach host nodes" in INDEX


def test_public_javascript_parses_when_node_is_available():
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed in this environment")
    result = subprocess.run(
        [node, "--check", str(ROOT / "docs" / "app.js")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
