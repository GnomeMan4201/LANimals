"""
LANimals core test suite.
Tests DB layer, risk scoring engine, and module imports.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# ── DB layer ──────────────────────────────────────────────────────────────────

def test_db_init():
    from core import nexus_db
    nexus_db.init_db()  # should not raise


def test_upsert_and_retrieve_host():
    from core.nexus_db import upsert_host, get_host
    host = {
        "ip": "10.0.0.1",
        "mac": "aa:bb:cc:dd:ee:ff",
        "hostname": "testhost",
        "vendor": "TestVendor",
        "status": "normal",
        "risk_score": 15,
    }
    upsert_host(host)
    result = get_host("10.0.0.1")
    assert result is not None
    assert result["ip"] == "10.0.0.1"
    assert result["mac"] == "aa:bb:cc:dd:ee:ff"


def test_upsert_host_missing_ip_is_noop():
    from core.nexus_db import upsert_host
    # Should not raise — just silently skip
    upsert_host({"hostname": "ghost", "mac": "00:00:00:00:00:00"})


def test_insert_and_retrieve_event():
    from core.nexus_db import insert_event, get_recent_events
    insert_event({
        "id": "test-event-001",
        "severity": "warning",
        "title": "Test event",
        "summary": "Unit test insertion",
        "ip": "10.0.0.1",
    })
    events = get_recent_events(limit=10, ip="10.0.0.1")
    ids = [e["id"] for e in events]
    assert "test-event-001" in ids


def test_mac_baseline_update_and_retrieve():
    from core.nexus_db import update_mac_baseline, get_mac_baseline
    update_mac_baseline("10.0.0.2", "11:22:33:44:55:66", "baselinehost")
    baseline = get_mac_baseline()
    assert "10.0.0.2" in baseline
    assert baseline["10.0.0.2"]["mac"] == "11:22:33:44:55:66"


def test_host_notes_roundtrip():
    from core.nexus_db import set_host_notes, get_host_notes, upsert_host
    upsert_host({"ip": "10.0.0.3", "status": "normal"})
    set_host_notes("10.0.0.3", "suspicious device — monitor")
    notes = get_host_notes("10.0.0.3")
    assert notes == "suspicious device — monitor"


def test_db_stats_returns_expected_keys():
    from core.nexus_db import get_db_stats
    stats = get_db_stats()
    for key in ("hosts", "services", "events", "warnings", "critical", "baseline_entries"):
        assert key in stats, f"Missing key in db stats: {key}"


def test_upsert_services():
    from core.nexus_db import upsert_services, get_services_for_ip
    upsert_services([{
        "ip": "10.0.0.1",
        "port": "22",
        "protocol": "tcp",
        "service_name": "ssh",
        "product": "OpenSSH",
        "version": "8.9",
    }])
    services = get_services_for_ip("10.0.0.1")
    ports = [s["port"] for s in services]
    assert "22" in ports


# ── Risk scoring engine ───────────────────────────────────────────────────────

def test_score_clean_host():
    from core.nexus_risk import score_host
    host = {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Apple"}
    score, status, reasons = score_host(host, [], in_baseline=True)
    assert isinstance(score, int)
    assert 0 < score <= 100
    assert status in ("normal", "warning", "critical")


def test_score_telnet_port_raises_risk():
    from core.nexus_risk import score_host
    host = {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Cisco"}
    services = [{"port": "23", "protocol": "tcp"}]
    score, status, reasons = score_host(host, services, in_baseline=True)
    assert score >= 35  # Telnet is 35 pts
    assert any("Telnet" in r for r in reasons)


def test_score_smb_port_raises_risk():
    from core.nexus_risk import score_host
    host = {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Microsoft"}
    services = [{"port": "445", "protocol": "tcp"}]
    score, status, reasons = score_host(host, services, in_baseline=True)
    assert score >= 35
    assert any("SMB" in r for r in reasons)


def test_score_metasploit_port_is_critical():
    from core.nexus_risk import score_host
    host = {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Unknown"}
    services = [{"port": "4444", "protocol": "tcp"}]
    score, status, reasons = score_host(host, services, in_baseline=True)
    assert score >= 60
    assert status in ("warning", "critical")


def test_score_mac_change_from_baseline():
    from core.nexus_risk import score_host
    host = {"ip": "10.0.0.1", "mac": "ff:ff:ff:ff:ff:ff", "vendor": "Unknown"}
    score, status, reasons = score_host(
        host, [], in_baseline=True, baseline_mac="aa:bb:cc:dd:ee:ff"
    )
    assert score >= 40
    assert any("MAC changed" in r for r in reasons)


def test_score_honeypot_hit_is_critical():
    from core.nexus_risk import score_host
    host = {
        "ip": "10.0.0.1",
        "mac": "aa:bb:cc:dd:ee:ff",
        "vendor": "Unknown",
        "honeypot_hits": 3,
    }
    score, status, reasons = score_host(host, [], in_baseline=True, honeypot_hits=3)
    assert score >= 65
    assert status == "critical"


def test_score_not_in_baseline_adds_risk():
    from core.nexus_risk import score_host
    host = {"ip": "10.0.0.99", "mac": "de:ad:be:ef:00:01", "vendor": "Unknown"}
    score, status, reasons = score_host(host, [], in_baseline=False)
    assert score >= 25
    assert any("baseline" in r.lower() for r in reasons)


def test_score_caps_at_100():
    from core.nexus_risk import score_host
    host = {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Unknown",
            "honeypot_hits": 99}
    services = [{"port": p, "protocol": "tcp"} for p in
                ["23", "445", "3389", "4444", "5900", "512", "513", "514"]]
    score, status, reasons = score_host(
        host, services, in_baseline=False,
        baseline_mac="ff:ff:ff:ff:ff:ff",
        cve_count=10, honeypot_hits=99
    )
    assert score <= 100


# ── Module imports ────────────────────────────────────────────────────────────

def test_nexus_db_imports():
    from core import nexus_db
    assert nexus_db is not None


def test_nexus_models_imports():
    from core import nexus_models
    assert nexus_models is not None


def test_nexus_risk_imports():
    from core import nexus_risk
    assert nexus_risk is not None


def test_modules_import():
    from modules import arp_recon
    assert arp_recon is not None


def test_killchain_imports():
    from core import killchain
    assert killchain is not None
