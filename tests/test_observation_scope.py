from unittest.mock import patch

from core import nexus_collectors


def test_filter_observations_keeps_only_usable_hosts_in_exact_cidr():
    rows = [
        {"ip": "192.168.250.0", "source": "network-address"},
        {"ip": "192.168.250.1", "source": "local"},
        {"ip": "192.168.250.2", "source": "remote"},
        {"ip": "192.168.250.3", "source": "broadcast"},
        {"ip": "192.168.251.2", "source": "other-subnet"},
        {"ip": "not-an-ip", "source": "malformed"},
    ]

    with patch.object(nexus_collectors, "validate_scan_cidr", return_value="192.168.250.0/30"):
        filtered = nexus_collectors.filter_observations_to_cidr(rows, "192.168.250.0/30")

    assert [row["ip"] for row in filtered] == ["192.168.250.1", "192.168.250.2"]


def test_rogue_scan_refreshes_neighbor_cache_before_reading_mac():
    state = {"swept": False}

    def nmap_after_validation(cidr: str):
        state["swept"] = True
        return [{
            "ip": "192.168.250.2",
            "hostname": "fixture",
            "mac": None,
            "source": "nmap_ping",
        }]

    def arp_after_sweep():
        if not state["swept"]:
            return []
        return [{
            "ip": "192.168.250.2",
            "hostname": "fixture",
            "mac": "02:42:AC:11:00:99",
            "source": "arp",
        }]

    baseline = {
        "192.168.250.2": {
            "ip": "192.168.250.2",
            "mac": "02:42:AC:11:00:01",
            "hostname": "fixture",
        }
    }

    with (
        patch.object(nexus_collectors, "validate_scan_cidr", return_value="192.168.250.0/30"),
        patch.object(nexus_collectors, "collect_nmap_ping_sweep", side_effect=nmap_after_validation),
        patch.object(nexus_collectors, "collect_arp_neighbors", side_effect=arp_after_sweep),
        patch("core.nexus_db.get_mac_baseline", return_value=baseline),
    ):
        result = nexus_collectors.collect_rogue_scan("192.168.250.0/30")

    assert result["scanned_count"] == 1
    assert result["rogues"] == [{
        "ip": "192.168.250.2",
        "mac": "02:42:AC:11:00:99",
        "previous_mac": "02:42:AC:11:00:01",
        "hostname": "fixture",
        "reason": "MAC changed from baseline",
    }]
