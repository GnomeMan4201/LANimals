from __future__ import annotations

from unittest.mock import patch

from core import nexus_collectors as collectors


def test_get_iface_mac_reads_and_normalizes_sysfs_address():
    with patch.object(collectors, "Path") as path_cls:
        path_cls.return_value.read_text.return_value = "aa:bb:cc:dd:ee:ff\n"

        result = collectors._get_iface_mac("eth0")

    path_cls.assert_called_once_with("/sys/class/net/eth0/address")
    path_cls.return_value.read_text.assert_called_once()
    assert result == "AA:BB:CC:DD:EE:FF"


def test_get_iface_mac_missing_or_unreadable_is_best_effort_none():
    with patch.object(collectors, "Path") as path_cls:
        path_cls.return_value.read_text.side_effect = OSError("unavailable")

        result = collectors._get_iface_mac("eth0")

    assert result is None
