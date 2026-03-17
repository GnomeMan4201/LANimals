from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parent.parent
TMP_DIR = ROOT / "tmp"
TMP_DIR.mkdir(exist_ok=True)


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return (result.stdout + "\n" + result.stderr).strip()
    except Exception:
        return ""


def collect_arp_neighbors() -> List[Dict[str, Any]]:
    output = _run(["ip", "neigh"])
    rows: List[Dict[str, Any]] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Example:
        # 192.168.1.1 dev wlp2s0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        parts = line.split()
        if len(parts) < 4:
            continue

        ip = parts[0]
        mac = None
        dev = None
        state = parts[-1] if parts else "UNKNOWN"

        if "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts):
                mac = parts[idx + 1]

        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                dev = parts[idx + 1]

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ip

        rows.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "interface": dev,
            "state": state,
            "source": "arp",
        })

    return rows


def collect_local_interfaces() -> List[Dict[str, Any]]:
    try:
        import psutil  # type: ignore
    except Exception:
        return []

    rows: List[Dict[str, Any]] = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            fam = getattr(addr.family, "name", str(addr.family))
            if fam == "AF_INET" and not str(addr.address).startswith("127."):
                rows.append({
                    "ip": addr.address,
                    "hostname": socket.gethostname(),
                    "mac": None,
                    "interface": iface,
                    "state": "LOCAL",
                    "source": "local_interface",
                })
    return rows


def collect_nmap_ping_sweep(cidr: str = "192.168.1.0/24") -> List[Dict[str, Any]]:
    if shutil.which("nmap") is None:
        return []

    xml_path = TMP_DIR / "nexus_ping_scan.xml"
    _run(["nmap", "-sn", cidr, "-oX", str(xml_path)], timeout=60)

    if not xml_path.exists():
        return []

    try:
        from xml.etree import ElementTree as ET
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return []

    rows: List[Dict[str, Any]] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip_elem = host.find("address[@addrtype='ipv4']")
        if ip_elem is None:
            continue

        ip = ip_elem.get("addr")
        mac_elem = host.find("address[@addrtype='mac']")
        mac = mac_elem.get("addr") if mac_elem is not None else None
        hostname_elem = host.find(".//hostname")
        hostname = hostname_elem.get("name") if hostname_elem is not None else ip

        rows.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "interface": None,
            "state": "UP",
            "source": "nmap_ping",
        })

    return rows


def collect_all(cidr: str = "192.168.1.0/24") -> Dict[str, Any]:
    arp = collect_arp_neighbors()
    local = collect_local_interfaces()
    nmap_hosts = collect_nmap_ping_sweep(cidr=cidr)

    return {
        "arp_neighbors": arp,
        "local_interfaces": local,
        "nmap_hosts": nmap_hosts,
    }


if __name__ == "__main__":
    print(json.dumps(collect_all(), indent=2))
