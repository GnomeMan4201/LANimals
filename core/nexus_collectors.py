from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
TMP_DIR = ROOT / "tmp"
TMP_DIR.mkdir(exist_ok=True)

# ── Virtual interface filtering ───────────────────────────────────────────────
_VIRTUAL_IFACE_PREFIXES = (
    "docker", "veth", "virbr", "br-", "lxc", "lxd",
    "vbox", "vmnet", "tun", "tap", "wg", "utun", "lxcbr",
)
_VIRTUAL_IP_PREFIXES = (
    "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
    "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "10.0.3.", "10.0.2.",
)


def _is_virtual_iface(iface: str) -> bool:
    return any(iface.lower().startswith(p) for p in _VIRTUAL_IFACE_PREFIXES)


def _is_virtual_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _VIRTUAL_IP_PREFIXES)


# ── OUI vendor lookup ─────────────────────────────────────────────────────────
_OUI_TABLE: dict[str, str] = {
    # TP-Link
    "C0C522":"TP-Link","C0C5C0":"TP-Link","C83A35":"TP-Link","1C61B4":"TP-Link",
    "5054FF":"TP-Link","788CB5":"TP-Link","B0487A":"TP-Link","2C4D54":"TP-Link",
    # Intel
    "6C6A77":"Intel","8086F2":"Intel","A4C3F0":"Intel","8C8D28":"Intel",
    "A0C589":"Intel","8C70D4":"Intel","B88D12":"Intel",
    # Apple
    "ACDE48":"Apple","F0DEF1":"Apple","A8BB50":"Apple","606BBD":"Apple",
    "3C2EFF":"Apple","784F43":"Apple","98FEE8":"Apple","3C15C2":"Apple",
    "A8B5E4":"Apple","A8B57C":"Apple",
    # Samsung
    "A8B57C":"Samsung","A4C2C6":"Samsung","B8C68E":"Samsung","6CBB14":"Samsung",
    "F49F54":"Samsung","68F63B":"Samsung",
    # Raspberry Pi
    "B827EB":"Raspberry Pi","DCA632":"Raspberry Pi","E45F01":"Raspberry Pi",
    # Google
    "001A11":"Google","F4F5E8":"Google","3C5AB4":"Google",
    # VMware / VirtualBox
    "000C29":"VMware","005056":"VMware","080027":"VirtualBox",
    # Cisco
    "C80CC8":"Cisco","0026CB":"Cisco","70105C":"Cisco","18D6C7":"Cisco",
    "F872EA":"Cisco","001143":"Cisco","0013C4":"Cisco","001B2B":"Cisco",
    # Netgear
    "D8BB2C":"Netgear","20E52A":"Netgear","A40CCB":"Netgear","9C3DCF":"Netgear",
    # Arris / CommScope
    "0000CA":"Arris","001A2A":"Arris","34A84E":"Arris","4C09D4":"Arris",
    # ASUSTek
    "1C872C":"ASUS","10BF48":"ASUS","50465D":"ASUS","AC220B":"ASUS",
    # Ubiquiti
    "687F74":"Ubiquiti","788A20":"Ubiquiti","DCEF09":"Ubiquiti","E063DA":"Ubiquiti",
    # Xiaomi
    "F8A45F":"Xiaomi","286C07":"Xiaomi","64B473":"Xiaomi",
    # Huawei
    "001E10":"Huawei","001E67":"Huawei","286ED4":"Huawei","48DB50":"Huawei",
    # Dell
    "848598":"Dell","F8DB88":"Dell","14187E":"Dell","BCEE7B":"Dell",
    # HP
    "001708":"HP","0022F3":"HP","30E171":"HP","9CB6D0":"HP",
    # Misc
    "1ADE E8":"Unknown","000000":"Xerox","00005E":"IANA",
}


def _lookup_vendor(mac: str | None) -> str:
    if not mac:
        return ""
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    return _OUI_TABLE.get(prefix, "")


# ── Helpers ───────────────────────────────────────────────────────────────────
def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return (result.stdout + "\n" + result.stderr).strip()
    except Exception:
        return ""


def _nmap_cmd(args: list[str]) -> list[str]:
    """Prepend sudo if not root — needed for MAC/ARP data."""
    if shutil.which("sudo") and os.geteuid() != 0:
        return ["sudo"] + ["nmap"] + args
    return ["nmap"] + args


def _is_ipv4(ip: str | None) -> bool:
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def _resolve(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def _get_iface_mac(iface: str) -> str | None:
    try:
        mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()
        if mac and mac != "00:00:00:00:00:00":
            return mac.upper()
    except Exception:
        pass
    return None


# ── Collectors ────────────────────────────────────────────────────────────────

def collect_arp_neighbors() -> List[Dict[str, Any]]:
    output = _run(["ip", "neigh"])
    rows: List[Dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) < 4:
            continue
        ip = parts[0]
        if not _is_ipv4(ip):
            continue
        mac = None
        dev = None
        state = parts[-1]
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts):
                mac = parts[idx + 1]
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                dev = parts[idx + 1]
        if dev and _is_virtual_iface(dev):
            continue
        hostname = _resolve(ip)
        rows.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": _lookup_vendor(mac),
            "interface": dev,
            "state": state,
            "source": "arp",
        })
    return rows


def collect_local_interfaces() -> List[Dict[str, Any]]:
    try:
        import psutil
    except Exception:
        return []
    rows: List[Dict[str, Any]] = []
    seen_ips: set[str] = set()
    for iface, addrs in psutil.net_if_addrs().items():
        if _is_virtual_iface(iface):
            continue
        for addr in addrs:
            fam = getattr(addr.family, "name", str(addr.family))
            ip = str(addr.address)
            if (
                fam == "AF_INET"
                and not ip.startswith("127.")
                and not _is_virtual_ip(ip)
                and ip not in seen_ips
            ):
                seen_ips.add(ip)
                mac = _get_iface_mac(iface)
                rows.append({
                    "ip": ip,
                    "hostname": socket.gethostname(),
                    "mac": mac,
                    "vendor": _lookup_vendor(mac),
                    "interface": iface,
                    "state": "LOCAL",
                    "source": "local_interface",
                })
    return rows


def collect_nmap_ping_sweep(cidr: str = "192.168.1.0/24") -> List[Dict[str, Any]]:
    if shutil.which("nmap") is None:
        return []
    xml_path = TMP_DIR / "nexus_ping_scan.xml"
    _run(_nmap_cmd(["-sn", cidr, "-oX", str(xml_path)]), timeout=90)
    if not xml_path.exists():
        return []
    try:
        from xml.etree import ElementTree as ET
        root = ET.parse(xml_path).getroot()
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
        if not _is_ipv4(ip):
            continue
        mac_elem = host.find("address[@addrtype='mac']")
        mac = mac_elem.get("addr") if mac_elem is not None else None
        vendor = mac_elem.get("vendor") if mac_elem is not None else _lookup_vendor(mac)
        hostname_elem = host.find(".//hostname")
        hostname = hostname_elem.get("name") if hostname_elem is not None else _resolve(ip)
        rows.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor or _lookup_vendor(mac),
            "interface": None,
            "state": "UP",
            "source": "nmap_ping",
        })
    return rows


def collect_host_map(cidr: str = "192.168.1.0/24") -> List[Dict[str, Any]]:
    rows = collect_nmap_ping_sweep(cidr=cidr)
    for row in rows:
        if row.get("hostname") == row.get("ip") or not row.get("hostname"):
            row["hostname"] = _resolve(row["ip"])
    return rows


def collect_rogue_scan(cidr: str = "192.168.1.0/24") -> Dict[str, Any]:
    from core.nexus_state import load_state, save_state

    current_arp = collect_arp_neighbors()
    current_nmap = collect_nmap_ping_sweep(cidr=cidr)

    current: Dict[str, Dict[str, Any]] = {}
    for row in current_arp + current_nmap:
        ip = row.get("ip")
        if ip and ip not in current:
            current[ip] = row

    state = load_state()
    baseline: Dict[str, Any] = state.get("mac_baseline", {})

    rogues = []
    for ip, info in current.items():
        mac = info.get("mac")
        if not mac:
            continue
        if ip in baseline:
            if baseline[ip].get("mac") and baseline[ip]["mac"] != mac:
                rogues.append({
                    "ip": ip,
                    "mac": mac,
                    "previous_mac": baseline[ip].get("mac"),
                    "hostname": info.get("hostname", ip),
                    "reason": "MAC changed from baseline",
                })
        else:
            rogues.append({
                "ip": ip,
                "mac": mac,
                "previous_mac": None,
                "hostname": info.get("hostname", ip),
                "reason": "New host not in baseline",
            })

    for ip, info in current.items():
        if ip not in baseline:
            baseline[ip] = {"mac": info.get("mac"), "first_seen": _now_str()}
    state["mac_baseline"] = baseline
    save_state(state)

    # Sync baseline to SQLite
    try:
        from core.nexus_db import update_mac_baseline as _upsert_baseline
        for ip, info in current.items():
            mac = info.get("mac")
            if mac:
                _upsert_baseline(ip, mac, info.get("hostname", ip))
    except Exception:
        pass

    return {
        "rogues": rogues,
        "known_count": len(baseline),
        "scanned_count": len(current),
    }


def _now_str() -> str:
    from datetime import datetime
    return datetime.utcnow().isoformat() + "Z"


def collect_sysinfo() -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    info["hostname"] = socket.gethostname()
    try:
        import psutil
        info["cpu_count"] = psutil.cpu_count()
        info["cpu_percent"] = psutil.cpu_percent(interval=0.5)
        vm = psutil.virtual_memory()
        info["ram_total_mb"] = round(vm.total / 1024 / 1024)
        info["ram_used_mb"] = round(vm.used / 1024 / 1024)
        info["ram_percent"] = vm.percent
        disk = psutil.disk_usage("/")
        info["disk_total_gb"] = round(disk.total / 1024 / 1024 / 1024, 1)
        info["disk_used_gb"] = round(disk.used / 1024 / 1024 / 1024, 1)
        info["disk_percent"] = disk.percent
        ifaces = {}
        for iface, addrs in psutil.net_if_addrs().items():
            if _is_virtual_iface(iface):
                continue
            ips = [
                a.address for a in addrs
                if getattr(a.family, "name", "") == "AF_INET"
                and not a.address.startswith("127.")
                and not _is_virtual_ip(a.address)
            ]
            if ips:
                ifaces[iface] = ips
        info["interfaces"] = ifaces
    except Exception as e:
        info["psutil_error"] = str(e)

    uname = _run(["uname", "-a"])
    if uname:
        info["uname"] = uname

    return info


def collect_all(cidr: str = "192.168.1.0/24") -> Dict[str, Any]:
    arp = collect_arp_neighbors()
    local = collect_local_interfaces()
    nmap_hosts = collect_nmap_ping_sweep(cidr=cidr)
    target_ips = sorted({row["ip"] for row in arp + local + nmap_hosts if row.get("ip")})
    service_scan = collect_service_scan(target_ips[:8])
    return {
        "arp_neighbors": arp,
        "local_interfaces": local,
        "nmap_hosts": nmap_hosts,
        "service_scan": service_scan,
    }


def collect_service_scan(targets: List[str]) -> List[Dict[str, Any]]:
    if shutil.which("nmap") is None:
        return []
    ipv4 = [t for t in targets if _is_ipv4(t)]
    if not ipv4:
        return []
    xml_path = TMP_DIR / "nexus_service_scan.xml"
    _run(_nmap_cmd(["-sV", "-oX", str(xml_path)] + ipv4), timeout=180)
    return _parse_nmap_services(xml_path, source="nmap_service")


def collect_services_for_ip(ip: str) -> List[Dict[str, Any]]:
    if shutil.which("nmap") is None or not _is_ipv4(ip):
        return []
    xml_path = TMP_DIR / f"nexus_svc_{ip.replace('.', '_')}.xml"
    _run(_nmap_cmd(["-Pn", "-sV", "-oX", str(xml_path), ip]), timeout=120)
    return _parse_nmap_services(xml_path, source="nmap_service_targeted", filter_ip=ip)


def _parse_nmap_services(
    xml_path: Path, source: str = "nmap", filter_ip: str | None = None
) -> List[Dict[str, Any]]:
    if not xml_path.exists():
        return []
    try:
        from xml.etree import ElementTree as ET
        root = ET.parse(xml_path).getroot()
    except Exception:
        return []
    services: List[Dict[str, Any]] = []
    for host in root.findall("host"):
        ip_elem = host.find("address[@addrtype='ipv4']")
        if ip_elem is None:
            continue
        ip = ip_elem.get("addr")
        if not _is_ipv4(ip):
            continue
        if filter_ip and ip != filter_ip:
            continue
        mac_elem = host.find("address[@addrtype='mac']")
        mac = mac_elem.get("addr") if mac_elem is not None else None
        vendor = mac_elem.get("vendor") if mac_elem is not None else _lookup_vendor(mac)
        for port in host.findall(".//port"):
            st = port.find("state")
            if st is not None and st.get("state") != "open":
                continue
            svc = port.find("service")
            services.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "port": port.get("portid", ""),
                "protocol": port.get("protocol", "tcp"),
                "service_name": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extra_info": svc.get("extrainfo", "") if svc is not None else "",
                "source": source,
            })
    return services


if __name__ == "__main__":
    print(json.dumps(collect_all(), indent=2))
