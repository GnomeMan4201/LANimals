from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"{path}: expected one match, found {text.count(old)}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "core/nexus_collectors.py",
    "import json\nimport shutil\n",
    "import ipaddress\nimport json\nimport shutil\n",
)

replace_once(
    "core/nexus_collectors.py",
    '''def _is_ipv4(ip: str | None) -> bool:\n    if not ip:\n        return False\n    parts = ip.split(".")\n    if len(parts) != 4:\n        return False\n    try:\n        return all(0 <= int(p) <= 255 for p in parts)\n    except Exception:\n        return False\n\n\n''',
    '''def _is_ipv4(ip: str | None) -> bool:\n    if not ip:\n        return False\n    parts = ip.split(".")\n    if len(parts) != 4:\n        return False\n    try:\n        return all(0 <= int(p) <= 255 for p in parts)\n    except Exception:\n        return False\n\n\ndef filter_observations_to_cidr(rows: List[Dict[str, Any]], cidr: str) -> List[Dict[str, Any]]:\n    """Keep only usable IPv4 host observations inside one validated scan CIDR."""\n    network = ipaddress.ip_network(validate_scan_cidr(cidr), strict=False)\n    filtered: List[Dict[str, Any]] = []\n    for row in rows:\n        raw_ip = row.get("ip")\n        try:\n            address = ipaddress.ip_address(str(raw_ip))\n        except ValueError:\n            continue\n        if not isinstance(address, ipaddress.IPv4Address) or address not in network:\n            continue\n        if address in {network.network_address, network.broadcast_address}:\n            continue\n        filtered.append(row)\n    return filtered\n\n\n''',
)

replace_once(
    "core/nexus_collectors.py",
    '''    current_arp = collect_arp_neighbors()\n    current_nmap = collect_nmap_ping_sweep(cidr=cidr)\n\n    current: Dict[str, Dict[str, Any]] = {}\n''',
    '''    cidr = validate_scan_cidr(cidr)\n    current_arp = filter_observations_to_cidr(collect_arp_neighbors(), cidr)\n    current_nmap = filter_observations_to_cidr(collect_nmap_ping_sweep(cidr=cidr), cidr)\n\n    current: Dict[str, Dict[str, Any]] = {}\n''',
)

replace_once(
    "core/nexus_collectors.py",
    '''def collect_all(cidr: str = "192.168.1.0/24") -> Dict[str, Any]:\n    arp = collect_arp_neighbors()\n    local = collect_local_interfaces()\n    nmap_hosts = collect_nmap_ping_sweep(cidr=cidr)\n''',
    '''def collect_all(cidr: str = "192.168.1.0/24") -> Dict[str, Any]:\n    cidr = validate_scan_cidr(cidr)\n    arp = filter_observations_to_cidr(collect_arp_neighbors(), cidr)\n    local = filter_observations_to_cidr(collect_local_interfaces(), cidr)\n    nmap_hosts = filter_observations_to_cidr(collect_nmap_ping_sweep(cidr=cidr), cidr)\n''',
)

replace_once(
    "core/nexus_api.py",
    '''    collect_sysinfo,\n    collect_services_for_ip,\n)\n''',
    '''    collect_sysinfo,\n    collect_services_for_ip,\n    filter_observations_to_cidr,\n)\n''',
)

replace_once(
    "core/nexus_api.py",
    '''        arp = collect_arp_neighbors()\n        local = collect_local_interfaces()\n        _job_log(jid, f"  ARP table: {len(arp)} entries")\n        _job_log(jid, f"  Local interfaces: {len(local)} addresses")\n        _job_log(jid, f"  Starting nmap ping sweep on {cidr} …")\n        nmap_hosts = collect_nmap_ping_sweep(cidr=cidr)\n        _job_log(jid, f"  nmap found: {len(nmap_hosts)} hosts")\n''',
    '''        arp = filter_observations_to_cidr(collect_arp_neighbors(), cidr)\n        local = filter_observations_to_cidr(collect_local_interfaces(), cidr)\n        _job_log(jid, f"  ARP table in scope: {len(arp)} entries")\n        _job_log(jid, f"  Local interfaces in scope: {len(local)} addresses")\n        _job_log(jid, f"  Starting nmap ping sweep on {cidr} …")\n        nmap_hosts = filter_observations_to_cidr(collect_nmap_ping_sweep(cidr=cidr), cidr)\n        _job_log(jid, f"  nmap found in scope: {len(nmap_hosts)} hosts")\n''',
)

print("discovery/rogue acquisition is constrained to the exact scan CIDR")
