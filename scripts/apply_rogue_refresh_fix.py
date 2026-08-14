from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "core" / "nexus_collectors.py"
text = TARGET.read_text(encoding="utf-8")

old = '''    cidr = validate_scan_cidr(cidr)\n    current_arp = filter_observations_to_cidr(collect_arp_neighbors(), cidr)\n    current_nmap = filter_observations_to_cidr(collect_nmap_ping_sweep(cidr=cidr), cidr)\n\n    current: Dict[str, Dict[str, Any]] = {}\n'''
new = '''    cidr = validate_scan_cidr(cidr)\n    # Run the active sweep before reading the neighbor cache. On a cold or\n    # recently-flushed cache, the sweep itself causes the kernel to resolve\n    # directly-connected peers; reading ARP first can miss a real MAC change.\n    current_nmap = filter_observations_to_cidr(collect_nmap_ping_sweep(cidr=cidr), cidr)\n    current_arp = filter_observations_to_cidr(collect_arp_neighbors(), cidr)\n\n    current: Dict[str, Dict[str, Any]] = {}\n'''

if text.count(old) != 1:
    raise SystemExit(f"cold-cache rogue source drifted: expected one match, found {text.count(old)}")
TARGET.write_text(text.replace(old, new, 1), encoding="utf-8")
print("rogue scan now refreshes active reachability before reading MAC evidence")
