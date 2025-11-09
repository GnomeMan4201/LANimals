import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
import os
import json
from collections import Counter, defaultdict
from rich import print
from rich.table import Table

LOOT_PATHS = [
    "loot_log.json",
    "loot_log.txt",
    "loot.json",
    os.path.expanduser("~/.lanimals/data/loot_log.json"),
    os.path.expanduser("~/.lanimals/data/loot.json"),
]

def find_loot_file():
    for path in LOOT_PATHS:
        if os.path.isfile(path):
            return path
    return None

def parse_loot(path):
    try:
        if path.endswith('.json'):
            with open(path, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return [data]
                return data
        else:
            with open(path, "r") as f:
                lines = f.readlines()
                devices = []
                for line in lines:
                    if "Host:" in line and "Status: Up" in line:
                        ip = line.split("Host:")[1].split("(")[0].strip()
                        devices.append({"ip": ip})
                return devices
    except Exception as e:
        print(f"[red]Failed to parse loot log: {e}[/red]")
        return []

def summarize_loot(devices):
    ips = []
    vendors = []
    ports = []
    odd_hosts = []
    for d in devices:
        ip = d.get("ip") or d.get("host") or d.get("address") or "?"
        vendor = d.get("vendor") or d.get("mac_vendor") or "Unknown"
        host_ports = d.get("ports") or d.get("open_ports") or []
        ips.append(ip)
        vendors.append(vendor)
        ports += host_ports
        if any(x in ip for x in ["."]) and (vendor == "Unknown" or len(host_ports) > 10):
            odd_hosts.append(ip)
    return ips, vendors, ports, odd_hosts

def main():
    print("[bold red]\nLANimals Loot Analytics / Summarizer\n[/bold red]")
    loot_path = find_loot_file()
    if not loot_path:
        print("[yellow][WARN] No loot log found.[/yellow]")
        return
    print(f"[green][ OK ] Parsing loot log: {loot_path}[/green]\n")
    loot = parse_loot(loot_path)
    if not loot:
        print("[yellow][WARN] No loot data to analyze.[/yellow]")
        return
    ips, vendors, ports, odd_hosts = summarize_loot(loot)

    table = Table(title="[red]Device Summary[/red]")
    table.add_column("IP", style="bold")
    table.add_column("Vendor", style="red")
    table.add_column("Open Ports", style="yellow")
    for d in loot:
        ip = d.get("ip") or d.get("host") or d.get("address") or "?"
        vendor = d.get("vendor") or d.get("mac_vendor") or "Unknown"
        ports = d.get("ports") or d.get("open_ports") or []
        table.add_row(ip, vendor, ", ".join(map(str, ports)))
    print(table)

    print(f"\n[cyan]Total devices:[/cyan] {len(set(ips))}")
    print(f"[cyan]Vendors detected:[/cyan] {len(set(vendors))} - {', '.join(set(vendors))}")
    if ports:
        port_counts = Counter(ports)
        print(f"[cyan]Most common open ports:[/cyan] " + ", ".join(f"{p}({c})" for p, c in port_counts.most_common(5)))
    if odd_hosts:
        print(f"\n[red][!] Odd hosts flagged:[/red] {', '.join(odd_hosts)}")

    print("\n[green][ OK ] Loot summary complete.\n[/green]")

if __name__ == "__main__":
    main()
