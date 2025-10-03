#!/usr/bin/env python3
import socket

import psutil
import requests
from rich import print

THREAT_ORGS = [
    "Amazon",
    "DigitalOcean",
    "OVH",
    "Hetzner",
    "Google",
    "Alibaba",
    "Microsoft",
    "LeaseWeb",
    "Vultr",
    "Linode",
    "Scaleway",
    "DataWeb",
    "Shodan",
    "Zenlayer",
    "HostHatch",
    "G-Core",
    "Choopa",
    "Censys",
    "NetActuate",
    "Contabo",
    "Tzulo",
    "Tencent",
    "Xiaomi",
    "Alibaba",
    "Tencent",
]


def get_remote_ips():
    """Return a set of all current remote IPs with outbound TCP connections."""
    ips = set()
    for c in psutil.net_connections(kind="inet"):
        if c.status == "ESTABLISHED" and c.raddr:
            try:
                ip = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
                if ip and not ip.startswith("127.") and ":" not in ip:
                    ips.add(ip)
            except Exception:
                continue
    return ips


def rdap_lookup(ip):
    try:
        r = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=2)
        if r.ok:
            data = r.json()
            org = (
                data.get("name")
                or data.get("entitySearchResults", [{}])[0].get(
                    "vcardArray", [["", []]]
                )[1][1]
            )
            return org
    except Exception:
        return None


def main():
    print("[bold red]\nLANimals GhostScan – Outbound Infra Detection[/bold red]\n")
    print("[red][ SCAN ] Checking live outbound TCP connections...\n[/red]")
    found = False
    for ip in sorted(get_remote_ips()):
        org = rdap_lookup(ip)
        orgstr = f"[yellow]{org}[/yellow]" if org else "[grey]Unknown[/grey]"
        if org and any(threat in org for threat in THREAT_ORGS):
            print(f"[red][ALERT] Suspicious org: {orgstr} - {ip}[/red]")
            found = True
        else:
            print(f"[white][INFO] {orgstr} - {ip}[/white]")
    if not found:
        print(
            "\n[green][ OK ] No suspicious orgs flagged. All outbound infra appears normal.[/green]"
        )
    print("[red]\n[ DONE ] GhostScan Complete.\n[/red]")


if __name__ == "__main__":
    main()
