#!/usr/bin/env python3
import json
import os

import psutil
from rich import box, print
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


def get_live_connections():
    conns = psutil.net_connections(kind="inet")
    ips = [c.raddr[0] for c in conns if c.raddr]
    return ips


def score(ip):
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return 0  # local
    if ip.startswith("127.") or ip.startswith("::1"):
        return 0
    return 1  # non-local = more suspicious


def main():
    print("[bold red]\nLANimals Network Anomaly Detector\n[/bold red]")
    loot_path = find_loot_file()
    loot_ips = set()
    if loot_path:
        try:
            with open(loot_path) as f:
                data = json.load(f)
            for d in data if isinstance(data, list) else [data]:
                ip = d.get("ip") or d.get("host") or d.get("address")
                if ip:
                    loot_ips.add(ip)
        except Exception:
            pass
    live_ips = get_live_connections()
    flagged = []
    for ip in live_ips:
        if score(ip) and ip not in loot_ips:
            flagged.append(ip)
    if flagged:
        table = Table(
            title="[red]Anomalous Outbound Connections[/red]", box=box.ROUNDED
        )
        table.add_column("IP", style="red")
        for ip in flagged:
            table.add_row(ip)
        print(table)
        print(
            f"\n[red][!!] {len(flagged)} outbound connections NOT seen in loot scan! Possible beaconing or C2.[/red]"
        )
    else:
        print("[green][ OK ] No anomalies detected.\n[/green]")
    print("[cyan][ DONE ] Anomaly detection complete.\n[/cyan]")


if __name__ == "__main__":
    main()
