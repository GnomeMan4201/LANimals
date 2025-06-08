#!/usr/bin/env python3
import os
import requests
from rich import print, box
from rich.table import Table

VIRUSTOTAL_API = os.environ.get("VT_API_KEY", "")

def vt_lookup(ip):
    if not VIRUSTOTAL_API:
        return None, None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API}
    try:
        r = requests.get(url, headers=headers, timeout=6)
        if r.ok:
            j = r.json()
            last_analysis = j["data"]["attributes"]["last_analysis_stats"]
            reputation = j["data"]["attributes"]["reputation"]
            return last_analysis, reputation
    except Exception:
        return None, None
    return None, None

def main():
    print("[bold red]\nLANimals Live Threat Intel Enrichment\n[/bold red]")
    ips = []
    import psutil
    conns = psutil.net_connections(kind='inet')
    for c in conns:
        if c.raddr:
            ips.append(c.raddr[0])
    ips = list(set([ip for ip in ips if "." in ip]))
    if not ips:
        print("[yellow][WARN] No active IPs to enrich.[/yellow]")
        return
    table = Table(title="[red]Live Threat Intel[/red]", box=box.ROUNDED)
    table.add_column("IP", style="bold")
    table.add_column("VT Detections", style="red")
    table.add_column("Reputation", style="yellow")
    for ip in ips:
        stats, rep = vt_lookup(ip)
        if stats:
            table.add_row(ip, f"{stats['malicious']}/ {stats['harmless']} benign", str(rep))
        else:
            table.add_row(ip, "?", "?")
    print(table)
    print("\n[green][ OK ] Live enrichment complete.\n[/green]")

if __name__ == "__main__":
    main()
