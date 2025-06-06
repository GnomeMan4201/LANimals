#!/usr/bin/env python3
import os
from rich.console import Console
from rich.table import Table
console = Console()
def dashboard():
    console.clear()
    table = Table(title="LANIMALS :: LIVE DASHBOARD", style="cyan")
    table.add_column("Stat", style="green")
    table.add_column("Value", style="magenta")
    table.add_row("CPU Load", os.popen("uptime | awk -F'load average:' '{print $2}'").read().strip(),)
    table.add_row("Uptime", os.popen("uptime -p").read().strip())
    table.add_row("RAM Usage", os.popen("free -h | awk '/Mem:/ {print $3"/"$2}'").read().strip())
    table.add_row("Active Hosts", str(len(os.popen("arp -a").readlines())))
    console.print(table)
if __name__ == "__main__":
    dashboard()
