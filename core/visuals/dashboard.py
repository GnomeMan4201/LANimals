#!/usr/bin/env python3
import os

from rich.console import Console
from rich.table import Table


def get_uptime():
    with open("/proc/uptime", "r") as f:
        uptime_seconds = float(f.readline().split()[0])
        return int(uptime_seconds // 3600), int((uptime_seconds % 3600) // 60)


def main():
    console = Console()
    console.clear()
    console.print("[bold cyan]LANIMALS DASHBOARD[/bold cyan]")
    hours, minutes = get_uptime()
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Metric", justify="right")
    table.add_column("Value", justify="left")
    table.add_row("Uptime", f"{hours}h {minutes}m")
    table.add_row("Logged In User", os.getenv("USER"))
    os.system("uptime -p")
    console.print(table)


if __name__ == "__main__":
    main()
