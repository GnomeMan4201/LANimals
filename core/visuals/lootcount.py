#!/usr/bin/env python3
from rich.console import Console
from rich.panel import Panel
import os

def count_loot_entries(log_path="/home/nmapkin/LANimals/loot.log"):
    try:
        with open(log_path, "r") as f:
            return sum(1 for line in f if "Status: Up" in line)
    except FileNotFoundError:
        return 0

def main():
    console = Console()
    console.clear()
    console.print("[bold yellow]LANIMALS LOOT COUNT[/bold yellow]")
    total = count_loot_entries()
    console.print(Panel(f"[✓] Total Devices Logged: {total}", border_style="yellow"))

if __name__ == "__main__":
    main()
