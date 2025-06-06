#!/usr/bin/env python3
import os
from rich.console import Console
console = Console()

def main():
    console.print("[✓] Autopilot Initiated...\n", style="bold green")
    console.print("→ Running interface scan...", style="yellow")
    os.system("ip addr | grep inet")
    console.print("→ Subnet probing...", style="yellow")
    os.system("nmap -sn 192.168.1.0/24 -oG /tmp/loot.log")
    console.print("→ Ghostscan passive recon...", style="yellow")
    os.system("python3 ~/LANimals/core/advanced/lanimals_ghostscan.py")
    console.print("\n[✓] Autopilot completed.", style="green")

if __name__ == "__main__":
    main()
