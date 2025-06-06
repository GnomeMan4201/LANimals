#!/usr/bin/env python3
import os
from rich.console import Console
console = Console()

def main():
    console.print("[✓] ARPWatcher: Tracking ARP anomalies on LAN...\n", style="yellow")
    console.print("[•] ARP sniffing... press Ctrl+C to stop.", style="cyan")
    os.system("sudo tcpdump -l -i wlan0 arp")

if __name__ == "__main__":
    main()
