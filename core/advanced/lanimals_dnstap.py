#!/usr/bin/env python3
import os

from rich.console import Console

console = Console()


def main():
    console.print("[] Passive DNS Tap: Observing DNS queries...\n", style="cyan")
    os.system("sudo tcpdump -l -i wlan0 port 53")


if __name__ == "__main__":
    main()
