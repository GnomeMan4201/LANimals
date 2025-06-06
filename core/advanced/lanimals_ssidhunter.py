#!/usr/bin/env python3
import os
from rich.console import Console
console = Console()

def main():
    console.print("[✓] SSID Hunter: Capturing broadcasted wireless IDs...\n", style="bold blue")
    os.system("sudo iwlist wlan0 scanning | grep 'ESSID:'")

if __name__ == "__main__":
    main()
