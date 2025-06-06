#!/usr/bin/env python3
from rich.console import Console
console = Console()

def main():
    console.print("[✓] Generating LANimals Operation Timeline...\n", style="green")
    try:
        with open("/tmp/loot.log", "r") as f:
            for line in f:
                console.print("[event] " + line.strip())
    except FileNotFoundError:
        console.print("[✗] No target data found. Run autopilot or subnet probe first.", style="red")

if __name__ == "__main__":
    main()
