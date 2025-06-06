#!/usr/bin/env python3
import os, time
from rich import print
from rich.panel import Panel

def main():
    print(Panel("Running Ghostscan: Passive Outbound Profiler", style="bold magenta"))
    if not os.path.exists("/tmp/loot.log"):
        print("[✗] No loot.log file found.")
    else:
        with open("/tmp/loot.log", "r") as f:
            for line in f:
                print("[event] " + line.strip())

if __name__ == "__main__":
    main()
