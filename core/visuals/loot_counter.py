#!/usr/bin/env python3
from rich import print
def loot_summary():
    try:
        with open("loot.log", "r") as f:
            lines = f.readlines()
            total = len(lines)
            risks = len([x for x in lines if "Suspicious" in x])
        print(f"[bold green]✓ Total entries:[/bold green] {total}")
        print(f"[bold red]! Suspicious:[/bold red] {risks}")
    except:
        print("[✗] Loot file not found.")
if __name__ == "__main__":
    loot_summary()
