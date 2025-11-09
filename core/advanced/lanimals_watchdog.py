#!/usr/bin/env python3
import os

from rich.console import Console

console = Console()


def main():
    console.print(
        "[✓] Gathering system info + uptime + running processes...\n", style="bold cyan"
    )
    os.system("uptime")
    os.system("top -b -n 1 | head -20")


if __name__ == "__main__":
    main()
