#!/usr/bin/env python3
import os

from rich.console import Console

console = Console()


def main():
    console.print("[] RogueScanner running...\n", style="bold magenta")
    os.system("nmap -sn 192.168.1.0/24 | grep MAC | sort | uniq")


if __name__ == "__main__":
    main()
