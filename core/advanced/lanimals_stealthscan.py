#!/usr/bin/env python3
import os

from rich.console import Console

console = Console()


def main():
    console.print(
        "[] StealthScanner: TCP SYN stealth scan active...", style="bold red"
    )
    os.system("nmap -sS 192.168.1.0/24 | grep open")


if __name__ == "__main__":
    main()
