#!/usr/bin/env python3
import time

from rich.console import Console

BANNERS = [
    "██╗      █████╗ ███╗   ██╗██╗███╗   ███╗ █████╗ ██╗",
    "██║     ██╔══██╗████╗  ██║██║████╗ ████║██╔══██╗██║",
    "██║     ███████║██╔██╗ ██║██║██╔████╔██║███████║██║",
    "██║     ██╔══██║██║╚██╗██║██║██║╚██╔╝██║██╔══██║██║",
    "███████╗██║  ██║██║ ╚████║██║██║ ╚═╝ ██║██║  ██║███████╗",
    "╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝",
]


def main():
    console = Console()
    console.print("[bold cyan]Rotating LANimals ASCII Art...[/bold cyan]\n")
    for _ in range(3):
        for b in BANNERS:
            console.clear()
            console.print(f"[bold green]{b}[/bold green]")
            time.sleep(0.2)
    console.print("\n[bold green][ OK ][/bold green] ASCII roll complete.\n")


if __name__ == "__main__":
    main()
