#!/usr/bin/env python3
import os

from rich.console import Console
from rich.panel import Panel

console = Console()


def main():
    os.system("clear")
    console.print(
        Panel(
            "[bold green]LANIMALS NETMAP VISUALIZER[/bold green]\n\nRunning subnet probe + MAC/org mapping...\n",
            border_style="green",
        )
    )
    os.system("lanimals linkmap")


if __name__ == "__main__":
    main()
