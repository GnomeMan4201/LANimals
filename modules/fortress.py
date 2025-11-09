import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
import os

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()


def main():
    os.system("clear")
    console.print(
        Panel(
            "[bold red]LANIMALS FORTRESS[/bold red]\n\n[01] Rogue Scanner\n[02] ARP Watcher\n[03] Stealth Scanner\n[00] Back",
            border_style="red",
        )
    )
    while True:
        choice = Prompt.ask("[bold yellow]> SELECT DEFENSE MODULE[/bold yellow]")
        if choice == "01":
            os.system("lanimals roguescan")
        elif choice == "02":
            os.system("lanimals arpwatcher")
        elif choice == "03":
            os.system("lanimals stealthscan")
        elif choice == "00":
            break
        else:
            console.print("Invalid selection.", style="bold red")


if __name__ == "__main__":
    main()
