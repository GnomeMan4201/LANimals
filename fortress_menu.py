#!/usr/bin/env python3
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
import os

console = Console()

def show_fortress():
    os.system("clear")
    console.print(Panel("[bold red]LANIMALS FORTRESS[/bold red]\n\n[01] Rogue Scanner\n[02] ARP Watcher\n[03] Stealth Scanner\n[00] Back", border_style="red"))

def launch_fortress(choice):
    match choice:
        case "1" | "01":
            os.system("lanimals roguescan")
        case "2" | "02":
            os.system("lanimals arpwatcher")
        case "3" | "03":
            os.system("lanimals stealthscan")
        case "0" | "00":
            return True
        case _:
            console.print("[bold red][!] Invalid selection[/bold red]\n")
    return False

def main():
    while True:
        show_fortress()
        choice = Prompt.ask("\n[bold orange3]> SELECT DEFENSE MODULE[/bold orange3]")
        if launch_fortress(choice.strip()):
            break

if __name__ == "__main__":
    main()
