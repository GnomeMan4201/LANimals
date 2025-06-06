#!/usr/bin/env python3
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from datetime import datetime

console = Console()

def clear_screen():
    os.system("clear")

def draw_header():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    panel = Panel(
        f"[bold green]LANIMALS :: NEXUS[/bold green]\n[white]Session Time: {timestamp}[/white]",
        style="green",
        border_style="bright_green",
        padding=(1, 2),
    )
    console.print(panel)

def build_main_menu():
    table = Table(show_header=True, header_style="bold cyan", border_style="green")
    table.add_column("ID", style="bold white", justify="center")
    table.add_column("Module", style="bold yellow")
    table.add_column("Action", style="white")

    menu_items = [
        ("1", "LAN Sweep", "Interface & Subnet Discovery"),
        ("2", "Rogue Scan", "Detect Foreign Hosts"),
        ("3", "Traffic Flow", "Passive Traffic Intel"),
        ("4", "ARP Monitor", "Watch ARP Shifts in Real Time"),
        ("5", "Threat Grid", "Simulated Threat Heatmap"),
        ("6", "Loot Viewer", "Open Recon Cache"),
        ("7", "System Intel", "Node Diagnostics"),
        ("8", "Darkviz Mode", "ASCII HUD Rotation"),
        ("0", "Exit", "Terminate Node Session")
    ]

    for item in menu_items:
        table.add_row(*item)
    return table

def route_module(choice):
    routes = {
        "1": "lanimals autopilot",
        "2": "lanimals roguescan",
        "3": "lanimals traffic",
        "4": "lanimals arpwatcher",
        "5": "lanimals threatmap",
        "6": "lanimals lootview",
        "7": "lanimals sysinfo",
        "8": "lanimals asciiroll"
    }

    command = routes.get(choice.strip())
    if command:
        console.print(f"[cyan]Launching module:[/cyan] [bold]{command}[/bold]")
        os.system(command)
    elif choice.strip() == "0":
        console.print("[bold red]Exiting LANIMALS Nexus...[/bold red]")
        exit()
    else:
        console.print("[bold red]Invalid choice. Try again.[/bold red]")

def main():
    while True:
        clear_screen()
        draw_header()
        console.print(build_main_menu())
        choice = Prompt.ask("[bold green]> SELECT MODULE[/bold green]")
        route_module(choice)

if __name__ == "__main__":
    main()
