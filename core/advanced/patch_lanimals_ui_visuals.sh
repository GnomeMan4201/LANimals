#!/bin/bash

echo "[] Installing visual libraries..."
pip install -q rich pyfiglet

echo "[] Patching LANimals UI visuals..."

tee ~/LANimals/lanimals_ui_FIXED.py >/dev/null <<'PYEOF'
#!/usr/bin/env python3
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from pyfiglet import Figlet
import os

console = Console()

def draw_banner():
    fig = Figlet(font='slant')
    banner = fig.renderText("LANIMALS")
    console.print(f"[bold green]{banner}[/bold green]")
    console.print("[bold cyan]LANIMALS v1.0  NETWORK OPS TOOL[/bold cyan]", style="dim")
    console.print(f"[bold red]CTX_ID:[/bold red] ghost://SIMHOST/3899   [bold green]INTEGRITY:[/bold green] OK\n")

def build_module_table():
    table = Table(title="Available Modules", style="bold white", border_style="blue")
    table.add_column("Module ID", style="bold cyan", justify="center")
    table.add_column("Function", style="green", justify="center")
    table.add_column("Description", style="magenta", justify="left")

    table.add_row("01", "scan.interface", "Identify active interfaces")
    table.add_row("02", "probe.subnet", "Broadcast local sweep")
    table.add_row("03", "analyze.traffic", "Passive flow extraction")
    table.add_row("04", "view.lootlog", "Parse exfiltration cache")
    table.add_row("05", "sys.diagnostics", "Gather host intel")
    table.add_row("00", "exit", "Terminate node session")
    return table

def run_module(choice):
    if choice == "01":
        console.print("\n Scanning active interfaces...", style="bold yellow")
        os.system("ip addr | grep inet")
    elif choice == "02":
        console.print("\n Probing local subnet...", style="bold yellow")
        os.system("nmap -sn 192.168.1.0/24 | grep 'Nmap scan report\|MAC Address'")
    elif choice == "03":
        console.print("\n Starting passive traffic capture...", style="bold yellow")
        os.system("sudo timeout 10 tcpdump -i any -nn -q")
    elif choice == "04":
        console.print("\n Viewing lootlog...", style="bold yellow")
        try:
            with open("loot.log", "r") as f:
                for line in f:
                    console.print(line.strip(), style="bold white")
        except FileNotFoundError:
            console.print("[] Loot directory not found: loot.log", style="bold red")
    elif choice == "05":
        console.print("\n Gathering host diagnostics...", style="bold yellow")
        os.system("uname -a && uptime")
    elif choice == "00":
        console.print(">> TERMINATING NODE SESSION...", style="bold red")
        exit()
    else:
        console.print("Invalid selection. Try again.\n", style="bold red")

def main():
    os.system("clear")
    draw_banner()
    table = build_module_table()
    console.print(table)

    while True:
        choice = Prompt.ask("\n[bold blue]> SELECT MODULE[/bold blue]")
        run_module(choice.strip())

if __name__ == "__main__":
    main()
PYEOF

chmod +x ~/LANimals/lanimals_ui_FIXED.py && echo "[] UI visuals successfully patched."
