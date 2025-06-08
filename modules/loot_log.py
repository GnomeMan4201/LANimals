#!/usr/bin/env python3
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

def show_banner():
    return '''
██╗      █████╗ ███╗   ██╗██╗███╗   ███╗ █████╗ ██╗     
██║     ██╔══██╗████╗  ██║██║████╗ ████║██╔══██╗██║     
██║     ███████║██╔██╗ ██║██║██╔████╔██║███████║██║     
██║     ██╔══██║██║╚██╗██║██║██║╚██╔╝██║██╔══██║██║     
███████╗██║  ██║██║ ╚████║██║██║ ╚═╝ ██║██║  ██║███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
                   LOOT VIEWER
'''

def main():
    console = Console()
    console.print(Panel(show_banner(), style="cyan"))
    loot_path = Path.home() / ".lanimals" / "data" / "loot.log"
    if loot_path.exists():
        console.print(f"[bold green][ OK ][/bold green] Showing recent loot from [white]{loot_path}[/white]:\n")
        for line in loot_path.read_text().splitlines()[-20:]:
            console.print(line)
    else:
        console.print("[bold red][ WARN ][/bold red] No loot log found.")
    console.print("\n[bold green][ OK ][/bold green] Loot viewing complete.\n")

if __name__ == "__main__":
    main()
