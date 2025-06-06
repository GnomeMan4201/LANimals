#!/usr/bin/env python3
import os
from rich.console import Console
from rich.panel import Panel

console = Console()

def main():
    console.print(Panel("[bold green]LANIMALS NETMAP VISUALIZER[/bold green]\n\nRunning subnet probe + MAC/org mapping...\n", border_style="green"))
    os.system("nmap -sn 192.168.1.0/24 | grep 'Nmap scan report\\|MAC Address'")

if __name__ == "__main__":
    main()
