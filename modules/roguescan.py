#!/usr/bin/env python3
import psutil, socket
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
                 ROGUE SCANNER
'''

def main():
    console = Console()
    console.print(Panel(show_banner(), style="cyan"))
    interfaces = psutil.net_if_addrs()
    console.print("[bold green][ INIT ][/bold green] Scanning local interfaces for rogue devices...\n")
    found = False
    for iface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family.name == "AF_INET" and not addr.address.startswith("127."):
                try:
                    hostname = socket.gethostbyaddr(addr.address)[0]
                except Exception:
                    hostname = "Unknown"
                if "rogue" in hostname.lower():
                    console.print(f"[bold red][ ALERT ][/bold red] Rogue device detected: {addr.address} ({hostname})")
                    found = True
    if not found:
        console.print("[bold green][ OK ][/bold green] No rogue devices found.\n")

if __name__ == "__main__":
    main()
