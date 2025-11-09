import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
import platform

import psutil
from rich.console import Console
from rich.panel import Panel


def show_banner():
    banner = """
██╗      █████╗ ███╗   ██╗██╗███╗   ███╗ █████╗ ██╗     
██║     ██╔══██╗████╗  ██║██║████╗ ████║██╔══██╗██║     
██║     ███████║██╔██╗ ██║██║██╔████╔██║███████║██║     
██║     ██╔══██║██║╚██╗██║██║██║╚██╔╝██║██╔══██║██║     
███████╗██║  ██║██║ ╚████║██║██║ ╚═╝ ██║██║  ██║███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
                 SYSTEM ANALYZER
"""
    return banner


def main():
    console = Console()
    console.print(Panel(show_banner(), style="cyan"))
    console.print("[bold green][ INIT ][/bold green] System Analysis Initializing...\n")

    # OS and basic info
    uname = platform.uname()
    console.print(
        f"[bold cyan]OS:[/bold cyan] {uname.system} {uname.release} ({uname.version})"
    )
    console.print(f"[bold cyan]Node:[/bold cyan] {uname.node}")
    console.print(f"[bold cyan]Architecture:[/bold cyan] {uname.machine}\n")

    # CPU
    cpu = psutil.cpu_percent(interval=1)
    cpu_cores = psutil.cpu_count(logical=False)
    cpu_threads = psutil.cpu_count(logical=True)
    console.print(
        f"[bold magenta]CPU:[/bold magenta] Usage: {cpu}% | Cores: {cpu_cores} | Threads: {cpu_threads}"
    )

    # Memory
    mem = psutil.virtual_memory()
    console.print(
        f"[bold magenta]Memory:[/bold magenta] {mem.percent}% used | {mem.used//(1024**2)}MB / {mem.total//(1024**2)}MB\n"
    )

    # Disk
    disk = psutil.disk_usage("/")
    console.print(
        f"[bold magenta]Disk:[/bold magenta] {disk.percent}% used | {disk.used//(1024**3)}GB / {disk.total//(1024**3)}GB\n"
    )

    # Network
    net = psutil.net_if_addrs()
    console.print("[bold yellow]Network Interfaces:[/bold yellow]")
    for iface, addrs in net.items():
        for addr in addrs:
            if addr.family.name == "AF_INET":
                console.print(f"    {iface}: {addr.address}")

    # Top processes by memory
    console.print("\n[bold yellow]Top Processes by Memory:[/bold yellow]")
    procs = [
        (p.info["name"], p.info["memory_info"].rss)
        for p in psutil.process_iter(["name", "memory_info"])
    ]
    top_procs = sorted(procs, key=lambda x: x[1], reverse=True)[:5]
    for name, mem_bytes in top_procs:
        console.print(f"    {name}: {mem_bytes//(1024**2)}MB")

    console.print("\n[bold green][ OK ][/bold green] System analysis complete.\n")


if __name__ == "__main__":
    main()
