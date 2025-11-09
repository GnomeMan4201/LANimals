import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

def show_nexus_menu():
    # Banner
    banner = Text("""
                    
             
           
          
       
           
""", style="bold red")
    console.print(banner)

    # System
    system = Table(title="[red]SYSTEM COMMANDS[/red]", show_lines=True, box=None)
    system.add_column("Command", style="bold cyan")
    system.add_column("Description", style="white")
    system.add_row("lanimals_dash", "Show LANimals dashboard")
    system.add_row("lanimals_sysinfo", "Analyze system components")
    system.add_row("lanimals_sessionlogger", "Session logger/report generator")

    # Network
    network = Table(title="[red]NETWORK COMMANDS[/red]", show_lines=True, box=None)
    network.add_column("Command", style="bold cyan")
    network.add_column("Description", style="white")
    network.add_row("lanimals_recon", "Autonomous recon")
    network.add_row("lanimals_traffic", "Analyze network traffic")
    network.add_row("lanimals_netmap", "Map network devices visually")
    network.add_row("lanimals_viznet", "Interactive network visualization")
    network.add_row("lanimals_wlanbeacon", "WLAN beacon hunter")

    # Security
    security = Table(title="[red]SECURITY COMMANDS[/red]", show_lines=True, box=None)
    security.add_column("Command", style="bold cyan")
    security.add_column("Description", style="white")
    security.add_row("lanimals_fortress", "Security hardening toolkit")
    security.add_row("lanimals_alert", "Run threat alert system")
    security.add_row("lanimals_vulscan", "Network vulnerability scanner")
    security.add_row("lanimals_roguescan", "Scan for rogue devices")
    security.add_row("lanimals_ghostscan", "Outbound infra detection")
    security.add_row("lanimals_darkwebhost", "Dark web host detector")
    security.add_row("lanimals_threatenrich", "Live threat intel enrichment")
    security.add_row("lanimals_anomalydetector", "Network anomaly detector")

    # Loot & Analytics
    loot = Table(title="[red]LOOT & ANALYTICS COMMANDS[/red]", show_lines=True, box=None)
    loot.add_column("Command", style="bold cyan")
    loot.add_column("Description", style="white")
    loot.add_row("lanimals_lootlog", "View loot log entries")
    loot.add_row("lanimals_lootsummary", "Loot analytics/summarizer")
    loot.add_row("lanimals_tripwire", "Monitor tripwire events")

    # Visuals & Fun
    visuals = Table(title="[red]VISUALS & UTILITIES[/red]", show_lines=True, box=None)
    visuals.add_column("Command", style="bold cyan")
    visuals.add_column("Description", style="white")
    visuals.add_row("lanimals_asciiroll", "Show rotating ASCII banners")
    visuals.add_row("lanimals_dash", "Show LANimals dashboard")

    # General
    general = Table(title="[red]GENERAL[/red]", show_lines=True, box=None)
    general.add_column("Command", style="bold cyan")
    general.add_column("Description", style="white")
    general.add_row("help", "Show this help message")
    general.add_row("version", "Show LANimals version")
    general.add_row("update", "Check for updates")

    # Output menu sections
    for section in [system, network, security, loot, visuals, general]:
        console.print(Panel(section, border_style="red", expand=False))

if __name__ == "__main__":
    show_nexus_menu()

import sys

def lanimals_dash():
    print("[*] Launching dashboard...")

def lanimals_vulscan():
    print("[*] Running vulnerability scanner...")

def lanimals_lootlog():
    print("[*] Accessing loot log...")

def show_main_menu():
    print("\n[1] LAN Sweep\n[2] ARP Recon\n[3] Loot Viewer\n[4] Exit")
    choice = input("Select an option: ").strip()
    if choice == "1":
        lanimals_dash()
    elif choice == "2":
        lanimals_vulscan()
    elif choice == "3":
        lanimals_lootlog()
    elif choice == "4":
        print("[] Exiting.")
    else:
        print("[!] Invalid selection.")

if __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "dash":
            lanimals_dash()
        elif cmd == "vulscan":
            lanimals_vulscan()
        elif cmd == "lootlog":
            lanimals_lootlog()
        else:
            print("[!] Unknown command.")
    else:
        show_main_menu()
