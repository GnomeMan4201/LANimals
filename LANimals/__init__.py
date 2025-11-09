#!/usr/bin/env python3
"""
LANimals - Real-time Network Intelligence Suite
Command-line interface for authorized security testing and network reconnaissance
"""

import sys
from typing import Dict, Callable

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Command registry mapping command names to their module paths
COMMANDS: Dict[str, Dict] = {
    # Reconnaissance commands
    "recon": {
        "module": "modules.arp_recon",
        "desc": "Run ARP reconnaissance on local network",
        "category": "Reconnaissance"
    },
    "arp-recon": {
        "module": "modules.arp_recon",
        "desc": "Run ARP reconnaissance on local network",
        "category": "Reconnaissance"
    },
    "arp-hunter": {
        "module": "modules.arp_hunter",
        "desc": "Hunt for devices using ARP scanning",
        "category": "Reconnaissance"
    },
    "ping-sweep": {
        "module": "modules.ping_sweep",
        "desc": "Perform ping sweep across subnet",
        "category": "Reconnaissance"
    },
    "lan-sweep": {
        "module": "modules.lan_sweep",
        "desc": "Comprehensive LAN sweep",
        "category": "Reconnaissance"
    },

    # Scanning commands
    "scan": {
        "module": "modules.net_scan",
        "desc": "Run network port scan",
        "category": "Scanning"
    },
    "net-scan": {
        "module": "modules.net_scan",
        "desc": "Run network port scan",
        "category": "Scanning"
    },
    "mass-scan": {
        "module": "modules.mass_scan",
        "desc": "Perform mass network scanning",
        "category": "Scanning"
    },
    "inventory-scan": {
        "module": "modules.inventory_scan",
        "desc": "Scan and inventory network devices",
        "category": "Scanning"
    },
    "interface-scan": {
        "module": "modules.interface_scan",
        "desc": "Scan network interfaces",
        "category": "Scanning"
    },
    "ghostscan": {
        "module": "modules.ghostscan",
        "desc": "Stealthy network scanning",
        "category": "Scanning"
    },
    "roguescan": {
        "module": "modules.roguescan",
        "desc": "Scan for rogue devices",
        "category": "Scanning"
    },

    # Analysis and mapping
    "host-mapper": {
        "module": "modules.host_mapper",
        "desc": "Map discovered hosts",
        "category": "Analysis"
    },
    "netmap": {
        "module": "modules.netmap",
        "desc": "Generate network map",
        "category": "Analysis"
    },
    "http-probe": {
        "module": "modules.http_probe",
        "desc": "Probe HTTP services",
        "category": "Analysis"
    },
    "service-fingerprint": {
        "module": "modules.service_fingerprint",
        "desc": "Fingerprint network services",
        "category": "Analysis"
    },
    "sysinfo": {
        "module": "modules.sysinfo",
        "desc": "Gather system information",
        "category": "Analysis"
    },

    # Loot and reporting
    "loot": {
        "module": "modules.loot_viewer",
        "desc": "View collected loot/data",
        "category": "Reporting"
    },
    "loot-viewer": {
        "module": "modules.loot_viewer",
        "desc": "View collected loot/data",
        "category": "Reporting"
    },
    "loot-log": {
        "module": "modules.loot_log",
        "desc": "Log loot data",
        "category": "Reporting"
    },
    "loot-export": {
        "module": "modules.loot_export",
        "desc": "Export loot data",
        "category": "Reporting"
    },
    "loot-summary": {
        "module": "modules.lootsummary",
        "desc": "Display loot summary",
        "category": "Reporting"
    },
    "alive-report": {
        "module": "modules.alive_report",
        "desc": "Generate alive hosts report",
        "category": "Reporting"
    },

    # Monitoring and detection
    "watchdog": {
        "module": "core.lanimals_watchdog",
        "desc": "Monitor network for changes",
        "category": "Monitoring"
    },
    "tripwire": {
        "module": "modules.tripwire_monitor",
        "desc": "Monitor for intrusions",
        "category": "Monitoring"
    },
    "traffic-tap": {
        "module": "modules.traffic_tap",
        "desc": "Tap network traffic",
        "category": "Monitoring"
    },
    "anomaly-detector": {
        "module": "modules.anomalydetector",
        "desc": "Detect network anomalies",
        "category": "Monitoring"
    },
    "session-logger": {
        "module": "modules.sessionlogger",
        "desc": "Log session activity",
        "category": "Monitoring"
    },

    # Advanced features
    "autopilot": {
        "module": "modules.autopilot",
        "desc": "Run automated reconnaissance",
        "category": "Advanced"
    },
    "fortress": {
        "module": "modules.fortress",
        "desc": "Network fortress mode",
        "category": "Advanced"
    },
    "timeline": {
        "module": "core.lanimals_timeline",
        "desc": "Generate activity timeline",
        "category": "Advanced"
    },
    "threat-enrich": {
        "module": "modules.threatenrich",
        "desc": "Enrich threat intelligence",
        "category": "Advanced"
    },

    # Wireless
    "wlan-beacon": {
        "module": "modules.wlanbeacon",
        "desc": "Monitor WLAN beacons",
        "category": "Wireless"
    },

    # UI/Visualization
    "ui": {
        "module": "lanimals-ui",
        "desc": "Launch LANimals web UI",
        "category": "Visualization"
    },
    "ascii": {
        "module": "modules.asciiroll",
        "desc": "Display ASCII visualization",
        "category": "Visualization"
    },
}


def print_banner():
    """Print LANimals ASCII banner"""
    banner = f"""{Colors.OKCYAN}
    ██╗      █████╗ ███╗   ██╗██╗███╗   ███╗ █████╗ ██╗     ███████╗
    ██║     ██╔══██╗████╗  ██║██║████╗ ████║██╔══██╗██║     ██╔════╝
    ██║     ███████║██╔██╗ ██║██║██╔████╔██║███████║██║     ███████╗
    ██║     ██╔══██║██║╚██╗██║██║██║╚██╔╝██║██╔══██║██║     ╚════██║
    ███████╗██║  ██║██║ ╚████║██║██║ ╚═╝ ██║██║  ██║███████╗███████║
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
    {Colors.ENDC}
    {Colors.BOLD}Real-time Network Intelligence Suite{Colors.ENDC}
    {Colors.WARNING}For Authorized Security Testing Only{Colors.ENDC}
    """
    print(banner)


def print_help():
    """Print help information with all available commands"""
    print_banner()
    print(f"\n{Colors.BOLD}Usage:{Colors.ENDC}")
    print(f"  LANimals <command> [options]")
    print(f"  lanimals <command> [options]")
    print(f"\n{Colors.BOLD}Available Commands:{Colors.ENDC}\n")

    # Group commands by category
    categories = {}
    for cmd, info in sorted(COMMANDS.items()):
        category = info["category"]
        if category not in categories:
            categories[category] = []
        categories[category].append((cmd, info["desc"]))

    # Print commands grouped by category
    for category in sorted(categories.keys()):
        print(f"{Colors.OKBLUE}{Colors.BOLD}{category}:{Colors.ENDC}")
        for cmd, desc in sorted(categories[category]):
            print(f"  {Colors.OKGREEN}{cmd:<20}{Colors.ENDC} {desc}")
        print()

    print(f"{Colors.BOLD}Examples:{Colors.ENDC}")
    print(f"  LANimals recon              # Run ARP reconnaissance")
    print(f"  LANimals ping-sweep         # Perform ping sweep")
    print(f"  LANimals scan               # Run network scan")
    print(f"  LANimals loot               # View collected data")
    print(f"  LANimals ui                 # Launch web interface")
    print(f"\n{Colors.WARNING}Note: Some commands require root/sudo privileges{Colors.ENDC}\n")


def run_command(command: str):
    """Execute a LANimals command"""
    if command in COMMANDS:
        cmd_info = COMMANDS[command]
        module_path = cmd_info["module"]

        print(f"{Colors.OKBLUE}[*] {cmd_info['desc']}...{Colors.ENDC}\n")

        try:
            # Import and run the module
            if "." in module_path:
                # Module with package (e.g., modules.arp_recon)
                parts = module_path.rsplit(".", 1)
                package = parts[0]
                module = parts[1]
                exec(f"from {package} import {module}")

                # Try to run main() if it exists, otherwise try run()
                try:
                    exec(f"{module}.main()")
                except AttributeError:
                    try:
                        exec(f"{module}.run()")
                    except AttributeError:
                        print(f"{Colors.FAIL}[!] Module '{module}' has no main() or run() function{Colors.ENDC}")
            else:
                # Direct module import
                exec(f"import {module_path}")
                try:
                    exec(f"{module_path}.main()")
                except AttributeError:
                    print(f"{Colors.FAIL}[!] Module has no main() function{Colors.ENDC}")

        except ImportError as e:
            print(f"{Colors.FAIL}[!] Error importing module '{module_path}': {e}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error running command: {e}{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}[!] Unknown command: {command}{Colors.ENDC}")
        print(f"{Colors.WARNING}Run 'LANimals help' to see available commands{Colors.ENDC}")


def main():
    """Main entry point for LANimals CLI"""
    args = sys.argv[1:]

    if not args or args[0] in ["help", "-h", "--help"]:
        print_help()
        return

    command = args[0].lower()

    # Handle special commands
    if command == "version":
        try:
            with open("VERSION", "r") as f:
                version = f.read().strip()
            print(f"LANimals version {version}")
        except:
            print("LANimals version 1.0.0")
        return

    # Run the requested command
    run_command(command)


if __name__ == "__main__":
    main()
