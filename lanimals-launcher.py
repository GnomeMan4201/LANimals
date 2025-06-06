#!/usr/bin/env python3
# LANimals Launcher
# Author: NMAPKin

import os
import subprocess
from lanimals_utils import banner, print_status, prompt_menu

MODULES = {
    "LAN Sweep": "modules/lan_sweep.py",
    "ARP Recon": "modules/arp_recon.py",
    "Net Scan": "modules/net_scan.py",
    "Service Fingerprint": "modules/service_fingerprint.py",
    "Loot Viewer": "modules/loot_viewer.py",
    "Loot Exporter": "modules/loot_export.py",
    "Tripwire Monitor": "modules/tripwire_monitor.py",
    "Live Traffic Tap": "modules/traffic_tap.py",
    "Host Mapper": "modules/host_mapper.py",
    "HTTP Probe": "modules/http_probe.py"
}

def run_module(script_path):
    if not os.path.exists(script_path):
        print_status(f"Script not found: {script_path}", "✗")
        return
    print_status(f"Running: {script_path}")
    subprocess.run(["python3", script_path])

def main():
    banner("LANimals 🧠")
    while True:
        choice = prompt_menu(list(MODULES.keys()) + ["Exit"])
        if choice == len(MODULES) + 1:
            print_status("Goodbye.", "✓")
            break
        elif 1 <= choice <= len(MODULES):
            key = list(MODULES.keys())[choice - 1]
            run_module(MODULES[key])
        else:
            print_status("Invalid selection", "!")

if __name__ == "__main__":
    main()
