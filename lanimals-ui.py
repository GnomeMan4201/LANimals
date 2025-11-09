#!/usr/bin/env python3
# LANimals Legacy UI
# Author: NMAPKin

import os
import subprocess

from lanimals_utils import banner, print_status, prompt_menu

LEGACY = {
    "LAN Sweep": "modules/lan_sweep.py",
    "ARP Recon": "modules/arp_recon.py",
    "Net Scan": "modules/net_scan.py",
    "Loot Viewer": "modules/loot_viewer.py",
}


def launch(script):
    if os.path.exists(script):
        print_status(f"Launching: {script}")
        subprocess.run(["python3", script])
    else:
        print_status(f"Missing: {script}", "✗")


def main():
    banner("LANimals :: UI")
    while True:
        opt = prompt_menu(list(LEGACY.keys()) + ["Exit"])
        if opt == len(LEGACY) + 1:
            print_status("Exiting UI.", "✓")
            break
        elif 1 <= opt <= len(LEGACY):
            launch(LEGACY[list(LEGACY.keys())[opt - 1]])
        else:
            print_status("Invalid selection", "!")


if __name__ == "__main__":
    main()
