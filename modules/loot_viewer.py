#!/usr/bin/env python3
# LANimals :: Loot Viewer
# Author: NMAPKin

import os
from lanimals_utils import banner, print_status, log_event

LOOT_DIR = "loot"

def list_loot():
    if not os.path.exists(LOOT_DIR):
        print_status(f"Loot directory not found: {LOOT_DIR}", "✗")
        return

    files = os.listdir(LOOT_DIR)
    if not files:
        print_status("Loot folder is empty.", "!")
        return

    print_status(f"Found {len(files)} loot item(s):")
    for file in files:
        log_event(f"📦 {file}")

def main():
    banner("LANimals :: Loot Viewer")
    list_loot()

if __name__ == "__main__":
    main()

def run():
    print("Running loot_viewer")
