#!/usr/bin/env python3
# LANimals :: Loot Logger
# Author: NMAPKin

import os
from datetime import datetime
from lanimals_utils import banner, print_status

LOOT_FILE = "loot/loot_notes.log"
os.makedirs("loot", exist_ok=True)

def log_loot(note):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOOT_FILE, "a") as f:
        f.write(f"[{now}] {note}\n")
    print_status("Loot entry saved.", "✓")

def main():
    banner("LANimals :: Loot Logger")
    print_status("Record valuable findings, creds, hashes, etc.")
    while True:
        note = input("📝 Note (or type 'exit'): ").strip()
        if note.lower() in ["exit", "quit"]:
            print_status("Exiting Loot Logger.")
            break
        if note:
            log_loot(note)

if __name__ == "__main__":
    main()
