#!/usr/bin/env python3
import os
import sys

# Ensure the current directory is in the import path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from lanimals_nexus import show_main_menu

if __name__ == "__main__":
    print("[✓] Launching LANimals core (Termux Mode)...")
    show_main_menu()
