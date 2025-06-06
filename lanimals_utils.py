#!/usr/bin/env python3
# LANimals :: Shared Utilities
# Author: NMAPKin

import os
import sys
import time
from datetime import datetime

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"

def banner(title):
    print(f"""
{CYAN}██╗      █████╗ ███╗   ██╗██╗███╗   ███╗ █████╗ ██╗     
██║     ██╔══██╗████╗  ██║██║████╗ ████║██╔══██╗██║     
██║     ███████║██╔██╗ ██║██║██╔████╔██║███████║██║     
██║     ██╔══██║██║╚██╗██║██║██║╚██╔╝██║██╔══██║██║     
███████╗██║  ██║██║ ╚████║██║██║ ╚═╝ ██║██║  ██║███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
{RESET}                      {title}
""")

def print_status(message, status="✓"):
    symbols = {
        "!": f"{YELLOW}[!]{RESET}",
        "-": f"{RED}[-]{RESET}",
        "✓": f"{GREEN}[✓]{RESET}",
        "✗": f"{RED}[✗]{RESET}"
    }
    print(f"{symbols.get(status, '[ ]')} {message}")

def log_event(message):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"{BLUE}[{now}]{RESET} {message}")

def prompt_menu(options):
    print()
    for i, item in enumerate(options, 1):
        print(f"{CYAN}{i}.{RESET} {item}")
    try:
        return int(input(f"\n{WHITE}Select an option:{RESET} "))
    except:
        return -1
