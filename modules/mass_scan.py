import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
# LANimals :: Mass Port Scanner
# Author: NMAPKin

import os
import subprocess
from datetime import datetime

from lanimals_utils import banner, log_event, print_status

ALIVE_LOG = "scan_output/alive_hosts.log"
OUT_DIR = "scan_output"


def load_targets():
    if not os.path.exists(ALIVE_LOG):
        print_status("Alive host log not found", "✗")
        return []
    with open(ALIVE_LOG, "r") as f:
        return [line.strip() for line in f.readlines()]


def scan_targets(targets):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_file = os.path.join(OUT_DIR, f"mass_scan_{timestamp}.txt")
    print_status(f"Launching mass scan on {len(targets)} host(s)...")

    with open(out_file, "w") as f:
        for ip in targets:
            log_event(f"Scanning {ip}")
            result = subprocess.run(
                ["nmap", "-T4", "-F", ip], capture_output=True, text=True
            )
            f.write(f"\n--- Scan: {ip} ---\n")
            f.write(result.stdout)

    print_status(f"Mass scan completed → {out_file}", "✓")


def main():
    banner("LANimals :: Mass Port Scanner")
    print_status("Preparing live target list...")
    targets = load_targets()
    if not targets:
        return
    scan_targets(targets)


if __name__ == "__main__":
    main()
