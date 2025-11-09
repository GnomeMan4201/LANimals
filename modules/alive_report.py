import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
# LANimals :: Alive Report Generator
# Author: NMAPKin

import os
from datetime import datetime

from lanimals_utils import banner, log_event, print_status

LOG_FILE = "scan_output/alive_hosts.log"


def load_active_hosts():
    if not os.path.exists(LOG_FILE):
        print_status("No alive hosts log found", "")
        return []
    with open(LOG_FILE, "r") as f:
        return [line.strip() for line in f.readlines()]


def generate_report():
    active = load_active_hosts()
    if not active:
        print_status("No hosts to report", "!")
        return
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_path = f"scan_output/alive_report_{timestamp}.txt"
    with open(out_path, "w") as f:
        f.write("\n".join(active))
    print_status(f"Report saved  {out_path}", "")
    log_event(f"Report created with {len(active)} live host(s)")


def main():
    banner("LANimals :: Alive Report Generator")
    print_status("Parsing alive host log...")
    generate_report()


if __name__ == "__main__":
    main()
