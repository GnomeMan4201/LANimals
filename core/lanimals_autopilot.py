import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
import os

#!/usr/bin/env python3
import subprocess
import time
from datetime import datetime

from .killchain import process_services, write_report
from .lanimals_netmap import parse_nmap

SCAN_PATH = "/tmp/lanimals_autoscan.xml"
STATE_FILE = "autopilot_state.json"
SCAN_INTERVAL = 300  # 5 minutes


def run_scan(subnet="192.168.1.0/24"):
    subprocess.run(
        ["nmap", "-sV", "-O", "-Pn", "-oX", SCAN_PATH, subnet],
        stdout=subprocess.DEVNULL,
    )


def load_previous_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def save_current_state(data):
    with open(STATE_FILE, "w") as f:
        json.dump(data, f, indent=4)


def summarize_hosts(parsed_data):
    summary = {}
    for ip, items in parsed_data.items():
        os_line = next((x for x in items if x.startswith("OS:")), "OS: Unknown")
        summary[ip] = os_line
    return summary


def diff_hosts(old, new):
    alerts = []
    old_ips = set(old.keys())
    new_ips = set(new.keys())

    for ip in new_ips - old_ips:
        alerts.append(f"[NEW] Device appeared: {ip} {new[ip]}")
    for ip in old_ips - new_ips:
        alerts.append(f"[MISSING] Device vanished: {ip} {old[ip]}")
    for ip in old_ips & new_ips:
        if old[ip] != new[ip]:
            alerts.append(f"[CHANGE] Device OS changed: {ip} {old[ip]}  {new[ip]}")

    return alerts


def main():
    print("[*] LANimals Autopilot is online. Monitoring begins...\n")
    while True:
        run_scan()
        parsed = parse_nmap(SCAN_PATH)
        summarized = summarize_hosts(parsed)

        prev = load_previous_state()
        alerts = diff_hosts(prev, summarized)

        if alerts:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n=== {now} ===")
            for a in alerts:
                print(a)
            print("=" * 40)

        save_current_state(summarized)
        killchain_data = process_services(SCAN_PATH)
        write_report(killchain_data)

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
