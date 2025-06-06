#!/usr/bin/env python3
# LANimals :: HTTP Probe
# Author: NMAPKin

import subprocess
from lanimals_utils import banner, print_status

def probe_url():
    url = input("🌐 Target URL (e.g., http://example.com): ").strip()
    if not url:
        print_status("No URL provided.", "!")
        return
    try:
        print_status(f"Probing {url} ...")
        result = subprocess.run(
            ["curl", "-sI", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        headers = result.stdout.strip().splitlines()
        for line in headers:
            print(f"  {line}")
        print_status("Header probe complete.", "✓")
    except Exception as e:
        print_status(f"Error: {e}", "✗")

def main():
    banner("LANimals :: HTTP Probe")
    probe_url()

if __name__ == "__main__":
    main()
