#!/usr/bin/env python3
import subprocess
from rich import print

def main():
    print("[✓] CVE Hunt starting via `nmap --script vulners`...\n")
    try:
        with open("/tmp/target_net", "r") as f:
            target = f.read().strip().split("/")[0]
        result = subprocess.getoutput(f"nmap -sV {target} --script vulners -oX -")
        print(result[:500] + "\n...\n[✓] Results truncated.")
    except Exception as e:
        print("[✗] Failed to perform CVE hunt:", e)

if __name__ == "__main__":
    main()
