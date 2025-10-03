#!/usr/bin/env python3
import os


def main():
    print("\n[✓] Running Network Scan...")
    os.system("sudo nmap -sS -T4 -Pn -n -iL /tmp/target_net")


if __name__ == "__main__":
    main()


def run():
    print("Running net_scan")
