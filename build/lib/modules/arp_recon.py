#!/usr/bin/env python3
import os


def main():
    print("\n[✓] Running ARP Recon...")
    os.system("arp -a")


if __name__ == "__main__":
    main()
