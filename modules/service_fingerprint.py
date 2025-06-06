#!/usr/bin/env python3
import os
def main():
    print("\n[✓] Running Service Fingerprinting...")
    os.system("sudo nmap -sV -iL /tmp/target_net")
if __name__ == "__main__":
    main()
