import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
# LANimals :: Interface Scanner
# Author: NMAPKin

import psutil
from lanimals_utils import banner, print_status


def list_interfaces():
    interfaces = psutil.net_if_addrs()
    if not interfaces:
        print_status("No network interfaces found!", "")
        return
    for iface, addrs in interfaces.items():
        print_status(f"Interface: {iface}")
        for addr in addrs:
            if addr.family.name == "AF_INET":
                print(f"  IP: {addr.address}")
                print(f"  Netmask: {addr.netmask}")
            elif addr.family.name == "AF_PACKET":
                print(f"  MAC: {addr.address}")
        print()


def main():
    banner("LANimals :: Interface Scanner")
    print_status("Enumerating active network interfaces...")
    list_interfaces()


if __name__ == "__main__":
    main()
