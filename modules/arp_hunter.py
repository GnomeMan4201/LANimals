import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
# LANimals :: ARP Hunter
# Author: NMAPKin

from lanimals_utils import banner, log_event, print_status
from scapy.all import ARP, Ether, srp


def arp_scan(target="192.168.1.0/24"):
    print_status(f"Scanning ARP on {target}...")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    result = srp(packet, timeout=2, verbose=0)[0]

    if not result:
        print_status("No ARP responses received.", "!")
        return

    for sent, received in result:
        log_event(f"{received.psrc} → {received.hwsrc}")


def main():
    banner("LANimals :: ARP Hunter")
    arp_scan()


if __name__ == "__main__":
    main()
