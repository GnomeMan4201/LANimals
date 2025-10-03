#!/usr/bin/env python3
import time

from scapy.all import ARP, sniff

seen_arp = {}


def detect_arp_poison(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        sender_ip = pkt[ARP].psrc
        sender_mac = pkt[ARP].hwsrc
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        if sender_ip in seen_arp:
            if seen_arp[sender_ip] != sender_mac:
                print(
                    f"[!] {now} ARP spoof detected: {sender_ip} is now at {sender_mac} (was {seen_arp[sender_ip]})"
                )
        else:
            print(f"[+] {now} New ARP mapping: {sender_ip} -> {sender_mac}")
        seen_arp[sender_ip] = sender_mac


def main():
    print(
        "[*] LANimals Watchdog activated. Sniffing for ARP spoofing...\nPress Ctrl+C to stop.\n"
    )
    sniff(filter="arp", store=0, prn=detect_arp_poison)


if __name__ == "__main__":
    main()
