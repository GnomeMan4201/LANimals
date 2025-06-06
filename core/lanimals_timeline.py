#!/usr/bin/env python3
import json, time, os
from scapy.all import sniff, ARP

TIMELINE_FILE = "lanimals_timeline.json"

def load_timeline():
    if os.path.exists(TIMELINE_FILE):
        with open(TIMELINE_FILE) as f:
            return json.load(f)
    return {}

def save_timeline(timeline):
    with open(TIMELINE_FILE, "w") as f:
        json.dump(timeline, f, indent=4)

def log_event(ip, mac, event_type):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {event_type.upper()}: {ip} -> {mac}")

def arp_monitor(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        previous = timeline.get(ip)
        if not previous:
            timeline[ip] = {"mac": mac, "first_seen": now, "last_seen": now}
            log_event(ip, mac, "new")
        elif previous["mac"] != mac:
            log_event(ip, mac, "mac_change")
            timeline[ip]["mac"] = mac
            timeline[ip]["last_seen"] = now
        else:
            timeline[ip]["last_seen"] = now

        save_timeline(timeline)

if __name__ == "__main__":
    print("[*] LANimals Timeline Tracker running. Watching ARP changes...\nPress Ctrl+C to stop.")
    timeline = load_timeline()
    sniff(filter="arp", store=0, prn=arp_monitor)
