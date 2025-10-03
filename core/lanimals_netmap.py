#!/usr/bin/env python3
from collections import defaultdict
from xml.etree import ElementTree as ET


def parse_nmap(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    network = defaultdict(list)

    for host in root.findall("host"):
        addr = host.find("address").get("addr")
        os_elem = host.find("os/osmatch")
        os_name = os_elem.get("name") if os_elem is not None else "Unknown OS"
        network[addr].append(f"OS: {os_name}")

        for port in host.findall(".//port"):
            service = port.find("service")
            if service is not None:
                name = service.get("name", "")
                product = service.get("product", "")
                version = service.get("version", "")
                desc = f"{name} {product} {version}".strip()
                network[addr].append(desc)

    return network


def draw_ascii_map(network):
    print("\n🐾 LANimals Network Map 🧭")
    print("=" * 40)
    for ip, details in network.items():
        print(f"[{ip}]")
        for d in details:
            print(f"  └─ {d}")
        print("-" * 40)


def main(xml_path):
    net = parse_nmap(xml_path)
    draw_ascii_map(net)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 lanimals_netmap.py <nmap_scan.xml>")
        sys.exit(1)
    main(sys.argv[1])


def resolve_mac_vendor(mac):
    mac = mac.upper().replace(":", "")[:6]
    oui_db = {
        "D8CF61": "Sagemcom",
        "DC7223": "Hui Zhou Gaoshengda",
        "C83DD4": "CyberTAN",
        "B46921": "Apple",
        "7E70E9": "Samsung",
        "D2BBDB": "Unknown",
    }
    return oui_db.get(mac, "Unknown Vendor")


def parse_nmap(xml_path):
    from collections import defaultdict
    from xml.etree import ElementTree as ET

    tree = ET.parse(xml_path)
    root = tree.getroot()
    network = defaultdict(list)

    for host in root.findall("host"):
        addr = host.find("address").get("addr")
        mac_elem = host.find("address[@addrtype='mac']")
        mac = mac_elem.get("addr") if mac_elem is not None else "N/A"
        vendor = resolve_mac_vendor(mac)

        os_elem = host.find("os/osmatch")
        os_name = os_elem.get("name") if os_elem is not None else "Unknown OS"

        network[addr].append(f"MAC: {mac} ({vendor})")
        network[addr].append(f"OS: {os_name}")

        for port in host.findall(".//port"):
            service = port.find("service")
            if service is not None:
                name = service.get("name", "")
                product = service.get("product", "")
                version = service.get("version", "")
                desc = f"{name} {product} {version}".strip()
                network[addr].append(desc)

    return network
