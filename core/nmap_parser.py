#!/usr/bin/env python3
import xml.etree.ElementTree as ET


def parse_nmap(xml_path):
    services = []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.findall("host"):
            addr_elem = host.find("address")
            if addr_elem is None:
                continue
            ip = addr_elem.get("addr")

            for port in host.findall(".//port"):
                portid = port.get("portid")
                protocol = port.get("protocol")
                service = port.find("service")
                name = service.get("name", "") if service is not None else ""
                product = service.get("product", "") if service is not None else ""
                version = service.get("version", "") if service is not None else ""
                services.append((ip, protocol, portid, name, product, version))
    except Exception as e:
        print(f"[ERROR] Parsing Nmap XML failed: {e}")
    return services
