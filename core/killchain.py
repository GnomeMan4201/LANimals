import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import datetime
import json

#!/usr/bin/env python3
import os
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.cache_osv import cached_query_osv

from .ecosystem_guesser import guess_ecosystem
from .exploit_fetcher import fetch_exploit_urls
from .nmap_parser import parse_nmap
from .osv_scanner import query_osv


def run_nmap(target):
    out_file = "/tmp/scan.xml"
    print(f"[+] Running Nmap against {target}")
    subprocess.run(
        ["nmap", "-sV", "-Pn", "-oX", out_file, target], stdout=subprocess.DEVNULL
    )
    return out_file if os.path.exists(out_file) else None


def process_services(xml_path):
    services = parse_nmap(xml_path)
    all_results = []
    for host, protocol, port, name, product, version in services:
        eco = guess_ecosystem(product)
        print(f"\n[=] {host}: {product} {version} ({eco})")
        vulns = cached_query_osv(product, eco, query_osv)
        if "No vulns" not in vulns:
            cve_list = [
                line.split()[1][:-1]
                for line in vulns.splitlines()
                if line.startswith("🔓")
            ]
            exploits = {cve: fetch_exploit_urls(cve) for cve in cve_list}
        else:
            exploits = {}
        all_results.append(
            {
                "host": host,
                "product": product,
                "version": version,
                "ecosystem": eco,
                "vulns": vulns,
                "exploits": exploits,
            }
        )
    return all_results


def write_report(data):
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs("reports", exist_ok=True)
    report_file = f"reports/report_{now}.json"
    with open(report_file, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Report saved to {report_file}")


def main(target):
    scan_path = run_nmap(target)
    if not scan_path:
        print("[!] Nmap scan failed.")
        return
    results = process_services(scan_path)
    write_report(results)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./core/killchain.py <target_ip_or_cidr>")
        sys.exit(1)
    main(sys.argv[1])
