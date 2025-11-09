#!/usr/bin/env python3
import os
import sys

from core.cache_osv import cached_query_osv
from core.ecosystem_guesser import guess_ecosystem
from core.exploit_fetcher import fetch_exploit_urls
from core.nmap_parser import parse_nmap
from core.osv_scanner import query_osv


def scan_deps(path):
    ext = os.path.basename(path)
    pkgs = []
    if ext.endswith("requirements.txt"):
        pkgs = parse_requirements(path)
    elif ext.endswith("package-lock.json"):
        pkgs = parse_package_lock(path)
    for name, eco in pkgs:
        print(f"\n[=] {name} ({eco})")
        print(cached_query_osv(name, eco, query_osv))


def scan_nmap(xml_file):
    results = parse_nmap(xml_file)
    for addr, product, version in results:
        eco = guess_ecosystem(product)
        print(f"\n[+] {addr}: {product} {version} ({eco})")
        print(cached_query_osv(product, eco, query_osv))


def search_exploit(cve):
    for url in fetch_exploit_urls(cve):
        print(url)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            "Usage:\n  ./lanimals.py deps <requirements.txt | package-lock.json>\n  ./lanimals.py nmap <scan.xml>\n  ./lanimals.py exploit <CVE-ID>"
        )
        sys.exit(1)

    mode, target = sys.argv[1], sys.argv[2]

    if mode == "deps":
        scan_deps(target)
    elif mode == "nmap":
        scan_nmap(target)
    elif mode == "exploit":
        search_exploit(target)
    else:
        print("Unknown mode.")

import click

from core.exploitlink import search_exploits


@click.group()
def cli():
    """LANimals Command Center"""
    pass


@cli.command()
@click.argument("query")
def exploitlink(query):
    """Search ExploitDB via searchsploit for a service/version"""
    try:
        name, version = query.split(" ", 1)
    except ValueError:
        click.echo('Usage: lanimals exploitlink "<service> <version>"')
        return
    results = search_exploits(name, version)
    for line in results:
        click.echo(f"  {line}")


if __name__ == "__main__":
    cli()
