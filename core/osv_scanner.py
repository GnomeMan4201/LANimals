#!/usr/bin/env python3
import requests


def query_osv(package_name, ecosystem):
    if ecosystem == "Unknown":
        return "No ecosystem match; skipping."
    url = "https://api.osv.dev/v1/query"
    data = {"package": {"name": package_name, "ecosystem": ecosystem}}
    try:
        res = requests.post(url, json=data)
        res.raise_for_status()
        vulns = res.json().get("vulns", [])
        if not vulns:
            return "No vulns found."

        output = ""
        for vuln in vulns:
            cve = vuln.get("id", "UNKNOWN")
            summary = vuln.get("summary", "")
            details = vuln.get("details", "")
            output += f" {cve} - {summary or details[:80]}\n"
        return output.strip()
    except Exception as e:
        return f"[ERROR] {e}"
