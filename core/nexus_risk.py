from __future__ import annotations

"""
LANimals risk scoring engine.
Scores hosts 0-100 based on observable signals.
"""

from typing import Any, Dict, List


# Ports that increase risk when open
_HIGH_RISK_PORTS = {
    "21": ("FTP", 20),
    "22": ("SSH", 10),
    "23": ("Telnet", 35),
    "25": ("SMTP", 15),
    "53": ("DNS", 10),
    "80": ("HTTP", 8),
    "111": ("RPC", 25),
    "135": ("MS-RPC", 30),
    "139": ("NetBIOS", 30),
    "443": ("HTTPS", 5),
    "445": ("SMB", 35),
    "512": ("rexec", 40),
    "513": ("rlogin", 40),
    "514": ("rsh", 40),
    "1433": ("MSSQL", 30),
    "1521": ("Oracle", 30),
    "2049": ("NFS", 25),
    "3306": ("MySQL", 25),
    "3389": ("RDP", 35),
    "4444": ("Metasploit", 60),
    "5432": ("PostgreSQL", 20),
    "5900": ("VNC", 35),
    "6379": ("Redis", 30),
    "8080": ("HTTP-Alt", 8),
    "8443": ("HTTPS-Alt", 8),
    "9200": ("Elasticsearch", 35),
    "27017": ("MongoDB", 30),
}

# MACs starting with these prefixes are locally administered (randomized) — suspicious
_LOCALLY_ADMINISTERED_BITS = (
    "02", "06", "0a", "0e", "12", "16", "1a", "1e",
    "22", "26", "2a", "2e", "32", "36", "3a", "3e",
    "42", "46", "4a", "4e", "52", "56", "5a", "5e",
    "62", "66", "6a", "6e", "72", "76", "7a", "7e",
    "82", "86", "8a", "8e", "92", "96", "9a", "9e",
    "a2", "a6", "aa", "ae", "b2", "b6", "ba", "be",
    "c2", "c6", "ca", "ce", "d2", "d6", "da", "de",
    "e2", "e6", "ea", "ee", "f2", "f6", "fa", "fe",
)


def _is_randomized_mac(mac: str | None) -> bool:
    if not mac:
        return False
    first = mac.lower().replace(":", "").replace("-", "")[:2]
    return first in _LOCALLY_ADMINISTERED_BITS


def score_host(
    host: Dict[str, Any],
    services: List[Dict[str, Any]],
    in_baseline: bool = True,
    baseline_mac: str | None = None,
    cve_count: int = 0,
    honeypot_hits: int = 0,
) -> tuple[int, str, list[str]]:
    """
    Returns (risk_score, status, reasons).
    status: 'normal' | 'warning' | 'critical'
    """
    score = 0
    reasons: list[str] = []

    mac = host.get("mac") or ""
    vendor = host.get("vendor") or ""
    # meta may be a JSON string (from DB) or a dict (from graph)
    _meta = host.get("meta") or {}
    if isinstance(_meta, str):
        try:
            import json as _j; _meta = _j.loads(_meta)
        except Exception:
            _meta = {}
    arp_state = _meta.get("neighbor_state") or host.get("neighbor_state") or ""

    # ── MAC checks ──────────────────────────────────────────────────────────
    if not mac:
        score += 10
        reasons.append("No MAC address observed")
    elif _is_randomized_mac(mac):
        score += 20
        reasons.append("Randomized/locally-administered MAC (device or VM may be spoofing)")
    
    if baseline_mac and mac and mac.lower() != baseline_mac.lower():
        score += 40
        reasons.append(f"MAC changed from baseline ({baseline_mac} → {mac})")

    if not in_baseline and mac:
        score += 25
        reasons.append("Host not in MAC baseline — first time seen or new device")

    # ── Vendor check ─────────────────────────────────────────────────────────
    if mac and not vendor:
        score += 8
        reasons.append("Unknown vendor OUI")

    # ── ARP state ────────────────────────────────────────────────────────────
    if arp_state.upper() in ("STALE", "DELAY"):
        score += 5
        reasons.append(f"ARP state: {arp_state}")
    elif arp_state.upper() in ("FAILED", "INCOMPLETE"):
        score += 12
        reasons.append(f"ARP state: {arp_state}")

    # ── Open services ────────────────────────────────────────────────────────
    open_ports = set()
    for svc in services:
        port = str(svc.get("port") or "")
        open_ports.add(port)
        if port in _HIGH_RISK_PORTS:
            label, pts = _HIGH_RISK_PORTS[port]
            score += pts
            reasons.append(f"Port {port} open ({label})")

    port_count = len(open_ports)
    if port_count >= 10:
        score += 15
        reasons.append(f"High port count ({port_count} open ports)")
    elif port_count >= 5:
        score += 8
        reasons.append(f"Elevated port count ({port_count} open ports)")

    # ── Honeypot interaction — highest weight signal ─────────────────────────
    honeypot_hits: int = host.get("honeypot_hits", 0)
    if isinstance(_meta, dict):
        honeypot_hits = max(honeypot_hits, int(_meta.get("honeypot_hits", 0)))
    if honeypot_hits > 0:
        score += min(50 + honeypot_hits * 5, 70)
        reasons.append(
            f"Honeypot interaction observed ({honeypot_hits} hit{'s' if honeypot_hits != 1 else ''})"
            " — no legitimate traffic should reach honeypot services"
        )

    # ── CVE findings ─────────────────────────────────────────────────────────
    if cve_count > 0:
        cve_pts = min(cve_count * 8, 40)
        score += cve_pts
        reasons.append(f"{cve_count} CVE(s) found by vulners scan")

    # ── Stability bonus — trusted known hosts get small risk reduction ────────
    if in_baseline and not honeypot_hits and not cve_count and score < 30:
        score = max(5, score - 5)
        reasons.append("Known stable host (in baseline, no threats detected)")

    # ── Cap and classify ─────────────────────────────────────────────────────
    score = max(5, min(score, 100))

    if score >= 65:
        status = "critical"
    elif score >= 25:
        status = "warning"
    else:
        status = "normal"

    return score, status, reasons


def rescore_all_hosts() -> List[Dict[str, Any]]:
    """Rescore all hosts in DB and write results back. Returns updated host list."""
    from core.nexus_db import (
        get_all_hosts, get_services_for_ip, get_mac_baseline,
        upsert_host,
    )

    hosts = get_all_hosts()
    baseline = get_mac_baseline()
    results = []

    for h in hosts:
        ip = h["ip"]
        services = get_services_for_ip(ip)
        in_baseline = ip in baseline
        baseline_mac = baseline.get(ip, {}).get("mac") if in_baseline else None
        
        # Check meta for CVE count
        import json as _json
        try:
            raw_meta = h.get("meta") or "{}"
            meta = _json.loads(raw_meta) if isinstance(raw_meta, str) else (raw_meta or {})
        except Exception:
            meta = {}
        cve_count = int(meta.get("cve_count", 0))
        honeypot_hits = int(meta.get("honeypot_hits", 0))

        score, status, reasons = score_host(
            h, services,
            in_baseline=in_baseline,
            baseline_mac=baseline_mac,
            cve_count=cve_count,
            honeypot_hits=honeypot_hits,
        )

        h["risk_score"] = score
        h["status"] = status
        meta["risk_reasons"] = reasons[:20]
        # Remove heavy fields before re-serializing
        meta.pop("cves", None)
        meta_str = _json.dumps(meta)
        h["meta"] = meta_str
        upsert_host(h)
        results.append({"ip": ip, "risk_score": score, "status": status, "reasons": reasons})

    return results
