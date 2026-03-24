from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from core.nexus_builder import build_snapshot, save_discovery_cache
from core.nexus_collectors import (
    collect_arp_neighbors,
    collect_local_interfaces,
    collect_nmap_ping_sweep,
    collect_host_map,
    collect_rogue_scan,
    collect_sysinfo,
    collect_services_for_ip,
)
from core.nexus_service_state import load_service_state, save_service_state
from core.nexus_state import load_state, save_state
from core.nexus_risk import rescore_all_hosts, score_host
from core.nexus_db import (
    init_db, upsert_hosts, upsert_services, insert_events,
    get_all_hosts, get_services_for_ip, get_recent_events,
    get_db_stats, update_mac_baseline, get_mac_baseline,
    get_host_notes, set_host_notes, get_host,
)

ROOT = Path(__file__).resolve().parent.parent
UI_FILE = ROOT / "ui" / "lanimals_live_map.html"
REPORTS_DIR = ROOT / "reports"

app = FastAPI(title="LANimals Nexus", version="2.0.0")

# ── Job registry ──────────────────────────────────────────────────────────────
_JOBS: Dict[str, Dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()
_JOB_MAX = 50


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _job_create(op: str, params: dict) -> str:
    jid = str(uuid.uuid4())[:8]
    with _JOBS_LOCK:
        _JOBS[jid] = {
            "id": jid, "op": op, "params": params, "status": "running",
            "started_at": _now_iso(), "finished_at": None,
            "lines": [], "result": None, "error": None,
        }
        keys = list(_JOBS.keys())
        if len(keys) > _JOB_MAX:
            for old in keys[: len(keys) - _JOB_MAX]:
                del _JOBS[old]
    return jid


def _job_log(jid: str, line: str) -> None:
    with _JOBS_LOCK:
        if jid in _JOBS:
            _JOBS[jid]["lines"].append(f"[{_now_iso()}] {line}")


def _job_done(jid: str, result: Any, error: Optional[str] = None) -> None:
    with _JOBS_LOCK:
        if jid in _JOBS:
            _JOBS[jid]["status"] = "error" if error else "done"
            _JOBS[jid]["finished_at"] = _now_iso()
            _JOBS[jid]["result"] = result
            _JOBS[jid]["error"] = error


def _job_get(jid: str) -> Optional[Dict[str, Any]]:
    with _JOBS_LOCK:
        return dict(_JOBS.get(jid, {}))


def _jobs_recent(limit: int = 20) -> List[Dict[str, Any]]:
    with _JOBS_LOCK:
        jobs = list(_JOBS.values())
    jobs.sort(key=lambda j: j.get("started_at", ""), reverse=True)
    return [{k: v for k, v in j.items() if k != "lines"} for j in jobs[:limit]]


# ── Background runners ────────────────────────────────────────────────────────

def _run_discovery(jid: str, cidr: str) -> None:
    try:
        _job_log(jid, f"Discovery scan: {cidr}")
        arp = collect_arp_neighbors()
        local = collect_local_interfaces()
        _job_log(jid, f"  ARP table: {len(arp)} entries")
        _job_log(jid, f"  Local interfaces: {len(local)} addresses")
        _job_log(jid, f"  Starting nmap ping sweep on {cidr} …")
        nmap_hosts = collect_nmap_ping_sweep(cidr=cidr)
        _job_log(jid, f"  nmap found: {len(nmap_hosts)} hosts")

        seen: dict[str, dict] = {}
        for h in arp + local + nmap_hosts:
            ip = h.get("ip")
            if ip and ip not in seen:
                seen[ip] = h

        for ip, h in sorted(seen.items()):
            _job_log(jid, f"  {ip:18s}  {h.get('hostname',''):32s}  mac={h.get('mac') or '--':18s}  src={h.get('source','')}")

        cache_data = {
            "arp_neighbors": arp,
            "local_interfaces": local,
            "nmap_hosts": nmap_hosts,
            "cidr": cidr,
        }
        save_discovery_cache(cache_data)
        # Persist to SQLite
        host_rows = []
        for ip, h in seen.items():
            parts = ip.split(".")
            group_cidr = ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else None
            host_rows.append({**h, "group_cidr": group_cidr})
        upsert_hosts(host_rows)
        insert_events([{
            "id": f"evt:discovery:{jid}",
            "ts": _now_iso(),
            "severity": "info",
            "title": "Discovery Scan Complete",
            "summary": f"{len(seen)} hosts found on {cidr}",
        }])
        _job_log(jid, f"Discovery complete: {len(seen)} unique hosts — graph cache updated")
        try:
            from core.nexus_risk import rescore_all_hosts
            scores = rescore_all_hosts()
            flagged = [s for s in scores if s["status"] != "normal"]
            if flagged:
                _job_log(jid, f"  Risk engine: {len(flagged)} hosts flagged")
                for s in flagged:
                    _job_log(jid, f"    [{s['status'].upper()}] {s['ip']}  risk={s['risk_score']}")
        except Exception as _re:
            _job_log(jid, f"  Risk engine error: {_re}")
        _job_done(jid, {"host_count": len(seen), "hosts": list(seen.values())})
    except Exception as exc:
        _job_log(jid, f"ERROR: {exc}")
        _job_done(jid, None, str(exc))


def _run_arp_refresh(jid: str) -> None:
    try:
        _job_log(jid, "ARP neighbor refresh")
        rows = collect_arp_neighbors()
        local = collect_local_interfaces()
        for r in rows:
            _job_log(jid, f"  {r.get('ip',''):18s}  mac={r.get('mac') or '--':20s}  state={r.get('state','')}")
        save_discovery_cache({
            "arp_neighbors": rows,
            "local_interfaces": local,
            "nmap_hosts": [],
        })
        _job_log(jid, f"ARP refresh complete: {len(rows)} entries — graph cache updated")
        _job_done(jid, {"count": len(rows), "neighbors": rows})
    except Exception as exc:
        _job_log(jid, f"ERROR: {exc}")
        _job_done(jid, None, str(exc))


def _run_hostmap(jid: str, cidr: str) -> None:
    try:
        _job_log(jid, f"Host mapping: {cidr}")
        rows = collect_host_map(cidr=cidr)
        for r in rows:
            _job_log(jid, f"  {r.get('ip',''):18s}  {r.get('hostname',''):40s}  mac={r.get('mac') or '--'}")
        # Merge into cache
        existing_cache = {}
        try:
            from core.nexus_builder import DISCOVERY_CACHE
            import json
            if DISCOVERY_CACHE.exists():
                existing_cache = json.loads(DISCOVERY_CACHE.read_text())
        except Exception:
            pass
        nmap_hosts = existing_cache.get("nmap_hosts", [])
        existing_ips = {h.get("ip") for h in nmap_hosts}
        for r in rows:
            if r.get("ip") not in existing_ips:
                nmap_hosts.append(r)
        save_discovery_cache({"nmap_hosts": nmap_hosts, "cidr": cidr})
        _job_log(jid, f"Host map complete: {len(rows)} hosts — graph cache updated")
        _job_done(jid, {"count": len(rows), "hosts": rows})
    except Exception as exc:
        _job_log(jid, f"ERROR: {exc}")
        _job_done(jid, None, str(exc))


def _run_rogue(jid: str, cidr: str) -> None:
    try:
        _job_log(jid, f"Rogue detection: {cidr}")
        result = collect_rogue_scan(cidr=cidr)
        rogues = result.get("rogues", [])
        known = result.get("known_count", 0)
        if rogues:
            for r in rogues:
                _job_log(jid, f"  [ROGUE] {r.get('ip',''):18s}  mac={r.get('mac') or '--':20s}  {r.get('reason','')}")
        else:
            _job_log(jid, "  No rogue devices detected")
        _job_log(jid, f"Rogue scan complete: {known} known, {len(rogues)} flagged")
        try:
            scores = rescore_all_hosts()
            flagged = [s for s in scores if s["status"] != "normal"]
            if flagged:
                _job_log(jid, f"  Risk: {len(flagged)} hosts flagged after rescore")
        except Exception:
            pass
        _job_done(jid, result)
    except Exception as exc:
        _job_log(jid, f"ERROR: {exc}")
        _job_done(jid, None, str(exc))


def _run_service_scan(jid: str, ip: str) -> None:
    try:
        _job_log(jid, f"Service fingerprint: {ip}")
        services = collect_services_for_ip(ip)
        state = load_service_state()
        svc_map = state.get("services_by_ip", {})
        svc_map[ip] = services
        state["services_by_ip"] = svc_map
        save_service_state(state)
        for svc in services:
            _job_log(jid, f"  {svc.get('protocol','tcp'):4s}/{svc.get('port','?'):6s}  {svc.get('service_name',''):16s}  {svc.get('product','')} {svc.get('version','')}")
        upsert_services(services)
        insert_events([{
            "id": f"evt:svc:{jid}",
            "ts": _now_iso(),
            "severity": "info",
            "title": f"Service Scan: {ip}",
            "summary": f"{len(services)} open ports found",
            "ip": ip,
        }])
        try:
            from core.nexus_risk import rescore_all_hosts
            rescore_all_hosts()
        except Exception:
            pass
        _job_log(jid, f"Service scan complete: {len(services)} open ports — detail panel updated")
        _job_done(jid, {"ip": ip, "count": len(services), "services": services})
    except Exception as exc:
        _job_log(jid, f"ERROR: {exc}")
        _job_done(jid, None, str(exc))


def _run_inventory(jid: str) -> None:
    try:
        _job_log(jid, "Inventory collection started")
        info = collect_sysinfo()
        for k, v in info.items():
            if k == "interfaces":
                for iface, ips in (v or {}).items():
                    _job_log(jid, f"  iface: {iface}  →  {', '.join(ips)}")
            else:
                _job_log(jid, f"  {k}: {v}")
        _job_log(jid, "Inventory complete")
        _job_done(jid, info)
    except Exception as exc:
        _job_log(jid, f"ERROR: {exc}")
        _job_done(jid, None, str(exc))


# ── API ───────────────────────────────────────────────────────────────────────

@app.get("/")
def ui():
    return FileResponse(UI_FILE)


@app.get("/favicon.ico")
def favicon():
    p = ROOT / "assets" / "LANimals.png"
    if p.exists():
        return FileResponse(p)
    raise HTTPException(status_code=404)


@app.get("/api/health")
def health():
    return {"ok": True, "service": "lanimals-nexus", "version": "2.0.0"}


@app.get("/api/graph")
def get_graph():
    snapshot = build_snapshot()
    return JSONResponse(snapshot.model_dump())


@app.get("/api/node/{node_id:path}")
def get_node(node_id: str):
    snapshot = build_snapshot()
    node = next((n for n in snapshot.nodes if n.id == node_id), None)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    related_edges = [e for e in snapshot.edges if e.source == node_id or e.target == node_id]
    neighbor_ids = set()
    for e in related_edges:
        if e.source != node_id:
            neighbor_ids.add(e.source)
        if e.target != node_id:
            neighbor_ids.add(e.target)
    neighbors = [n for n in snapshot.nodes if n.id in neighbor_ids]
    related_events = [evt for evt in snapshot.events if evt.node_id == node_id]
    return JSONResponse({
        "node": node.model_dump(),
        "neighbors": [n.model_dump() for n in neighbors],
        "edges": [e.model_dump() for e in related_edges],
        "events": [e.model_dump() for e in related_events],
    })


@app.get("/api/reports")
def get_reports():
    files = []
    if REPORTS_DIR.exists():
        for path in sorted(REPORTS_DIR.glob("report_*.json"), reverse=True):
            stat = path.stat()
            files.append({"name": path.name, "size": stat.st_size, "modified": stat.st_mtime})
    return {"reports": files[:20]}


@app.get("/api/logs")
def get_logs():
    snap = build_snapshot()
    return {"events": [e.model_dump() for e in snap.events[:30]]}


@app.get("/api/sysinfo")
def get_sysinfo():
    return collect_sysinfo()


@app.get("/api/services/{ip}")
def get_services(ip: str):
    state = load_service_state()
    services = state.get("services_by_ip", {}).get(ip, [])
    return {"ip": ip, "services": services, "count": len(services)}


# ── Scan endpoints ─────────────────────────────────────────────────────────────

@app.post("/api/scan/discovery")
def scan_discovery(cidr: str = Query(default="192.168.0.0/24")):
    jid = _job_create("discovery", {"cidr": cidr})
    threading.Thread(target=_run_discovery, args=(jid, cidr), daemon=True).start()
    return {"ok": True, "job_id": jid, "op": "discovery", "cidr": cidr}


@app.post("/api/scan/arp")
def scan_arp():
    jid = _job_create("arp_refresh", {})
    threading.Thread(target=_run_arp_refresh, args=(jid,), daemon=True).start()
    return {"ok": True, "job_id": jid, "op": "arp_refresh"}


@app.post("/api/scan/hostmap")
def scan_hostmap(cidr: str = Query(default="192.168.0.0/24")):
    jid = _job_create("hostmap", {"cidr": cidr})
    threading.Thread(target=_run_hostmap, args=(jid, cidr), daemon=True).start()
    return {"ok": True, "job_id": jid, "op": "hostmap", "cidr": cidr}


@app.post("/api/scan/rogue")
def scan_rogue(cidr: str = Query(default="192.168.0.0/24")):
    jid = _job_create("rogue", {"cidr": cidr})
    threading.Thread(target=_run_rogue, args=(jid, cidr), daemon=True).start()
    return {"ok": True, "job_id": jid, "op": "rogue", "cidr": cidr}


@app.post("/api/scan/services/{ip}")
def scan_services(ip: str):
    jid = _job_create("service_scan", {"ip": ip})
    threading.Thread(target=_run_service_scan, args=(jid, ip), daemon=True).start()
    return {"ok": True, "job_id": jid, "op": "service_scan", "ip": ip}


@app.post("/api/scan/inventory")
def scan_inventory():
    jid = _job_create("inventory", {})
    threading.Thread(target=_run_inventory, args=(jid,), daemon=True).start()
    return {"ok": True, "job_id": jid, "op": "inventory"}


# ── Job endpoints ──────────────────────────────────────────────────────────────

@app.get("/api/jobs")
def list_jobs():
    return {"jobs": _jobs_recent()}


@app.get("/api/jobs/{jid}")
def get_job(jid: str):
    job = _job_get(jid)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


# ── Production endpoints ───────────────────────────────────────────────────────

@app.get("/api/hosts")
def get_hosts():
    """All known hosts from persistent DB."""
    hosts = get_all_hosts()
    return {"hosts": hosts, "count": len(hosts)}


@app.get("/api/hosts/{ip}/services")
def get_host_services(ip: str):
    svcs = get_services_for_ip(ip)
    return {"ip": ip, "services": svcs, "count": len(svcs)}


@app.get("/api/hosts/{ip}/events")
def get_host_events(ip: str):
    events = get_recent_events(limit=50, ip=ip)
    return {"ip": ip, "events": events, "count": len(events)}


@app.get("/api/events")
def get_events(limit: int = 60):
    events = get_recent_events(limit=min(limit, 200))
    return {"events": events, "count": len(events)}


@app.get("/api/stats")
def get_stats():
    db = get_db_stats()
    snap = build_snapshot()
    return {
        "db": db,
        "graph": snap.stats,
        "generated_at": _now_iso(),
    }


@app.get("/api/scan/anomaly")
def get_anomaly():
    """Check live outbound connections against known hosts — flag unknowns."""
    import psutil
    known_hosts = {h["ip"] for h in get_all_hosts()}
    baseline = get_mac_baseline()
    known_ips = known_hosts | set(baseline.keys())

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        return {"error": str(e), "anomalies": []}

    anomalies = []
    seen = set()
    for c in conns:
        if not c.raddr:
            continue
        rip = c.raddr[0]
        if rip in seen:
            continue
        seen.add(rip)
        # Skip loopback and RFC1918
        if (rip.startswith("127.") or rip.startswith("::1") or
                rip.startswith("192.168.") or rip.startswith("10.") or
                any(rip.startswith(p) for p in ("172.16.","172.17.","172.18.","172.19.","172.20.",
                    "172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.",
                    "172.28.","172.29.","172.30.","172.31."))):
            continue
        anomalies.append({
            "ip": rip,
            "port": c.raddr[1],
            "status": c.status,
            "known": rip in known_ips,
            "pid": c.pid,
        })

    insert_events([{
        "id": f"evt:anomaly:{_now_iso()}",
        "ts": _now_iso(),
        "severity": "warning" if anomalies else "info",
        "title": "Anomaly Scan",
        "summary": f"{len(anomalies)} external connections detected",
    }])

    return {"anomalies": anomalies, "count": len(anomalies), "scanned_at": _now_iso()}


@app.get("/api/export/report")
def export_report():
    """Generate a full HTML operator report."""
    from fastapi.responses import HTMLResponse
    hosts = get_all_hosts()
    events = get_recent_events(limit=100)
    stats = get_db_stats()
    now = _now_iso()

    rows = ""
    for h in sorted(hosts, key=lambda x: x.get("ip") or ""):
        svcs = get_services_for_ip(h["ip"])
        svc_str = ", ".join(f"{s['service_name']}:{s['port']}" for s in svcs) or "—"
        status_color = "#ff4455" if h["status"]=="critical" else "#c97b00" if h["status"]=="warning" else "#2a9d4e"
        rows += f"""<tr>
            <td>{h.get("ip","")}</td>
            <td>{h.get("hostname","")}</td>
            <td>{h.get("mac","") or "—"}</td>
            <td>{h.get("vendor","") or "—"}</td>
            <td style="color:{status_color}">{h.get("status","normal")}</td>
            <td>{h.get("risk_score",0)}</td>
            <td style="font-size:11px">{svc_str}</td>
            <td>{h.get("last_seen","") or "—"}</td>
        </tr>"""

    event_rows = ""
    for e in events[:50]:
        sev_color = "#ff4455" if e["severity"] in ("critical","high") else "#c97b00" if e["severity"]=="warning" else "#3b7ecf"
        event_rows += f"""<tr>
            <td style="color:{sev_color}">{e["severity"].upper()}</td>
            <td>{e["ts"]}</td>
            <td>{e["title"]}</td>
            <td>{e.get("summary","")}</td>
            <td>{e.get("ip","") or "—"}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<title>LANimals Report — {now}</title>
<style>
  body{{font-family:'JetBrains Mono',monospace;background:#0b0b0d;color:#f0f1f3;padding:32px;}}
  h1{{color:#d61f2c;font-size:28px;margin-bottom:4px;}}
  h2{{color:#7a8090;font-size:13px;font-weight:400;margin-bottom:32px;}}
  h3{{color:#d61f2c;font-size:14px;text-transform:uppercase;letter-spacing:.1em;margin:32px 0 12px;}}
  table{{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:32px;}}
  th{{background:#17171d;color:#7a8090;text-align:left;padding:8px 10px;border-bottom:1px solid #252530;font-size:10px;text-transform:uppercase;letter-spacing:.08em;}}
  td{{padding:7px 10px;border-bottom:1px solid #17171d;}}
  tr:hover td{{background:#111115;}}
  .stat{{display:inline-block;background:#111115;border:1px solid #252530;border-radius:6px;padding:12px 20px;margin:0 8px 8px 0;}}
  .sv{{font-size:28px;font-weight:800;color:#d61f2c;}}
  .sl{{font-size:10px;color:#7a8090;text-transform:uppercase;}}
  .footer{{color:#252530;font-size:10px;margin-top:48px;}}
</style>
</head><body>
<h1>LANimals</h1>
<h2>Network Intelligence Report — Generated {now}</h2>
<div>
  <div class="stat"><div class="sv">{stats["hosts"]}</div><div class="sl">Hosts</div></div>
  <div class="stat"><div class="sv">{stats["services"]}</div><div class="sl">Services</div></div>
  <div class="stat"><div class="sv" style="color:#c97b00">{stats["warnings"]}</div><div class="sl">Warnings</div></div>
  <div class="stat"><div class="sv">{stats["baseline_entries"]}</div><div class="sl">Baseline</div></div>
  <div class="stat"><div class="sv">{stats["events"]}</div><div class="sl">Events</div></div>
</div>
<h3>Host Inventory</h3>
<table><thead><tr>
  <th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th>
  <th>Status</th><th>Risk</th><th>Services</th><th>Last Seen</th>
</tr></thead><tbody>{rows}</tbody></table>
<h3>Recent Events</h3>
<table><thead><tr>
  <th>Severity</th><th>Timestamp</th><th>Event</th><th>Summary</th><th>IP</th>
</tr></thead><tbody>{event_rows}</tbody></table>
<div class="footer">LANimals Nexus v2.0 — badBANANA/LANimals</div>
</body></html>"""

    return HTMLResponse(content=html)



# ── Notes endpoint ────────────────────────────────────────────────────────────

from pydantic import BaseModel as _BaseModel

class NotesPayload(_BaseModel):
    notes: str


@app.get("/api/hosts/{ip}/notes")
def get_notes(ip: str):
    return {"ip": ip, "notes": get_host_notes(ip)}


@app.patch("/api/hosts/{ip}/notes")
def patch_notes(ip: str, payload: NotesPayload):
    set_host_notes(ip, payload.notes.strip())
    insert_events([{
        "id": f"evt:notes:{ip}:{_now_iso()}",
        "ts": _now_iso(),
        "severity": "info",
        "title": f"Notes updated: {ip}",
        "summary": payload.notes.strip()[:120],
        "ip": ip,
    }])
    return {"ok": True, "ip": ip, "notes": payload.notes.strip()}


# ── VirusTotal enrichment ─────────────────────────────────────────────────────

@app.get("/api/enrich/vt/{ip}")
def enrich_vt(ip: str):
    """VirusTotal IP reputation. Requires VT_API_KEY env var."""
    import os, urllib.request, json as _json
    api_key = os.environ.get("VT_API_KEY", "")
    if not api_key:
        return {"ip": ip, "error": "VT_API_KEY not set", "available": False}
    try:
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key, "User-Agent": "LANimals/2.0"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = _json.loads(resp.read())
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        result = {
            "ip": ip,
            "available": True,
            "reputation": attrs.get("reputation", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
            "network": attrs.get("network", ""),
        }
        severity = "critical" if result["malicious"] > 0 else "warning" if result["suspicious"] > 0 else "info"
        insert_events([{
            "id": f"evt:vt:{ip}:{_now_iso()}",
            "ts": _now_iso(),
            "severity": severity,
            "title": f"VT Lookup: {ip}",
            "summary": f"malicious={result['malicious']} suspicious={result['suspicious']} reputation={result['reputation']} as={result['as_owner']}",
            "ip": ip,
        }])
        return result
    except Exception as e:
        return {"ip": ip, "available": False, "error": str(e)}


# ── CVE scan ──────────────────────────────────────────────────────────────────

def _run_cve_scan(jid: str, ip: str) -> None:
    import shutil, subprocess, json as _json
    from xml.etree import ElementTree as ET
    from pathlib import Path as _Path

    TMP = _Path(__file__).resolve().parent.parent / "tmp"
    try:
        _job_log(jid, f"CVE scan starting on {ip} (nmap vulners)")
        if not shutil.which("nmap"):
            _job_done(jid, None, "nmap not found")
            return

        xml_path = TMP / f"cve_{ip.replace('.','_')}.xml"
        cmd = ["nmap", "-Pn", "-sV", "--script", "vulners", "-oX", str(xml_path), ip]
        if shutil.which("sudo") and __import__("os").geteuid() != 0:
            cmd = ["sudo"] + cmd

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if not xml_path.exists():
            _job_done(jid, None, "nmap produced no output")
            return

        root = ET.parse(xml_path).getroot()
        cves: list[dict] = []
        for host in root.findall("host"):
            for port in host.findall(".//port"):
                portid = port.get("portid", "")
                for script in port.findall(".//script[@id='vulners']"):
                    output = script.get("output", "")
                    for line in output.splitlines():
                        line = line.strip()
                        if line.startswith("CVE-") or "CVE-" in line:
                            parts = line.split()
                            cve_id = next((p for p in parts if p.startswith("CVE-")), line[:20])
                            score_str = next((p for p in parts if p.replace(".","").isdigit() and "." in p), "?")
                            cves.append({"cve": cve_id, "score": score_str, "port": portid})
                            _job_log(jid, f"  [{portid}] {cve_id}  CVSS={score_str}")

        if not cves:
            _job_log(jid, "  No CVEs found")
        else:
            _job_log(jid, f"  {len(cves)} CVE(s) found")

        # Persist CVE count to host meta
        host_row = get_host(ip) or {"ip": ip}
        try:
            meta = _json.loads(host_row.get("meta") or "{}")
        except Exception:
            meta = {}
        meta["cve_count"] = len(cves)
        meta["cves"] = cves[:30]
        host_row["meta"] = _json.dumps(meta)
        upsert_hosts([host_row])

        # Store as events
        for cve in cves[:10]:
            insert_events([{
                "id": f"evt:cve:{ip}:{cve['cve']}",
                "ts": _now_iso(),
                "severity": "critical" if float(cve["score"]) >= 7.0 else "warning"
                            if float(cve["score"]) >= 4.0 else "info"
                            if cve["score"] != "?" else "warning",
                "title": f"CVE: {cve['cve']}",
                "summary": f"CVSS {cve['score']} on port {cve['port']}",
                "ip": ip,
            }])

        # Rescore
        try:
            rescore_all_hosts()
        except Exception:
            pass

        _job_log(jid, "CVE scan complete")
        _job_done(jid, {"ip": ip, "cve_count": len(cves), "cves": cves})
    except subprocess.TimeoutExpired:
        _job_done(jid, None, "nmap timeout after 180s")
    except Exception as exc:
        _job_log(jid, f"ERROR: {exc}")
        _job_done(jid, None, str(exc))


@app.post("/api/scan/cve/{ip}")
def scan_cve(ip: str):
    jid = _job_create("cve_scan", {"ip": ip})
    threading.Thread(target=_run_cve_scan, args=(jid, ip), daemon=True).start()
    return {"ok": True, "job_id": jid, "op": "cve_scan", "ip": ip}


@app.get("/api/hosts/{ip}/cves")
def get_cves(ip: str):
    import json as _json
    row = get_host(ip)
    if not row:
        return {"ip": ip, "cves": [], "cve_count": 0}
    try:
        raw = row.get("meta") or "{}"
        meta = _json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception:
        meta = {}
    return {"ip": ip, "cves": meta.get("cves", []), "cve_count": meta.get("cve_count", 0)}


# ── Risk rescore endpoint ─────────────────────────────────────────────────────

@app.post("/api/scan/rescore")
def rescore():
    results = rescore_all_hosts()
    flagged = [r for r in results if r["status"] != "normal"]
    insert_events([{
        "id": f"evt:rescore:{_now_iso()}",
        "ts": _now_iso(),
        "severity": "warning" if flagged else "info",
        "title": "Risk Rescore",
        "summary": f"{len(results)} hosts scored. {len(flagged)} flagged.",
    }])
    return {"rescored": len(results), "flagged": len(flagged), "results": results}


# ── Network diff ──────────────────────────────────────────────────────────────

@app.get("/api/diff")
def network_diff():
    """Compare current DB state to previous snapshot. Shows what changed."""
    from core.nexus_state import load_state
    import json as _json

    current_hosts = {h["ip"]: h for h in get_all_hosts()}
    prev_state = load_state()
    prev_hosts: dict = prev_state.get("hosts", {})

    current_ips = set(current_hosts.keys())
    prev_ips = set(prev_hosts.keys())

    appeared = []
    disappeared = []
    changed = []

    for ip in sorted(current_ips - prev_ips):
        h = current_hosts[ip]
        appeared.append({
            "ip": ip, "hostname": h.get("hostname", ip),
            "mac": h.get("mac", ""), "vendor": h.get("vendor", ""),
            "first_seen": h.get("first_seen", ""),
        })

    for ip in sorted(prev_ips - current_ips):
        prev = prev_hosts[ip]
        disappeared.append({
            "ip": ip, "hostname": prev.get("label", ip),
            "last_seen": prev.get("last_seen", ""),
        })

    for ip in sorted(current_ips & prev_ips):
        cur = current_hosts[ip]
        prev = prev_hosts[ip]
        diffs = []
        if cur.get("status") != prev.get("status"):
            diffs.append(f"status: {prev.get('status')} → {cur.get('status')}")
        if cur.get("risk_score") != prev.get("risk_score"):
            diffs.append(f"risk: {prev.get('risk_score')} → {cur.get('risk_score')}")
        if cur.get("mac") and prev.get("mac") and cur["mac"].lower() != prev["mac"].lower():
            diffs.append(f"MAC: {prev['mac']} → {cur['mac']}")
        if diffs:
            changed.append({"ip": ip, "hostname": cur.get("hostname", ip), "changes": diffs})

    return {
        "appeared": appeared,
        "disappeared": disappeared,
        "changed": changed,
        "summary": f"+{len(appeared)} new  -{len(disappeared)} gone  ~{len(changed)} changed",
        "generated_at": _now_iso(),
    }


# ── Watchdog ──────────────────────────────────────────────────────────────────

@app.get("/api/watchdog")
def watchdog():
    """Check which baseline hosts are currently NOT in the ARP table."""
    from core.nexus_collectors import collect_arp_neighbors

    arp_rows = collect_arp_neighbors()
    arp_ips = {r["ip"] for r in arp_rows}
    baseline = get_mac_baseline()

    offline = []
    online = []
    for ip, info in baseline.items():
        if ip in arp_ips:
            online.append(ip)
        else:
            offline.append({
                "ip": ip,
                "mac": info.get("mac", ""),
                "hostname": info.get("hostname", ip),
                "last_seen": info.get("last_seen", ""),
            })

    if offline:
        insert_events([{
            "id": f"evt:watchdog:{_now_iso()}",
            "ts": _now_iso(),
            "severity": "warning",
            "title": "Watchdog: Hosts Offline",
            "summary": f"{len(offline)} baseline host(s) not in ARP table: "
                       + ", ".join(o["ip"] for o in offline[:5]),
        }])

    return {
        "online_count": len(online),
        "offline_count": len(offline),
        "offline": offline,
        "arp_count": len(arp_ips),
        "checked_at": _now_iso(),
    }


# ── Security audit summary ────────────────────────────────────────────────────

@app.get("/api/audit")
def get_audit():
    """Full security posture summary — suitable for report header."""
    import json as _json

    hosts = get_all_hosts()
    baseline = get_mac_baseline()
    events = get_recent_events(limit=200)
    services = []
    try:
        from core.nexus_db import get_all_services
        services = get_all_services()
    except Exception:
        pass

    # Risk distribution
    critical = [h for h in hosts if h.get("status") == "critical"]
    warning  = [h for h in hosts if h.get("status") == "warning"]
    normal   = [h for h in hosts if h.get("status") == "normal"]

    # Randomized MACs
    from core.nexus_risk import _is_randomized_mac
    randomized = [h for h in hosts if _is_randomized_mac(h.get("mac"))]

    # New hosts (not in baseline)
    baseline_ips = set(baseline.keys())
    new_hosts = [h for h in hosts if h["ip"] not in baseline_ips]

    # High-risk ports
    risky_ports = {"21","23","445","3389","5900","4444","6379","9200","27017"}
    exposed = [s for s in services if s.get("port") in risky_ports]

    # CVE-flagged hosts
    cve_hosts = []
    for h in hosts:
        try:
            meta = _json.loads(h.get("meta") or "{}")
        except Exception:
            meta = {}
        if meta.get("cve_count", 0) > 0:
            cve_hosts.append({
                "ip": h["ip"],
                "hostname": h.get("hostname", h["ip"]),
                "cve_count": meta["cve_count"],
            })

    # Recent alerts
    alert_events = [e for e in events if e.get("severity") in ("critical","high","warning")][:20]

    return {
        "generated_at": _now_iso(),
        "summary": {
            "total_hosts": len(hosts),
            "critical": len(critical),
            "warning": len(warning),
            "normal": len(normal),
            "in_baseline": len(baseline_ips),
            "new_hosts": len(new_hosts),
            "randomized_macs": len(randomized),
            "exposed_services": len(exposed),
            "cve_flagged_hosts": len(cve_hosts),
            "total_services": len(services),
            "total_events": len(events),
        },
        "critical_hosts": [{"ip": h["ip"], "hostname": h.get("hostname",""), "risk": h.get("risk_score",0)} for h in critical],
        "warning_hosts":  [{"ip": h["ip"], "hostname": h.get("hostname",""), "risk": h.get("risk_score",0)} for h in warning],
        "new_hosts": [{"ip": h["ip"], "hostname": h.get("hostname",""), "mac": h.get("mac",""), "vendor": h.get("vendor","")} for h in new_hosts],
        "randomized_macs": [{"ip": h["ip"], "mac": h.get("mac",""), "hostname": h.get("hostname","")} for h in randomized],
        "exposed_services": [{"ip": s["ip"], "port": s["port"], "service": s.get("service_name",""), "product": s.get("product","")} for s in exposed],
        "cve_flagged": cve_hosts,
        "recent_alerts": [{"ts": e["ts"], "severity": e["severity"], "title": e["title"], "ip": e.get("ip","")} for e in alert_events],
    }


# ── Security audit summary ────────────────────────────────────────────────────

@app.get("/api/audit")
def get_audit():
    """Full security posture summary — suitable for report header."""
    import json as _json

    hosts = get_all_hosts()
    baseline = get_mac_baseline()
    events = get_recent_events(limit=200)
    services = []
    try:
        from core.nexus_db import get_all_services
        services = get_all_services()
    except Exception:
        pass

    # Risk distribution
    critical = [h for h in hosts if h.get("status") == "critical"]
    warning  = [h for h in hosts if h.get("status") == "warning"]
    normal   = [h for h in hosts if h.get("status") == "normal"]

    # Randomized MACs
    from core.nexus_risk import _is_randomized_mac
    randomized = [h for h in hosts if _is_randomized_mac(h.get("mac"))]

    # New hosts (not in baseline)
    baseline_ips = set(baseline.keys())
    new_hosts = [h for h in hosts if h["ip"] not in baseline_ips]

    # High-risk ports
    risky_ports = {"21","23","445","3389","5900","4444","6379","9200","27017"}
    exposed = [s for s in services if s.get("port") in risky_ports]

    # CVE-flagged hosts
    cve_hosts = []
    for h in hosts:
        try:
            meta = _json.loads(h.get("meta") or "{}")
        except Exception:
            meta = {}
        if meta.get("cve_count", 0) > 0:
            cve_hosts.append({
                "ip": h["ip"],
                "hostname": h.get("hostname", h["ip"]),
                "cve_count": meta["cve_count"],
            })

    # Recent alerts
    alert_events = [e for e in events if e.get("severity") in ("critical","high","warning")][:20]

    return {
        "generated_at": _now_iso(),
        "summary": {
            "total_hosts": len(hosts),
            "critical": len(critical),
            "warning": len(warning),
            "normal": len(normal),
            "in_baseline": len(baseline_ips),
            "new_hosts": len(new_hosts),
            "randomized_macs": len(randomized),
            "exposed_services": len(exposed),
            "cve_flagged_hosts": len(cve_hosts),
            "total_services": len(services),
            "total_events": len(events),
        },
        "critical_hosts": [{"ip": h["ip"], "hostname": h.get("hostname",""), "risk": h.get("risk_score",0)} for h in critical],
        "warning_hosts":  [{"ip": h["ip"], "hostname": h.get("hostname",""), "risk": h.get("risk_score",0)} for h in warning],
        "new_hosts": [{"ip": h["ip"], "hostname": h.get("hostname",""), "mac": h.get("mac",""), "vendor": h.get("vendor","")} for h in new_hosts],
        "randomized_macs": [{"ip": h["ip"], "mac": h.get("mac",""), "hostname": h.get("hostname","")} for h in randomized],
        "exposed_services": [{"ip": s["ip"], "port": s["port"], "service": s.get("service_name",""), "product": s.get("product","")} for s in exposed],
        "cve_flagged": cve_hosts,
        "recent_alerts": [{"ts": e["ts"], "severity": e["severity"], "title": e["title"], "ip": e.get("ip","")} for e in alert_events],
    }


# ── Trap endpoints ─────────────────────────────────────────────────────────────

from core.nexus_traps import (
    deploy_trap, stop_trap, get_all_traps, get_trap,
    get_trap_hits, deploy_bundle, get_all_hits,
)
from pydantic import BaseModel as _TrapModel


class TrapDeployPayload(_TrapModel):
    type: str = "port"
    port: int
    name: str
    banner: str = "generic"


@app.get("/api/traps")
def list_traps():
    traps = get_all_traps()
    active = [t for t in traps if t.get("status") == "active"]
    total_hits = sum(t.get("hit_count", 0) for t in traps)
    return {"traps": traps, "active_count": len(active), "total_hits": total_hits}


@app.post("/api/traps")
def create_trap(payload: TrapDeployPayload):
    trap = deploy_trap(
        trap_type=payload.type,
        port=payload.port,
        name=payload.name,
        banner_key=payload.banner,
    )
    insert_events([{
        "id": f"evt:trap_deploy:{trap['id']}",
        "ts": _now_iso(),
        "severity": "info",
        "title": f"Trap deployed: {payload.name}",
        "summary": f"{payload.type} trap on port {payload.port}",
    }])
    return {"ok": True, "trap": trap}


@app.post("/api/traps/bundle/{bundle_name}")
def deploy_trap_bundle(bundle_name: str):
    deployed = deploy_bundle(bundle_name)
    active = [t for t in deployed if "error" not in t]
    insert_events([{
        "id": f"evt:bundle:{bundle_name}:{_now_iso()}",
        "ts": _now_iso(),
        "severity": "info",
        "title": f"Trap bundle deployed: {bundle_name}",
        "summary": f"{len(active)} traps active",
    }])
    return {"ok": True, "bundle": bundle_name, "deployed": deployed, "active_count": len(active)}


@app.delete("/api/traps/{trap_id}")
def remove_trap(trap_id: str):
    ok = stop_trap(trap_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Trap not found")
    insert_events([{
        "id": f"evt:trap_stop:{trap_id}:{_now_iso()}",
        "ts": _now_iso(),
        "severity": "info",
        "title": f"Trap stopped: {trap_id}",
        "summary": "Trap deactivated by operator",
    }])
    return {"ok": True, "trap_id": trap_id}


@app.get("/api/traps/{trap_id}")
def get_trap_detail(trap_id: str):
    trap = get_trap(trap_id)
    if not trap:
        raise HTTPException(status_code=404, detail="Trap not found")
    return trap


@app.get("/api/traps/{trap_id}/hits")
def trap_hits(trap_id: str):
    hits = get_trap_hits(trap_id)
    return {"trap_id": trap_id, "hits": hits, "count": len(hits)}


@app.get("/api/traps/hits/all")
def all_trap_hits():
    hits = get_all_hits()
    return {"hits": hits[:100], "count": len(hits)}


# ── WebSocket Terminal ────────────────────────────────────────────────────────

import asyncio
import ptyprocess
from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState


@app.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    """
    Real PTY terminal over WebSocket.
    Spawns a bash shell in the LANimals directory.
    xterm.js on the frontend connects here.
    """
    await websocket.accept()

    # Spawn shell in LANimals root
    shell = ptyprocess.PtyProcessUnicode.spawn(
        ["/usr/bin/bash", "--login"],
        cwd=str(ROOT),
        env={
            "TERM": "xterm-256color",
            "HOME": str(Path.home()),
            "USER": "bad_banana",
            "SHELL": "/usr/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
                    + str(Path.home() / ".local/bin"),
            "LANIMALS_ROOT": str(ROOT),
            "PS1": r"\[\033[01;31m\]LANimals\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ ",
        },
    )

    async def read_shell():
        """Read from PTY and send to browser."""
        loop = asyncio.get_event_loop()
        while True:
            try:
                data = await loop.run_in_executor(None, shell.read, 4096)
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_text(data)
            except EOFError:
                break
            except Exception:
                break

    read_task = asyncio.create_task(read_shell())

    try:
        while True:
            msg = await websocket.receive_text()
            try:
                import json as _json
                pkt = _json.loads(msg)
                if pkt.get("type") == "input":
                    shell.write(pkt.get("data", ""))
                elif pkt.get("type") == "resize":
                    rows = int(pkt.get("rows", 24))
                    cols = int(pkt.get("cols", 80))
                    shell.setwinsize(rows, cols)
            except Exception:
                # Raw input fallback
                shell.write(msg)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        read_task.cancel()
        try:
            shell.terminate()
        except Exception:
            pass


# ── WebSocket Terminal ────────────────────────────────────────────────────────

import asyncio
import ptyprocess
from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState


@app.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    """
    Real PTY terminal over WebSocket.
    Spawns a bash shell in the LANimals directory.
    xterm.js on the frontend connects here.
    """
    await websocket.accept()

    # Spawn shell in LANimals root
    shell = ptyprocess.PtyProcessUnicode.spawn(
        ["/usr/bin/bash", "--login"],
        cwd=str(ROOT),
        env={
            "TERM": "xterm-256color",
            "HOME": str(Path.home()),
            "USER": "bad_banana",
            "SHELL": "/usr/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
                    + str(Path.home() / ".local/bin"),
            "LANIMALS_ROOT": str(ROOT),
            "PS1": r"\[\033[01;31m\]LANimals\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ ",
        },
    )

    async def read_shell():
        """Read from PTY and send to browser."""
        loop = asyncio.get_event_loop()
        while True:
            try:
                data = await loop.run_in_executor(None, shell.read, 4096)
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_text(data)
            except EOFError:
                break
            except Exception:
                break

    read_task = asyncio.create_task(read_shell())

    try:
        while True:
            msg = await websocket.receive_text()
            try:
                import json as _json
                pkt = _json.loads(msg)
                if pkt.get("type") == "input":
                    shell.write(pkt.get("data", ""))
                elif pkt.get("type") == "resize":
                    rows = int(pkt.get("rows", 24))
                    cols = int(pkt.get("cols", 80))
                    shell.setwinsize(rows, cols)
            except Exception:
                # Raw input fallback
                shell.write(msg)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        read_task.cancel()
        try:
            shell.terminate()
        except Exception:
            pass
