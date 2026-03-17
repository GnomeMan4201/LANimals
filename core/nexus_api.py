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
from core.nexus_db import (
    init_db, upsert_hosts, upsert_services, insert_events,
    get_all_hosts, get_services_for_ip, get_recent_events,
    get_db_stats, update_mac_baseline, get_mac_baseline,
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

