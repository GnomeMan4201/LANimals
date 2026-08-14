from __future__ import annotations

import json
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from core.nexus_builder import build_snapshot, save_discovery_cache, advance_observation_snapshot
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
from core.nexus_risk import rescore_all_hosts, score_host
from core.nexus_db import (
    init_db, upsert_hosts, upsert_services, insert_events,
    get_all_hosts, get_services_for_ip, get_recent_events,
    get_db_stats, get_mac_baseline, get_pending_baseline_changes,
    accept_baseline_observation, defer_baseline_observation,
    get_baseline_decisions,
    get_host_notes, set_host_notes, get_host,
)
from core.nexus_scope import (
    ScopeError, default_scan_cidr, scope_summary,
    validate_host_target, validate_scan_cidr,
)
from core.nexus_paths import CACHE_DIR, REPORTS_DIR
from core.nexus_terminal import (
    TerminalCommandError, parse_terminal_command, terminal_help,
)
from core.version import VERSION

ROOT = Path(__file__).resolve().parent.parent
UI_FILE = ROOT / "ui" / "lanimals_live_map.html"


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="LANimals", version=VERSION, lifespan=lifespan)


@app.middleware("http")
async def require_operator_header(request: Request, call_next):
    """Block cross-site form requests from triggering local state changes."""
    if (
        request.url.path.startswith("/api/")
        and request.method in {"POST", "PATCH", "PUT", "DELETE"}
        and request.headers.get("x-lanimals-operator") != "1"
    ):
        return JSONResponse(
            status_code=403,
            content={"detail": "missing X-LANimals-Operator request header"},
        )
    return await call_next(request)

# ── Job registry ──────────────────────────────────────────────────────────────
_JOBS: Dict[str, Dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()
_JOB_MAX = 50


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _cidr_or_422(value: Optional[str]) -> str:
    try:
        return validate_scan_cidr(value or default_scan_cidr())
    except ScopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _host_or_422(value: str) -> str:
    try:
        return validate_host_target(value)
    except ScopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


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
        diff = advance_observation_snapshot(cache_data, source="discovery", scope=cidr)
        if diff.get("comparable"):
            _job_log(jid, f"  Observation diff: {diff['summary']}")
        else:
            _job_log(jid, "  Observation baseline recorded; run Discovery again for a diff")
        _job_done(jid, {"host_count": len(seen), "hosts": list(seen.values()), "diff": diff})
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
        upsert_hosts(rows + local)
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
        upsert_hosts(rows)
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
        observations = result.get("observations", [])
        rogue_ips = {item.get("ip") for item in rogues}
        upsert_hosts([
            {
                **item,
                "status": "warning" if item.get("ip") in rogue_ips else "normal",
                "risk_score": 65 if item.get("ip") in rogue_ips else 15,
            }
            for item in observations
        ])
        save_discovery_cache({"nmap_hosts": observations, "cidr": cidr})
        known = result.get("known_count", 0)
        if rogues:
            for r in rogues:
                _job_log(jid, f"  [ROGUE] {r.get('ip',''):18s}  mac={r.get('mac') or '--':20s}  {r.get('reason','')}")
            insert_events([{
                "id": f"evt:baseline:{jid}:{r.get('ip','unknown')}",
                "ts": _now_iso(),
                "severity": "warning",
                "title": "Baseline Change Requires Review",
                "summary": r.get("reason", "Observed identity differs from baseline"),
                "ip": r.get("ip"),
            } for r in rogues])
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
        # SQLite is the operator authority. Keep the JSON cache only as a
        # best-effort compatibility artifact for historical modules.
        upsert_services(services)
        try:
            state = load_service_state()
            svc_map = state.get("services_by_ip", {})
            svc_map[ip] = services
            state["services_by_ip"] = svc_map
            save_service_state(state)
        except Exception:
            pass
        for svc in services:
            _job_log(jid, f"  {svc.get('protocol','tcp'):4s}/{svc.get('port','?'):6s}  {svc.get('service_name',''):16s}  {svc.get('product','')} {svc.get('version','')}")
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
    return {"ok": True, "service": "lanimals", "product": "LANimals", "version": VERSION}


@app.get("/api/scope")
def get_scope():
    """Return the effective local-only scan boundary."""
    return scope_summary()


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
    REPORTS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = []
    for path in sorted(
        REPORTS_DIR.glob("report_*.html"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    ):
        if not path.is_file() or path.is_symlink():
            continue
        stat = path.stat()
        files.append({
            "name": path.name,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "url": f"/api/reports/{path.name}",
        })
    return {"reports": files[:20]}


def _safe_report_name(value: str) -> str:
    name = Path(value).name
    if name != value or not name.startswith("report_") or not name.endswith(".html"):
        raise HTTPException(status_code=400, detail="invalid report name")
    if not re.fullmatch(r"report_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}_[0-9]{6}\.html", name):
        raise HTTPException(status_code=400, detail="invalid report name")
    return name


@app.get("/api/reports/{name}")
def get_report(name: str):
    safe_name = _safe_report_name(name)
    path = REPORTS_DIR / safe_name
    if not path.is_file() or path.is_symlink():
        raise HTTPException(status_code=404, detail="report not found")
    return FileResponse(path, media_type="text/html", filename=safe_name)
@app.get("/api/logs")
def get_logs():
    return {"events": get_recent_events(limit=30)}


@app.get("/api/sysinfo")
def get_sysinfo():
    return collect_sysinfo()


@app.get("/api/services/{ip}")
def get_services(ip: str):
    services = get_services_for_ip(ip)
    return {"ip": ip, "services": services, "count": len(services)}


# ── Scan endpoints ─────────────────────────────────────────────────────────────

@app.post("/api/scan/discovery")
def scan_discovery(cidr: Optional[str] = Query(default=None)):
    cidr = _cidr_or_422(cidr)
    jid = _job_create("discovery", {"cidr": cidr})
    threading.Thread(target=_run_discovery, args=(jid, cidr), daemon=True).start()
    return {"ok": True, "job_id": jid, "op": "discovery", "cidr": cidr}


@app.post("/api/scan/arp")
def scan_arp():
    jid = _job_create("arp_refresh", {})
    threading.Thread(target=_run_arp_refresh, args=(jid,), daemon=True).start()
    return {"ok": True, "job_id": jid, "op": "arp_refresh"}


@app.post("/api/scan/hostmap")
def scan_hostmap(cidr: Optional[str] = Query(default=None)):
    cidr = _cidr_or_422(cidr)
    jid = _job_create("hostmap", {"cidr": cidr})
    threading.Thread(target=_run_hostmap, args=(jid, cidr), daemon=True).start()
    return {"ok": True, "job_id": jid, "op": "hostmap", "cidr": cidr}


@app.post("/api/scan/rogue")
def scan_rogue(cidr: Optional[str] = Query(default=None)):
    cidr = _cidr_or_422(cidr)
    jid = _job_create("rogue", {"cidr": cidr})
    threading.Thread(target=_run_rogue, args=(jid, cidr), daemon=True).start()
    return {"ok": True, "job_id": jid, "op": "rogue", "cidr": cidr}


@app.post("/api/scan/services/{ip}")
def scan_services(ip: str):
    ip = _host_or_422(ip)
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


@app.post("/api/scan/anomaly")
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
    """Generate, persist, and return a local HTML operator report."""
    from fastapi.responses import HTMLResponse
    from html import escape as html_escape

    hosts = get_all_hosts()
    events = get_recent_events(limit=100)
    stats = get_db_stats()
    now = _now_iso()

    def h(value: Any) -> str:
        return html_escape(str(value if value is not None else ""), quote=True)

    rows = ""
    for host in sorted(hosts, key=lambda item: item.get("ip") or ""):
        services = get_services_for_ip(host["ip"])
        svc_str = ", ".join(
            f"{service.get('service_name') or 'service'}:{service.get('port') or '?'}"
            for service in services
        ) or "—"
        status = str(host.get("status") or "normal")
        status_color = "#ff4455" if status == "critical" else "#c97b00" if status == "warning" else "#2a9d4e"
        rows += f"""<tr>
            <td>{h(host.get("ip"))}</td>
            <td>{h(host.get("hostname"))}</td>
            <td>{h(host.get("mac") or "—")}</td>
            <td>{h(host.get("vendor") or "—")}</td>
            <td style="color:{status_color}">{h(status)}</td>
            <td>{h(host.get("risk_score", 0))}</td>
            <td style="font-size:11px">{h(svc_str)}</td>
            <td>{h(host.get("last_seen") or "—")}</td>
        </tr>"""

    event_rows = ""
    for event in events[:50]:
        severity = str(event.get("severity") or "info")
        sev_color = "#ff4455" if severity in ("critical", "high") else "#c97b00" if severity == "warning" else "#3b7ecf"
        event_rows += f"""<tr>
            <td style="color:{sev_color}">{h(severity.upper())}</td>
            <td>{h(event.get("ts"))}</td>
            <td>{h(event.get("title"))}</td>
            <td>{h(event.get("summary"))}</td>
            <td>{h(event.get("ip") or "—")}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<title>LANimals Report — {h(now)}</title>
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
  .footer{{color:#7a8090;font-size:10px;margin-top:48px;}}
</style>
</head><body>
<h1>LANimals</h1>
<h2>Network Intelligence Report — Generated {h(now)}</h2>
<div>
  <div class="stat"><div class="sv">{h(stats["hosts"])}</div><div class="sl">Hosts</div></div>
  <div class="stat"><div class="sv">{h(stats["services"])}</div><div class="sl">Services</div></div>
  <div class="stat"><div class="sv" style="color:#c97b00">{h(stats["warnings"])}</div><div class="sl">Warnings</div></div>
  <div class="stat"><div class="sv">{h(stats["baseline_entries"])}</div><div class="sl">Baseline</div></div>
  <div class="stat"><div class="sv">{h(stats["events"])}</div><div class="sl">Events</div></div>
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
<div class="footer">LANimals v{h(VERSION)} — badBANANA/LANimals</div>
</body></html>"""

    REPORTS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    filename = datetime.now(timezone.utc).strftime("report_%Y-%m-%d_%H-%M-%S_%f.html")
    report_path = REPORTS_DIR / filename
    report_path.write_text(html, encoding="utf-8")
    report_path.chmod(0o600)

    return HTMLResponse(
        content=html,
        headers={"X-LANimals-Report": filename, "Cache-Control": "no-store"},
    )



# ── Notes endpoint ────────────────────────────────────────────────────────────

from pydantic import BaseModel as _BaseModel

class NotesPayload(_BaseModel):
    notes: str


class BaselineDecisionPayload(_BaseModel):
    ip: str
    note: str = ""


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


@app.get("/api/baseline")
def get_baseline():
    entries = list(get_mac_baseline().values())
    pending = get_pending_baseline_changes()
    decisions = get_baseline_decisions(limit=50)
    return {
        "entries": entries,
        "entry_count": len(entries),
        "pending": pending,
        "pending_count": len(pending),
        "decisions": decisions,
        "revision": decisions[0]["id"] if decisions else 0,
    }


@app.post("/api/baseline/accept")
def accept_baseline(payload: BaselineDecisionPayload):
    ip = _host_or_422(payload.ip)
    try:
        decision = accept_baseline_observation(ip, payload.note)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    insert_events([{
        "id": f"evt:baseline:accept:{decision['id']}",
        "ts": decision["ts"],
        "severity": "info",
        "title": "Baseline Observation Accepted",
        "summary": (
            f"{ip} accepted with MAC {decision['observed_mac']}"
            + (f"; note: {decision['note'][:80]}" if decision["note"] else "")
        ),
        "ip": ip,
    }])
    rescore_all_hosts()
    return {"ok": True, "decision": decision}


@app.post("/api/baseline/defer")
def defer_baseline(payload: BaselineDecisionPayload):
    ip = _host_or_422(payload.ip)
    try:
        decision = defer_baseline_observation(ip, payload.note)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    insert_events([{
        "id": f"evt:baseline:defer:{decision['id']}",
        "ts": decision["ts"],
        "severity": "warning",
        "title": "Baseline Observation Deferred",
        "summary": (
            f"{ip} remains unresolved"
            + (f"; note: {decision['note'][:80]}" if decision["note"] else "")
        ),
        "ip": ip,
    }])
    return {"ok": True, "decision": decision, "baseline_changed": False}


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
            headers={"x-apikey": api_key, "User-Agent": f"LANimals/{VERSION}"}
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

def _parse_cvss(value: Any) -> Optional[float]:
    try:
        score = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def _cve_severity(value: Any) -> str:
    score = _parse_cvss(value)
    if score is None:
        return "warning"
    if score >= 7.0:
        return "critical"
    if score >= 4.0:
        return "warning"
    return "info"


def _run_cve_scan(jid: str, ip: str) -> None:
    import shutil, subprocess, json as _json
    from xml.etree import ElementTree as ET
    TMP = CACHE_DIR
    TMP.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        _job_log(jid, f"CVE scan starting on {ip} (nmap vulners)")
        if not shutil.which("nmap"):
            _job_done(jid, None, "nmap not found")
            return

        xml_path = TMP / f"cve_{ip.replace('.','_')}.xml"
        xml_path.unlink(missing_ok=True)
        cmd = ["nmap", "-Pn", "-sV", "--script", "vulners", "-oX", str(xml_path), ip]

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
                "severity": _cve_severity(cve.get("score")),
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
    ip = _host_or_422(ip)
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
    """Compare the last two explicit full Discovery observations."""
    from core.nexus_state import diff_snapshots, load_snapshot_pair

    pair = load_snapshot_pair()
    result = diff_snapshots(pair.get("previous"), pair.get("current"))
    result["generated_at"] = _now_iso()
    return result


# ── Watchdog ──────────────────────────────────────────────────────────────────

@app.post("/api/watchdog")
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


# ── WebSocket Operator Command Bridge ────────────────────────────────────────

_TERMINAL_PROMPT = "\r\n\x1b[38;5;88mLANimals\x1b[0m> "


def _start_terminal_job(action: str, target: Optional[str]) -> dict[str, Any]:
    if action == "scan:arp":
        jid = _job_create("arp_refresh", {})
        runner, args = _run_arp_refresh, (jid,)
    elif action in {"scan:discovery", "scan:hostmap", "scan:rogue"}:
        cidr = _cidr_or_422(target)
        operation = action.split(":", 1)[1]
        jid = _job_create(operation, {"cidr": cidr})
        runner = {
            "discovery": _run_discovery,
            "hostmap": _run_hostmap,
            "rogue": _run_rogue,
        }[operation]
        args = (jid, cidr)
    elif action in {"scan:services", "scan:cve"}:
        ip = _host_or_422(target or "")
        operation = action.split(":", 1)[1]
        jid = _job_create(operation, {"ip": ip})
        runner = _run_service_scan if operation == "services" else _run_cve_scan
        args = (jid, ip)
    else:
        raise TerminalCommandError("unsupported scan operation")
    threading.Thread(target=runner, args=args, daemon=True).start()
    return {"job_id": jid, "operation": action, "target": target}


def _terminal_output(raw: str) -> tuple[list[str], bool]:
    command = parse_terminal_command(raw)
    if command.action == "help":
        return terminal_help(), False
    if command.action == "clear":
        return [], True
    if command.action == "status":
        stats = get_db_stats()
        return [f"{key}: {value}" for key, value in sorted(stats.items())], False
    if command.action == "hosts":
        hosts = get_all_hosts()
        lines = [
            f"{host.get('ip', ''):15s}  {host.get('mac') or '--':17s}  "
            f"{host.get('status', 'normal'):8s}  {host.get('hostname') or '--'}"
            for host in hosts
        ]
        return lines or ["No observed hosts. Run: scan discovery"], False
    if command.action == "events":
        events = get_recent_events(limit=20)
        lines = [
            f"[{event.get('severity', 'info').upper():8s}] "
            f"{event.get('ts', '')}  {event.get('title', '')}"
            for event in events
        ]
        return lines or ["No recorded events."], False
    if command.action == "baseline":
        pending = get_pending_baseline_changes()
        lines = [
            f"{item['status'].upper():7s} {item['ip']:15s}  "
            f"baseline={item.get('baseline_mac') or '--'}  observed={item.get('observed_mac') or '--'}"
            for item in pending
        ]
        return lines or ["No unresolved baseline changes."], False
    if command.action == "sysinfo":
        info = collect_sysinfo()
        return json.dumps(info, indent=2, sort_keys=True).splitlines(), False
    if command.action == "report":
        return ["Report endpoint: /api/export/report"], False
    if command.action.startswith("scan:"):
        job = _start_terminal_job(command.action, command.target)
        return [
            f"Queued {job['operation']} as job {job['job_id']}.",
            f"Inspect progress: /api/jobs/{job['job_id']}",
        ], False
    raise TerminalCommandError("unsupported command")


@app.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    """Expose LANimals operations without exposing the host operating-system shell."""
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host")
    if origin and (not host or urlsplit(origin).netloc.lower() != host.lower()):
        await websocket.close(code=1008, reason="cross-origin terminal connection refused")
        return
    await websocket.accept()
    await websocket.send_text(
        "LANimals operator command bridge\r\n"
        "Type 'help' for approved commands. This is not a system shell."
        + _TERMINAL_PROMPT
    )
    line = ""
    try:
        while True:
            message = await websocket.receive_text()
            try:
                packet = json.loads(message)
                if packet.get("type") != "input":
                    continue
                data = str(packet.get("data", ""))
            except (json.JSONDecodeError, TypeError, AttributeError):
                data = message

            for char in data:
                if char in {"\r", "\n"}:
                    await websocket.send_text("\r\n")
                    try:
                        output, clear = _terminal_output(line)
                        if clear:
                            await websocket.send_text("\x1b[2J\x1b[H")
                        elif output:
                            await websocket.send_text("\r\n".join(output))
                    except HTTPException as exc:
                        await websocket.send_text(f"[ERROR] {exc.detail}")
                    except TerminalCommandError as exc:
                        await websocket.send_text(f"[ERROR] {exc}")
                    except Exception as exc:
                        await websocket.send_text(f"[ERROR] operation failed: {exc}")
                    line = ""
                    await websocket.send_text(_TERMINAL_PROMPT)
                elif char in {"\x7f", "\b"}:
                    if line:
                        line = line[:-1]
                        await websocket.send_text("\b \b")
                elif char == "\x03":
                    line = ""
                    await websocket.send_text("^C" + _TERMINAL_PROMPT)
                elif char.isprintable() and len(line) < 512:
                    line += char
                    await websocket.send_text(char)
    except WebSocketDisconnect:
        return
