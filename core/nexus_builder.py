from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.nexus_models import GraphEdge, GraphEvent, GraphNode, GraphSnapshot
from core.nexus_service_state import load_service_state
from core.nexus_state import load_state, save_state

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports"
TMP_DIR = ROOT / "tmp"
DISCOVERY_CACHE = TMP_DIR / "nexus_discovery_cache.json"


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _safe_load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _latest_reports(limit: int = 4, max_age_days: int = 7) -> List[Path]:
    """Return recent reports. Uses filename date (YYYY-MM-DD) to avoid mtime tricks."""
    if not REPORTS_DIR.exists():
        return []
    from datetime import datetime, timezone
    import re
    cutoff = datetime.now(timezone.utc).timestamp() - max_age_days * 86400
    files = []
    for p in REPORTS_DIR.glob("report_*.json"):
        # Filename: report_YYYY-MM-DD_HH-MM-SS.json
        m = re.search(r"report_(\d{4}-\d{2}-\d{2})", p.name)
        if m:
            try:
                file_ts = datetime.strptime(m.group(1), "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                ).timestamp()
                if file_ts >= cutoff:
                    files.append(p)
            except ValueError:
                pass
        else:
            # No date in filename — fall back to mtime
            if p.stat().st_mtime >= cutoff:
                files.append(p)
    return sorted(files)[-limit:]


def _add_node(nodes: Dict[str, GraphNode], node: GraphNode) -> None:
    existing = nodes.get(node.id)
    if not existing:
        nodes[node.id] = node
        return
    if node.risk_score > existing.risk_score:
        existing.risk_score = node.risk_score
    severity_rank = {"normal": 0, "warning": 1, "critical": 2}
    if severity_rank.get(node.status, 0) > severity_rank.get(existing.status, 0):
        existing.status = node.status
    for field in ("ip", "mac", "hostname", "group"):
        if getattr(existing, field) in (None, "", "unknown") and getattr(node, field):
            setattr(existing, field, getattr(node, field))
    for k, v in node.meta.items():
        if k not in existing.meta:
            existing.meta[k] = v


def _add_edge(edges: Dict[str, GraphEdge], edge: GraphEdge) -> None:
    edges[edge.id] = edge


def _edge_id(source: str, target: str, edge_type: str) -> str:
    return f"{edge_type}:{source}->{target}"


def _host_group_from_ip(ip: str | None) -> str:
    if not ip or "." not in ip:
        return "unknown"
    parts = ip.split(".")
    if len(parts) != 4:
        return "unknown"
    return ".".join(parts[:3]) + ".0/24"


def _ensure_subnet(nodes: Dict[str, GraphNode], ip: str | None) -> str:
    group = _host_group_from_ip(ip)
    subnet_id = f"subnet:{group}"
    if subnet_id not in nodes:
        _add_node(
            nodes,
            GraphNode(
                id=subnet_id,
                node_type="subnet",
                label=group,
                status="normal",
                risk_score=5,
                group=group,
            ),
        )
    return subnet_id


def _merge_threatenrich_report(items: List[dict]) -> List[dict]:
    """Collapse {host, product, version, vulns, exploits} list into per-host dicts with services."""
    by_host: Dict[str, dict] = {}
    for item in items:
        host = item.get("host") or item.get("ip")
        if not host:
            continue
        if host not in by_host:
            by_host[host] = {"ip": host, "hostname": host, "services": []}
        product = item.get("product", "")
        version = item.get("version", "")
        vulns = item.get("vulns", "")
        exploits = item.get("exploits", {})
        if product:
            svc: Dict[str, Any] = {"product": product, "version": version}
            if vulns and "No ecosystem" not in str(vulns):
                svc["vulns"] = vulns
            if exploits:
                svc["exploits"] = exploits
            by_host[host]["services"].append(svc)
        # Elevate risk if exploits found
        if exploits and isinstance(exploits, dict) and any(exploits.values()):
            by_host[host]["has_exploits"] = True
    return list(by_host.values())


def _extract_hosts_and_alerts(report: Any) -> Tuple[List[dict], List[dict]]:
    hosts: List[dict] = []
    alerts: List[dict] = []
    if isinstance(report, dict):
        for key in ("hosts", "devices", "alive_hosts", "live_hosts", "inventory"):
            value = report.get(key)
            if isinstance(value, list):
                hosts.extend([x for x in value if isinstance(x, dict)])
        for key in ("alerts", "findings", "threats", "anomalies", "rogues"):
            value = report.get(key)
            if isinstance(value, list):
                alerts.extend([x for x in value if isinstance(x, dict)])
    elif isinstance(report, list):
        dict_items = [x for x in report if isinstance(x, dict)]
        # Detect threatenrich format: list of {host, product, version, vulns, exploits}
        if dict_items and all("host" in i and "product" in i for i in dict_items[:3]):
            hosts.extend(_merge_threatenrich_report(dict_items))
            return hosts, alerts
        for item in dict_items:
            keys = set(item.keys())
            if {"ip", "hostname"} & keys or {"ip", "mac"} & keys or {"host", "ports"} <= keys:
                hosts.append(item)
                continue
            if {"severity", "summary"} & keys or {"type", "severity"} <= keys:
                alerts.append(item)
                continue
        if not hosts and not alerts:
            for item in dict_items:
                if any(k in item for k in ("ip", "address", "host", "hostname", "mac")):
                    hosts.append(item)
    return hosts, alerts


def _normalize_report_nodes(report: Any) -> Tuple[List[GraphNode], List[GraphEdge], List[GraphEvent]]:
    nodes: Dict[str, GraphNode] = {}
    edges: Dict[str, GraphEdge] = {}
    events: List[GraphEvent] = []
    hosts, alerts = _extract_hosts_and_alerts(report)

    for idx, host in enumerate(hosts, start=1):
        ip = host.get("ip") or host.get("address") or host.get("host")
        hostname = host.get("hostname") or host.get("name") or ip or f"host-{idx}"
        mac = host.get("mac") or host.get("mac_address")
        open_ports = host.get("ports") or host.get("open_ports") or []
        rogue = bool(host.get("rogue")) or bool(host.get("is_rogue"))
        status = "warning" if rogue else "normal"
        risk = 80 if rogue else 15
        group = _host_group_from_ip(ip)
        subnet_id = _ensure_subnet(nodes, ip)
        node_id = f"host:{ip or hostname}"
        report_services = host.get("services") or []
        has_exploits = bool(host.get("has_exploits"))
        if has_exploits:
            risk = max(risk, 70)
            status = "warning" if status == "normal" else status
        _add_node(nodes, GraphNode(
            id=node_id, node_type="host", label=hostname, hostname=hostname,
            ip=ip, mac=mac, status=status, risk_score=risk, group=group,
            meta={"open_ports": open_ports if isinstance(open_ports, list) else [],
                  "source": "lanimals_report",
                  "report_services": report_services},
        ))
        _add_edge(edges, GraphEdge(
            id=_edge_id(subnet_id, node_id, "contains"),
            source=subnet_id, target=node_id, edge_type="contains", status="normal",
        ))

    for idx, alert in enumerate(alerts, start=1):
        title = alert.get("title") or alert.get("name") or alert.get("type") or f"Alert {idx}"
        severity = str(alert.get("severity") or "warning").lower()
        summary = alert.get("summary") or alert.get("description") or title
        target_ip = alert.get("ip") or alert.get("host") or alert.get("target")
        target_id = f"host:{target_ip}" if target_ip else None
        alert_id = f"alert:{idx}:{title}".replace(" ", "_")
        _add_node(nodes, GraphNode(
            id=alert_id, node_type="alert", label=title,
            status="critical" if severity in ("high", "critical") else "warning",
            risk_score=90 if severity in ("high", "critical") else 60,
            meta={"summary": summary, "severity": severity},
        ))
        if target_id and target_id in nodes:
            _add_edge(edges, GraphEdge(
                id=_edge_id(alert_id, target_id, "targets"),
                source=alert_id, target=target_id, edge_type="targets",
                status="critical" if severity in ("high", "critical") else "warning",
            ))
        events.append(GraphEvent(
            id=f"evt:alert:{idx}", ts=_now(), severity=severity,
            title=title, summary=summary, node_id=target_id,
        ))

    return list(nodes.values()), list(edges.values()), events


def _normalize_collector_data(data: Dict[str, Any]) -> Tuple[List[GraphNode], List[GraphEdge], List[GraphEvent]]:
    nodes: Dict[str, GraphNode] = {}
    edges: Dict[str, GraphEdge] = {}
    events: List[GraphEvent] = []

    all_hosts: List[Dict[str, Any]] = []
    all_hosts.extend(data.get("arp_neighbors", []))
    all_hosts.extend(data.get("local_interfaces", []))
    all_hosts.extend(data.get("nmap_hosts", []))

    for item in all_hosts:
        ip = item.get("ip")
        if not ip:
            continue
        hostname = item.get("hostname") or ip
        mac = item.get("mac")
        interface = item.get("interface")
        state = str(item.get("state") or "UNKNOWN")
        source = item.get("source") or "collector"
        vendor = item.get("vendor") or None
        subnet_id = _ensure_subnet(nodes, ip)
        group = _host_group_from_ip(ip)
        node_id = f"host:{ip}"
        risk = 15
        status = "normal"
        if state.upper() in ("STALE", "DELAY", "FAILED", "INCOMPLETE"):
            status = "warning"
            risk = 35
        meta: Dict[str, Any] = {
            "interface": interface,
            "neighbor_state": state,
            "source": source,
        }
        if vendor:
            meta["vendor"] = vendor
        if mac:
            meta["mac"] = mac
        _add_node(nodes, GraphNode(
            id=node_id, node_type="host", label=hostname, hostname=hostname,
            ip=ip, mac=mac, status=status, risk_score=risk, group=group, meta=meta,
        ))
        _add_edge(edges, GraphEdge(
            id=_edge_id(subnet_id, node_id, "contains"),
            source=subnet_id, target=node_id, edge_type="contains", status="normal",
        ))
        if interface:
            iface_id = f"iface:{interface}"
            _add_node(nodes, GraphNode(
                id=iface_id, node_type="interface", label=interface,
                status="normal", risk_score=5, group=group,
                meta={"source": "collector"},
            ))
            _add_edge(edges, GraphEdge(
                id=_edge_id(iface_id, node_id, "sees"),
                source=iface_id, target=node_id, edge_type="sees", status="normal",
            ))

    return list(nodes.values()), list(edges.values()), events


def _merge_cached_services(
    nodes: Dict[str, GraphNode], edges: Dict[str, GraphEdge], events: List[GraphEvent]
) -> None:
    svc_state = load_service_state()
    services_by_ip = svc_state.get("services_by_ip", {})
    for ip, svc_rows in services_by_ip.items():
        host_id = f"host:{ip}"
        if host_id not in nodes:
            continue
        host_group = nodes[host_id].group
        service_summaries = []
        for svc in svc_rows:
            port = str(svc.get("port") or "")
            protocol = svc.get("protocol") or "tcp"
            service_name = svc.get("service_name") or "service"
            product = svc.get("product") or ""
            version = svc.get("version") or ""
            svc_id = f"service:{ip}:{protocol}:{port}"
            _add_node(nodes, GraphNode(
                id=svc_id, node_type="service", label=f"{service_name}:{port}",
                status="normal", risk_score=20, group=host_group,
                meta={"port": port, "protocol": protocol, "service_name": service_name,
                      "product": product, "version": version,
                      "source": svc.get("source", "service_cache")},
            ))
            _add_edge(edges, GraphEdge(
                id=_edge_id(host_id, svc_id, "offers_service"),
                source=host_id, target=svc_id, edge_type="offers_service", status="normal",
            ))
            service_summaries.append({
                "port": port, "protocol": protocol, "service_name": service_name,
                "product": product, "version": version,
            })
        nodes[host_id].meta["services"] = service_summaries


def _generate_state_events(nodes: Dict[str, GraphNode]) -> List[GraphEvent]:
    now = _now()
    current_hosts = {}
    for node in nodes.values():
        if node.node_type == "host" and node.ip:
            current_hosts[node.ip] = {
                "label": node.label, "status": node.status,
                "risk_score": node.risk_score, "group": node.group,
            }
    prev = load_state()
    prev_hosts = prev.get("hosts", {})
    events: List[GraphEvent] = []
    current_ips = set(current_hosts.keys())
    prev_ips = set(prev_hosts.keys())

    for ip in sorted(current_ips - prev_ips):
        info = current_hosts[ip]
        events.append(GraphEvent(
            id=f"evt:new:{ip}:{now}", ts=now, severity="info",
            title="New Host Observed",
            summary=f'{info["label"]} appeared on {info["group"]}.',
            node_id=f"host:{ip}",
        ))
    for ip in sorted(prev_ips - current_ips):
        info = prev_hosts[ip]
        events.append(GraphEvent(
            id=f"evt:gone:{ip}:{now}", ts=now, severity="warning",
            title="Host Missing",
            summary=f'{info["label"]} is no longer visible.',
            node_id=f"host:{ip}",
        ))
    for ip in sorted(current_ips & prev_ips):
        cur = current_hosts[ip]
        old = prev_hosts[ip]
        if cur["status"] != old.get("status"):
            sev = "warning" if cur["status"] == "warning" else "info"
            events.append(GraphEvent(
                id=f"evt:status:{ip}:{now}", ts=now, severity=sev,
                title="Host Status Changed",
                summary=f'{cur["label"]} status: {old.get("status")} → {cur["status"]}.',
                node_id=f"host:{ip}",
            ))

    save_state({"hosts": current_hosts, "saved_at": now})
    return events


def _load_discovery_cache() -> Dict[str, Any]:
    """Read cached discovery results written by scan jobs. Never runs nmap."""
    if not DISCOVERY_CACHE.exists():
        return {}
    try:
        return json.loads(DISCOVERY_CACHE.read_text())
    except Exception:
        return {}


_VIRTUAL_IP_PREFIXES_BUILD = ("172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                               "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                               "172.29.", "172.30.", "172.31.", "10.0.3.", "10.0.2.")
_VIRTUAL_IFACE_PREFIXES_BUILD = ("docker", "veth", "virbr", "br-", "lxc", "lxd", "vbox", "vmnet",
                                  "tun", "tap", "wg", "utun")


def _filter_virtual_hosts(rows: list) -> list:
    out = []
    for h in rows:
        ip = h.get("ip") or ""
        iface = h.get("interface") or ""
        if any(ip.startswith(p) for p in _VIRTUAL_IP_PREFIXES_BUILD):
            continue
        if any(iface.lower().startswith(p) for p in _VIRTUAL_IFACE_PREFIXES_BUILD):
            continue
        out.append(h)
    return out


def save_discovery_cache(data: Dict[str, Any]) -> None:
    """Called by scan jobs to persist results. Filters virtual interfaces before writing."""
    TMP_DIR.mkdir(exist_ok=True)
    existing = _load_discovery_cache()
    # Merge lists, filtering virtual entries
    for key in ("arp_neighbors", "local_interfaces", "nmap_hosts"):
        if key in data:
            existing[key] = _filter_virtual_hosts(data[key])
        elif key not in existing:
            existing[key] = []
    for key in ("cidr",):
        if key in data:
            existing[key] = data[key]
    existing["saved_at"] = _now()
    DISCOVERY_CACHE.write_text(json.dumps(existing, indent=2))


def build_snapshot() -> GraphSnapshot:
    all_nodes: Dict[str, GraphNode] = {}
    all_edges: Dict[str, GraphEdge] = {}
    all_events: List[GraphEvent] = []

    # 1. Load from report files
    for report_path in _latest_reports():
        report = _safe_load_json(report_path)
        nodes, edges, events = _normalize_report_nodes(report)
        for node in nodes:
            _add_node(all_nodes, node)
        for edge in edges:
            _add_edge(all_edges, edge)
        all_events.extend(events)

    # 2. Load from persisted discovery cache (written by scan jobs — no live nmap here)
    cache = _load_discovery_cache()
    if cache:
        c_nodes, c_edges, c_events = _normalize_collector_data(cache)
        for node in c_nodes:
            _add_node(all_nodes, node)
        for edge in c_edges:
            _add_edge(all_edges, edge)
        all_events.extend(c_events)

    # 3. Cheap live ARP only (no nmap, fast)
    if not cache:
        try:
            from core.nexus_collectors import collect_arp_neighbors, collect_local_interfaces
            quick = {
                "arp_neighbors": collect_arp_neighbors(),
                "local_interfaces": collect_local_interfaces(),
                "nmap_hosts": [],
            }
            q_nodes, q_edges, q_events = _normalize_collector_data(quick)
            for node in q_nodes:
                _add_node(all_nodes, node)
            for edge in q_edges:
                _add_edge(all_edges, edge)
            all_events.extend(q_events)
        except Exception:
            pass

    # 4. Merge cached services
    _merge_cached_services(all_nodes, all_edges, all_events)

    # 5. Fallback demo graph if nothing loaded
    if not all_nodes:
        subnet = GraphNode(id="subnet:192.168.1.0/24", node_type="subnet", label="192.168.1.0/24", risk_score=5)
        router = GraphNode(id="host:192.168.1.1", node_type="router", label="Gateway", ip="192.168.1.1", risk_score=20)
        ws1 = GraphNode(id="host:192.168.1.20", node_type="host", label="Workstation-01", ip="192.168.1.20", risk_score=25)
        ws2 = GraphNode(id="host:192.168.1.88", node_type="host", label="Unknown-Host", ip="192.168.1.88", risk_score=85, status="warning")
        alert = GraphNode(id="alert:rogue-88", node_type="alert", label="Rogue Host", risk_score=95, status="critical")
        for n in (subnet, router, ws1, ws2, alert):
            all_nodes[n.id] = n
        for e in (
            GraphEdge(id="contains:subnet-router", source=subnet.id, target=router.id, edge_type="contains"),
            GraphEdge(id="contains:subnet-ws1", source=subnet.id, target=ws1.id, edge_type="contains"),
            GraphEdge(id="contains:subnet-ws2", source=subnet.id, target=ws2.id, edge_type="contains"),
            GraphEdge(id="targets:alert-ws2", source=alert.id, target=ws2.id, edge_type="targets", status="critical"),
        ):
            all_edges[e.id] = e
        all_events.extend([
            GraphEvent(id="evt:boot:1", ts=_now(), severity="info",
                       title="LANimals initialized", summary="Run Discovery Scan to populate the graph."),
            GraphEvent(id="evt:boot:2", ts=_now(), severity="high",
                       title="Rogue Host Flagged", summary="Unknown-Host requires triage.", node_id=ws2.id),
        ])

    all_events.extend(_generate_state_events(all_nodes))

    stats = {
        "total_nodes": len(all_nodes),
        "total_edges": len(all_edges),
        "hosts": len([n for n in all_nodes.values() if n.node_type in ("host", "router")]),
        "alerts": len([n for n in all_nodes.values() if n.node_type == "alert"]),
        "critical_nodes": len([n for n in all_nodes.values() if n.status == "critical"]),
        "warning_nodes": len([n for n in all_nodes.values() if n.status == "warning"]),
    }

    return GraphSnapshot(
        title="LANimals",
        subtitle="Live Network Map",
        generated_at=_now(),
        nodes=list(all_nodes.values()),
        edges=list(all_edges.values()),
        events=sorted(all_events, key=lambda e: e.ts, reverse=True)[:60],
        stats=stats,
    )
