from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.nexus_collectors import collect_all
from core.nexus_models import GraphEdge, GraphEvent, GraphNode, GraphSnapshot


ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports"


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _safe_load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _latest_reports(limit: int = 4) -> List[Path]:
    if not REPORTS_DIR.exists():
        return []
    return sorted(REPORTS_DIR.glob("report_*.json"))[-limit:]


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

        _add_node(
            nodes,
            GraphNode(
                id=node_id,
                node_type="host",
                label=hostname,
                hostname=hostname,
                ip=ip,
                mac=mac,
                status=status,
                risk_score=risk,
                group=group,
                meta={
                    "open_ports": open_ports if isinstance(open_ports, list) else [],
                    "source": "lanimals_report",
                },
            ),
        )

        _add_edge(
            edges,
            GraphEdge(
                id=_edge_id(subnet_id, node_id, "contains"),
                source=subnet_id,
                target=node_id,
                edge_type="contains",
                status="normal",
            ),
        )

        if isinstance(open_ports, list):
            for port in open_ports[:8]:
                port_val = str(port)
                svc_id = f"service:{hostname}:{port_val}"
                _add_node(
                    nodes,
                    GraphNode(
                        id=svc_id,
                        node_type="service",
                        label=port_val,
                        status="normal",
                        risk_score=10,
                        group=group,
                        meta={"port": port_val},
                    ),
                )
                _add_edge(
                    edges,
                    GraphEdge(
                        id=_edge_id(node_id, svc_id, "offers_service"),
                        source=node_id,
                        target=svc_id,
                        edge_type="offers_service",
                        status="normal",
                    ),
                )

        if rogue:
            events.append(
                GraphEvent(
                    id=f"evt:rogue:{node_id}",
                    ts=_now(),
                    severity="high",
                    title="Rogue Host Flagged",
                    summary=f"{hostname} was marked as rogue in LANimals report data.",
                    node_id=node_id,
                )
            )

    for idx, alert in enumerate(alerts, start=1):
        title = (
            alert.get("title")
            or alert.get("name")
            or alert.get("type")
            or f"Alert {idx}"
        )
        severity = str(alert.get("severity") or "warning").lower()
        summary = alert.get("summary") or alert.get("description") or title
        target_ip = alert.get("ip") or alert.get("host") or alert.get("target")
        target_id = f"host:{target_ip}" if target_ip else None

        alert_id = f"alert:{idx}:{title}".replace(" ", "_")
        _add_node(
            nodes,
            GraphNode(
                id=alert_id,
                node_type="alert",
                label=title,
                status="critical" if severity in ("high", "critical") else "warning",
                risk_score=90 if severity in ("high", "critical") else 60,
                meta={"summary": summary, "severity": severity},
            ),
        )

        if target_id and target_id in nodes:
            _add_edge(
                edges,
                GraphEdge(
                    id=_edge_id(alert_id, target_id, "targets"),
                    source=alert_id,
                    target=target_id,
                    edge_type="targets",
                    status="critical" if severity in ("high", "critical") else "warning",
                ),
            )

        events.append(
            GraphEvent(
                id=f"evt:alert:{idx}",
                ts=_now(),
                severity=severity,
                title=title,
                summary=summary,
                node_id=target_id,
            )
        )

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

        subnet_id = _ensure_subnet(nodes, ip)
        group = _host_group_from_ip(ip)
        node_id = f"host:{ip}"

        risk = 15
        status = "normal"

        if state.upper() in ("STALE", "DELAY", "FAILED", "INCOMPLETE"):
            status = "warning"
            risk = 35

        _add_node(
            nodes,
            GraphNode(
                id=node_id,
                node_type="host",
                label=hostname,
                hostname=hostname,
                ip=ip,
                mac=mac,
                status=status,
                risk_score=risk,
                group=group,
                meta={
                    "interface": interface,
                    "neighbor_state": state,
                    "source": source,
                },
            ),
        )

        _add_edge(
            edges,
            GraphEdge(
                id=_edge_id(subnet_id, node_id, "contains"),
                source=subnet_id,
                target=node_id,
                edge_type="contains",
                status="normal",
            ),
        )

        if interface:
            iface_id = f"iface:{interface}"
            _add_node(
                nodes,
                GraphNode(
                    id=iface_id,
                    node_type="interface",
                    label=interface,
                    status="normal",
                    risk_score=5,
                    group=group,
                    meta={"source": "collector"},
                ),
            )
            _add_edge(
                edges,
                GraphEdge(
                    id=_edge_id(iface_id, node_id, "sees"),
                    source=iface_id,
                    target=node_id,
                    edge_type="sees",
                    status="normal",
                ),
            )

    return list(nodes.values()), list(edges.values()), events


def build_snapshot() -> GraphSnapshot:
    all_nodes: Dict[str, GraphNode] = {}
    all_edges: Dict[str, GraphEdge] = {}
    all_events: List[GraphEvent] = []

    reports = _latest_reports()

    for report_path in reports:
        report = _safe_load_json(report_path)
        nodes, edges, events = _normalize_report_nodes(report)

        for node in nodes:
            _add_node(all_nodes, node)
        for edge in edges:
            _add_edge(all_edges, edge)
        all_events.extend(events)

    collector_data = collect_all(cidr="192.168.1.0/24")
    c_nodes, c_edges, c_events = _normalize_collector_data(collector_data)

    for node in c_nodes:
        _add_node(all_nodes, node)
    for edge in c_edges:
        _add_edge(all_edges, edge)
    all_events.extend(c_events)

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

        all_events.extend(
            [
                GraphEvent(
                    id="evt:boot:1",
                    ts=_now(),
                    severity="info",
                    title="LANimals graph initialized",
                    summary="Fallback graph loaded because no parseable data was found.",
                ),
                GraphEvent(
                    id="evt:boot:2",
                    ts=_now(),
                    severity="high",
                    title="Rogue Host Flagged",
                    summary="Unknown-Host requires triage.",
                    node_id=ws2.id,
                ),
            ]
        )

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
        events=sorted(all_events, key=lambda e: e.ts, reverse=True)[:30],
        stats=stats,
    )
