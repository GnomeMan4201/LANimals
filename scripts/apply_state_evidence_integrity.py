from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    (ROOT / path).write_text(content, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one literal match, found {count}")
    write(path, text.replace(old, new, 1))


def regex_once(path: str, pattern: str, replacement: str) -> None:
    text = read(path)
    rendered, count = re.subn(pattern, lambda _: replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one regex match, found {count}")
    write(path, rendered)


STATE_SOURCE = '''from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from core.nexus_paths import DATA_DIR

SNAPSHOT_STATE_FILE = DATA_DIR / "network_snapshot.json"
LEGACY_STATE_FILE = DATA_DIR / "nexus_state.json"
SNAPSHOT_SCHEMA_VERSION = 2


def _normalize_snapshot(data: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(data, dict):
        return None
    hosts = data.get("hosts")
    if not isinstance(hosts, dict):
        return None
    normalized_hosts: Dict[str, Dict[str, Any]] = {}
    for key, value in hosts.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        ip = str(value.get("ip") or key)
        normalized_hosts[ip] = {
            "ip": ip,
            "hostname": value.get("hostname") or value.get("label") or ip,
            "label": value.get("label") or value.get("hostname") or ip,
            "mac": value.get("mac"),
            "status": value.get("status") or "normal",
            "risk_score": int(value.get("risk_score") or 0),
            "group": value.get("group"),
            "last_seen": value.get("last_seen"),
            "observed_at": value.get("observed_at") or data.get("saved_at"),
            "source": value.get("source") or data.get("source"),
        }
    return {
        "hosts": normalized_hosts,
        "saved_at": data.get("saved_at"),
        "source": data.get("source"),
        "scope": data.get("scope"),
    }


def _state_path() -> Path:
    if SNAPSHOT_STATE_FILE.exists():
        return SNAPSHOT_STATE_FILE
    return LEGACY_STATE_FILE


def load_snapshot_pair() -> Dict[str, Any]:
    path = _state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"schema_version": SNAPSHOT_SCHEMA_VERSION, "previous": None, "current": None}

    if isinstance(data, dict) and data.get("schema_version") == SNAPSHOT_SCHEMA_VERSION:
        return {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "previous": _normalize_snapshot(data.get("previous")),
            "current": _normalize_snapshot(data.get("current")),
        }

    # Compatibility with the pre-v2 single-snapshot file. Treat it as current;
    # the next explicit acquisition will shift it to previous.
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "previous": None,
        "current": _normalize_snapshot(data),
    }


def load_snapshot_state() -> Dict[str, Any]:
    """Compatibility reader returning the current snapshot's legacy shape."""
    current = load_snapshot_pair().get("current")
    if not current:
        return {}
    return {"hosts": current["hosts"], "saved_at": current.get("saved_at")}


def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise ValueError(f"refusing symlinked snapshot state: {path}")
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temp_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def advance_snapshot_state(data: Dict[str, Any]) -> Dict[str, Any]:
    """Advance the observation baseline only after an explicit acquisition."""
    current = _normalize_snapshot(data)
    if current is None:
        raise ValueError("snapshot state requires a hosts mapping")
    pair = load_snapshot_pair()
    payload = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "previous": pair.get("current"),
        "current": current,
    }
    _atomic_write_json(SNAPSHOT_STATE_FILE, payload)
    return payload


def save_snapshot_state(data: Dict[str, Any]) -> None:
    """Compatibility alias. New code should call advance_snapshot_state explicitly."""
    advance_snapshot_state(data)


def diff_snapshots(previous: Any, current: Any) -> Dict[str, Any]:
    prev = _normalize_snapshot(previous)
    cur = _normalize_snapshot(current)
    if not prev or not cur:
        return {
            "comparable": False,
            "reason": "two explicit observation snapshots are required",
            "appeared": [], "disappeared": [], "changed": [],
            "summary": "No comparable discovery snapshots yet",
        }
    if prev.get("scope") and cur.get("scope") and prev["scope"] != cur["scope"]:
        return {
            "comparable": False,
            "reason": f"observation scopes differ: {prev['scope']} vs {cur['scope']}",
            "appeared": [], "disappeared": [], "changed": [],
            "summary": "Discovery snapshots use different scopes",
        }

    prev_hosts = prev["hosts"]
    cur_hosts = cur["hosts"]
    prev_ips = set(prev_hosts)
    cur_ips = set(cur_hosts)

    appeared = [cur_hosts[ip] for ip in sorted(cur_ips - prev_ips)]
    disappeared = [prev_hosts[ip] for ip in sorted(prev_ips - cur_ips)]
    changed = []
    for ip in sorted(cur_ips & prev_ips):
        old = prev_hosts[ip]
        new = cur_hosts[ip]
        changes = []
        old_mac = old.get("mac")
        new_mac = new.get("mac")
        if old_mac and new_mac and str(old_mac).lower() != str(new_mac).lower():
            changes.append(f"MAC: {old_mac} → {new_mac}")
        if old.get("status") != new.get("status"):
            changes.append(f"status: {old.get('status')} → {new.get('status')}")
        if old.get("risk_score") != new.get("risk_score"):
            changes.append(f"risk: {old.get('risk_score')} → {new.get('risk_score')}")
        if changes:
            changed.append({
                "ip": ip,
                "hostname": new.get("hostname") or new.get("label") or ip,
                "changes": changes,
            })

    return {
        "comparable": True,
        "reason": None,
        "source": cur.get("source"),
        "scope": cur.get("scope"),
        "previous_saved_at": prev.get("saved_at"),
        "current_saved_at": cur.get("saved_at"),
        "appeared": appeared,
        "disappeared": disappeared,
        "changed": changed,
        "summary": f"+{len(appeared)} new  -{len(disappeared)} gone  ~{len(changed)} changed",
    }


# Compatibility aliases for older callers. These represent observation snapshots
# only; MAC baselines remain authoritative in SQLite and never share this file.
load_state = load_snapshot_state
save_state = save_snapshot_state
'''
write("core/nexus_state.py", STATE_SOURCE)

# Preserve and merge explicit metadata rather than recursively nesting the raw DB
# meta column when a persisted row is written back after rescoring/enrichment.
regex_once(
    "core/nexus_db.py",
    r'''def upsert_host\(host: Dict\[str, Any\]\) -> None:\n    ip = host\.get\("ip"\)\n    if not ip:\n        return\n    now = _now\(\)\n    meta = \{k: v for k, v in host\.items\(\)\n            if k not in \("ip","mac","hostname","vendor","interface",\n                         "status","risk_score","group_cidr","first_seen","last_seen"\)\}\n''',
    '''def upsert_host(host: Dict[str, Any]) -> None:
    ip = host.get("ip")
    if not ip:
        return
    now = _now()
    raw_meta = host.get("meta") or {}
    if isinstance(raw_meta, str):
        try:
            parsed_meta = json.loads(raw_meta)
            meta = dict(parsed_meta) if isinstance(parsed_meta, dict) else {}
        except (TypeError, json.JSONDecodeError):
            meta = {}
    elif isinstance(raw_meta, dict):
        meta = dict(raw_meta)
    else:
        meta = {}
    host_columns = {
        "ip", "mac", "hostname", "vendor", "interface", "status", "notes",
        "risk_score", "group_cidr", "first_seen", "last_seen", "meta",
    }
    for key, value in host.items():
        if key not in host_columns:
            meta[key] = value
''',
)

# Keep detailed bounded CVE evidence and respect explicitly supplied honeypot hit
# counts while rescoring.
replace_once(
    "core/nexus_risk.py",
    '''    # ── Honeypot interaction — highest weight signal ─────────────────────────
    honeypot_hits: int = host.get("honeypot_hits", 0)
    if isinstance(_meta, dict):
        honeypot_hits = max(honeypot_hits, int(_meta.get("honeypot_hits", 0)))
    if honeypot_hits > 0:
''',
    '''    # ── Honeypot interaction — highest weight signal ─────────────────────────
    def _safe_int(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    honeypot_hits = max(
        _safe_int(honeypot_hits),
        _safe_int(host.get("honeypot_hits", 0)),
        _safe_int(_meta.get("honeypot_hits", 0)) if isinstance(_meta, dict) else 0,
    )
    if honeypot_hits > 0:
''',
)
replace_once(
    "core/nexus_risk.py",
    '''        meta["risk_reasons"] = reasons[:20]
        # Remove heavy fields before re-serializing
        meta.pop("cves", None)
        meta_str = _json.dumps(meta)
''',
    '''        meta["risk_reasons"] = reasons[:20]
        # Detailed CVE evidence is already bounded by nexus_db.upsert_host.
        # Do not delete it during a derived risk evaluation.
        meta_str = _json.dumps(meta)
''',
)

# Personality records now carry the exact rule version and bounded input summary
# that produced the displayed derived classification.
replace_once(
    "core/personality_engine.py",
    '''_lock = threading.Lock()

# ── Personality definitions ───────────────────────────────────────────────────
''',
    '''_lock = threading.Lock()
PERSONALITY_RULE_VERSION = "1"

# ── Personality definitions ───────────────────────────────────────────────────
''',
)
replace_once(
    "core/personality_engine.py",
    '''            assigned_at     TEXT,
            reason          TEXT
        );
''',
    '''            assigned_at     TEXT,
            reason          TEXT,
            rule_version    TEXT,
            input_summary   TEXT
        );
''',
)
replace_once(
    "core/personality_engine.py",
    '''        c.commit()
        c.close()


# ── Personality assignment ────────────────────────────────────────────────────
''',
    '''        columns = {row[1] for row in c.execute("PRAGMA table_info(host_personalities)").fetchall()}
        if "rule_version" not in columns:
            c.execute("ALTER TABLE host_personalities ADD COLUMN rule_version TEXT")
        if "input_summary" not in columns:
            c.execute("ALTER TABLE host_personalities ADD COLUMN input_summary TEXT")
        c.commit()
        c.close()


# ── Personality assignment ────────────────────────────────────────────────────
''',
)
replace_once(
    "core/personality_engine.py",
    '''    _save_personality(ip, personality, reason)
    return personality, reason


def _save_personality(ip: str, personality: str, reason: str) -> None:
    p = PERSONALITIES[personality]
''',
    '''    input_summary = {
        "risk_score": int(risk_score),
        "open_ports": sorted(open_ports, key=lambda value: int(value) if value.isdigit() else value),
        "honeypot_hits": honeypot_hits,
        "cve_count": int(meta.get("cve_count", 0) or 0),
    }
    _save_personality(ip, personality, reason, input_summary)
    return personality, reason


def _save_personality(
    ip: str,
    personality: str,
    reason: str,
    input_summary: Dict[str, Any],
) -> None:
    p = PERSONALITIES[personality]
''',
)
replace_once(
    "core/personality_engine.py",
    '''            INSERT INTO host_personalities
                (ip, personality, aggression, stealth, persistence, assigned_at, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                personality=excluded.personality,
                aggression=excluded.aggression,
                stealth=excluded.stealth,
                persistence=excluded.persistence,
                assigned_at=excluded.assigned_at,
                reason=excluded.reason
        """, (
            ip,
            personality,
            p["aggression"],
            p["stealth"],
            p["persistence"],
            datetime.utcnow().isoformat(),
            reason,
        ))
''',
    '''            INSERT INTO host_personalities
                (ip, personality, aggression, stealth, persistence, assigned_at, reason,
                 rule_version, input_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                personality=excluded.personality,
                aggression=excluded.aggression,
                stealth=excluded.stealth,
                persistence=excluded.persistence,
                assigned_at=excluded.assigned_at,
                reason=excluded.reason,
                rule_version=excluded.rule_version,
                input_summary=excluded.input_summary
        """, (
            ip,
            personality,
            p["aggression"],
            p["stealth"],
            p["persistence"],
            datetime.utcnow().isoformat(),
            reason,
            PERSONALITY_RULE_VERSION,
            json.dumps(input_summary, sort_keys=True),
        ))
''',
)

# Restore persisted trap history lazily but never re-open listeners after process
# restart. Previously-active traps become interrupted historical records.
replace_once(
    "core/nexus_traps.py",
    '''_ACTIVE_TRAPS: Dict[str, Dict[str, Any]] = {}
_TRAPS_LOCK = threading.Lock()
''',
    '''_ACTIVE_TRAPS: Dict[str, Dict[str, Any]] = {}
_TRAPS_LOCK = threading.Lock()
_TRAPS_LOADED = False
''',
)
replace_once(
    "core/nexus_traps.py",
    '''def _load_traps_state() -> Dict[str, Any]:
    try:
        if TRAPS_FILE.exists():
            return json.loads(TRAPS_FILE.read_text())
    except Exception:
        pass
    return {}


# ── Public API ────────────────────────────────────────────────────────────────
''',
    '''def _load_traps_state() -> Dict[str, Any]:
    try:
        if TRAPS_FILE.exists() and not TRAPS_FILE.is_symlink():
            data = json.loads(TRAPS_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _ensure_traps_loaded() -> None:
    global _TRAPS_LOADED
    with _TRAPS_LOCK:
        if _TRAPS_LOADED:
            return
        persisted = _load_traps_state()
        for trap_id, value in persisted.items():
            if not isinstance(value, dict):
                continue
            trap = dict(value)
            trap["id"] = str(trap.get("id") or trap_id)
            trap.pop("thread", None)
            trap.pop("stop_event", None)
            if trap.get("status") in {"active", "starting"}:
                trap["status"] = "interrupted"
            hits = trap.get("hits") if isinstance(trap.get("hits"), list) else []
            trap["hits"] = hits[-100:]
            try:
                trap["hit_count"] = max(int(trap.get("hit_count", 0)), len(trap["hits"]))
            except (TypeError, ValueError):
                trap["hit_count"] = len(trap["hits"])
            _ACTIVE_TRAPS[trap["id"]] = trap
        _TRAPS_LOADED = True


# ── Public API ────────────────────────────────────────────────────────────────
''',
)
for signature in (
    'def deploy_trap(trap_type: str, port: int, name: str,\n                banner_key: str = "generic") -> Dict[str, Any]:\n    """Deploy a single trap. Returns trap info dict."""\n',
    'def stop_trap(trap_id: str) -> bool:\n',
    'def get_all_traps() -> List[Dict[str, Any]]:\n',
    'def get_trap(trap_id: str) -> Optional[Dict[str, Any]]:\n',
    'def get_trap_hits(trap_id: str) -> List[Dict[str, Any]]:\n',
    'def get_all_hits() -> List[Dict[str, Any]]:\n    """All hits across all traps, sorted newest first."""\n',
):
    insertion = signature + '    _ensure_traps_loaded()\n'
    replace_once("core/nexus_traps.py", signature, insertion)

# Builder must be a pure projection of persisted observations and durable DB
# evidence. SQLite becomes the operator authority for host/service state.
replace_once(
    "core/nexus_builder.py",
    '''from core.nexus_service_state import load_service_state
from core.nexus_state import load_snapshot_state, save_snapshot_state
''',
    '''from core.nexus_state import advance_snapshot_state, diff_snapshots, load_snapshot_pair
''',
)
regex_once(
    "core/nexus_builder.py",
    r'''def _merge_cached_services\(\n    nodes: Dict\[str, GraphNode\], edges: Dict\[str, GraphEdge\], events: List\[GraphEvent\]\n\) -> None:\n.*?\n\ndef _generate_state_events\(nodes: Dict\[str, GraphNode\]\) -> List\[GraphEvent\]:\n.*?\n    return events\n''',
    '''def _overlay_persisted_host_state(nodes: Dict[str, GraphNode]) -> None:
    from core.nexus_db import get_all_hosts

    persisted = {row["ip"]: row for row in get_all_hosts()}
    for node in nodes.values():
        if node.node_type not in ("host", "router") or not node.ip:
            continue
        row = persisted.get(node.ip)
        if not row:
            continue
        observation_source = node.meta.get("source")
        raw_meta = row.get("meta") or {}
        if isinstance(raw_meta, str):
            try:
                parsed = json.loads(raw_meta)
                durable_meta = parsed if isinstance(parsed, dict) else {}
            except Exception:
                durable_meta = {}
        elif isinstance(raw_meta, dict):
            durable_meta = dict(raw_meta)
        else:
            durable_meta = {}
        node.status = row.get("status") or node.status
        try:
            node.risk_score = int(row.get("risk_score") or node.risk_score)
        except (TypeError, ValueError):
            pass
        if row.get("mac"):
            node.mac = row["mac"]
        if row.get("hostname"):
            node.hostname = row["hostname"]
            node.label = row["hostname"]
        if row.get("group_cidr"):
            node.group = row["group_cidr"]
        if row.get("vendor"):
            node.meta["vendor"] = row["vendor"]
        node.meta.update(durable_meta)
        if observation_source:
            node.meta["observation_source"] = observation_source
        if durable_meta.get("source"):
            node.meta["evidence_source"] = durable_meta["source"]
        if row.get("last_seen"):
            node.meta["last_seen"] = row["last_seen"]
        if row.get("notes"):
            node.meta["notes"] = row["notes"]


def _merge_cached_services(
    nodes: Dict[str, GraphNode], edges: Dict[str, GraphEdge], events: List[GraphEvent]
) -> None:
    """Compatibility name; SQLite is the operator authority for services."""
    from core.nexus_db import get_all_services

    by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for service in get_all_services():
        ip = service.get("ip")
        if ip:
            by_ip.setdefault(ip, []).append(service)
    for ip, svc_rows in by_ip.items():
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
                      "source": svc.get("source", "sqlite")},
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


def _durable_graph_events(limit: int = 60) -> List[GraphEvent]:
    from core.nexus_db import get_recent_events

    rendered: List[GraphEvent] = []
    for event in get_recent_events(limit=limit):
        node_id = event.get("node_id")
        if not node_id and event.get("ip"):
            node_id = f"host:{event['ip']}"
        rendered.append(GraphEvent(
            id=str(event.get("id") or f"evt:{event.get('ts')}"),
            ts=str(event.get("ts") or _now()),
            severity=str(event.get("severity") or "info"),
            title=str(event.get("title") or "Event"),
            summary=str(event.get("summary") or ""),
            node_id=node_id,
        ))
    return rendered


def _generate_state_events(nodes: Dict[str, GraphNode]) -> List[GraphEvent]:
    """Compatibility helper: graph reads expose durable events and never mutate state."""
    return _durable_graph_events()


def advance_observation_snapshot(
    data: Dict[str, Any], *, source: str = "discovery", scope: str | None = None
) -> Dict[str, Any]:
    """Advance diff state after an explicit, successful observation acquisition."""
    nodes_list, _, _ = _normalize_collector_data(data)
    nodes = {node.id: node for node in nodes_list}
    _overlay_persisted_host_state(nodes)
    observed_at = _now()
    hosts: Dict[str, Dict[str, Any]] = {}
    for node in nodes.values():
        if node.node_type not in ("host", "router") or not node.ip:
            continue
        hosts[node.ip] = {
            "ip": node.ip,
            "hostname": node.hostname or node.label or node.ip,
            "label": node.label or node.hostname or node.ip,
            "mac": node.mac,
            "status": node.status,
            "risk_score": node.risk_score,
            "group": node.group,
            "last_seen": node.meta.get("last_seen") or observed_at,
            "observed_at": observed_at,
            "source": node.meta.get("observation_source") or source,
        }
    current = {
        "hosts": hosts,
        "saved_at": observed_at,
        "source": source,
        "scope": scope or data.get("cidr"),
    }
    before = load_snapshot_pair().get("current")
    advance_snapshot_state(current)
    diff = diff_snapshots(before, current)
    if diff.get("comparable"):
        from core.nexus_db import insert_events
        events = []
        for item in diff["appeared"]:
            events.append({
                "id": f"evt:observed:new:{item['ip']}:{observed_at}",
                "ts": observed_at, "severity": "info", "title": "New Host Observed",
                "summary": f"{item.get('hostname') or item['ip']} appeared in the discovery snapshot.",
                "ip": item["ip"],
            })
        for item in diff["disappeared"]:
            events.append({
                "id": f"evt:observed:gone:{item['ip']}:{observed_at}",
                "ts": observed_at, "severity": "warning", "title": "Host Missing",
                "summary": f"{item.get('hostname') or item['ip']} is absent from the latest discovery snapshot.",
                "ip": item["ip"],
            })
        for item in diff["changed"]:
            events.append({
                "id": f"evt:observed:changed:{item['ip']}:{observed_at}",
                "ts": observed_at, "severity": "warning", "title": "Host Observation Changed",
                "summary": "; ".join(item.get("changes") or []), "ip": item["ip"],
            })
        if events:
            insert_events(events)
    return diff
''',
)
# Read-only graph construction must never fall back to live collection.
regex_once(
    "core/nexus_builder.py",
    r'''    # 3\. Cheap live ARP only \(no nmap, fast\)\n    if not cache:\n        try:\n            from core\.nexus_collectors import collect_arp_neighbors, collect_local_interfaces\n            quick = \{.*?\n        except Exception:\n            pass\n\n    # 4\. Merge cached services\n    _merge_cached_services\(all_nodes, all_edges, all_events\)\n''',
    '''    # 3. Hydrate durable host evidence without performing network I/O.
    _overlay_persisted_host_state(all_nodes)

    # 4. Merge persisted SQLite services (single operator authority).
    _merge_cached_services(all_nodes, all_edges, all_events)
''',
)
replace_once(
    "core/nexus_builder.py",
    '''        subtitle="Live Network Map",
''',
    '''        subtitle="Observed Network Map",
''',
)
# Expose reproducible personality provenance in the graph metadata.
replace_once(
    "core/nexus_builder.py",
    '''        node.meta["personality_reason"] = p.get("reason", "")
        node.meta["personality_color"] = PERSONALITY_COLORS.get(p["personality"], "#ffffff")
''',
    '''        node.meta["personality_reason"] = p.get("reason", "")
        node.meta["personality_rule_version"] = p.get("rule_version")
        try:
            node.meta["personality_inputs"] = json.loads(p.get("input_summary") or "{}")
        except Exception:
            node.meta["personality_inputs"] = {}
        node.meta["personality_color"] = PERSONALITY_COLORS.get(p["personality"], "#ffffff")
''',
)

# API: canonical identity, explicit discovery advances observation snapshots,
# durable log/service authorities, and compatible snapshot-to-snapshot diffing.
replace_once(
    "core/nexus_api.py",
    '''from core.nexus_builder import build_snapshot, save_discovery_cache
''',
    '''from core.nexus_builder import build_snapshot, save_discovery_cache, advance_observation_snapshot
''',
)
replace_once(
    "core/nexus_api.py",
    '''app = FastAPI(title="LANimals Nexus", version=VERSION, lifespan=lifespan)
''',
    '''app = FastAPI(title="LANimals", version=VERSION, lifespan=lifespan)
''',
)
replace_once(
    "core/nexus_api.py",
    '''        except Exception as _re:
            _job_log(jid, f"  Risk engine error: {_re}")
        _job_done(jid, {"host_count": len(seen), "hosts": list(seen.values())})
''',
    '''        except Exception as _re:
            _job_log(jid, f"  Risk engine error: {_re}")
        diff = advance_observation_snapshot(cache_data, source="discovery", scope=cidr)
        if diff.get("comparable"):
            _job_log(jid, f"  Observation diff: {diff['summary']}")
        else:
            _job_log(jid, "  Observation baseline recorded; run Discovery again for a diff")
        _job_done(jid, {"host_count": len(seen), "hosts": list(seen.values()), "diff": diff})
''',
)
replace_once(
    "core/nexus_api.py",
    '''@app.get("/api/logs")
def get_logs():
    snap = build_snapshot()
    return {"events": [e.model_dump() for e in snap.events[:30]]}
''',
    '''@app.get("/api/logs")
def get_logs():
    return {"events": get_recent_events(limit=30)}
''',
)
replace_once(
    "core/nexus_api.py",
    '''@app.get("/api/services/{ip}")
def get_services(ip: str):
    state = load_service_state()
    services = state.get("services_by_ip", {}).get(ip, [])
    return {"ip": ip, "services": services, "count": len(services)}
''',
    '''@app.get("/api/services/{ip}")
def get_services(ip: str):
    services = get_services_for_ip(ip)
    return {"ip": ip, "services": services, "count": len(services)}
''',
)
replace_once(
    "core/nexus_api.py",
    '''        services = collect_services_for_ip(ip)
        state = load_service_state()
        svc_map = state.get("services_by_ip", {})
        svc_map[ip] = services
        state["services_by_ip"] = svc_map
        save_service_state(state)
        for svc in services:
''',
    '''        services = collect_services_for_ip(ip)
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
''',
)
replace_once(
    "core/nexus_api.py",
    '''        upsert_services(services)
        insert_events([{
''',
    '''        insert_events([{
''',
)
regex_once(
    "core/nexus_api.py",
    r'''@app\.get\("/api/diff"\)\ndef network_diff\(\):\n    """Compare current DB state to previous snapshot\. Shows what changed\."""\n.*?\n    return \{\n        "appeared": appeared,\n        "disappeared": disappeared,\n        "changed": changed,\n        "summary": f"\+\{len\(appeared\)\} new  -\{len\(disappeared\)\} gone  ~\{len\(changed\)\} changed",\n        "generated_at": _now_iso\(\),\n    \}\n''',
    '''@app.get("/api/diff")
def network_diff():
    """Compare the last two explicit full Discovery observations."""
    from core.nexus_state import diff_snapshots, load_snapshot_pair

    pair = load_snapshot_pair()
    result = diff_snapshots(pair.get("previous"), pair.get("current"))
    result["generated_at"] = _now_iso()
    return result
''',
)

# UI should label personality as derived and describe diff's explicit boundary.
replace_once(
    "ui/lanimals_live_map.html",
    '''<div class="kv"><div class="k">personality</div><div class="v" style="color:${node.meta.personality_color||'#fff'};font-weight:700;text-transform:uppercase;letter-spacing:.08em">${esc(node.meta.personality)}</div></div>''',
    '''<div class="kv"><div class="k">derived personality</div><div class="v" style="color:${node.meta.personality_color||'#fff'};font-weight:700;text-transform:uppercase;letter-spacing:.08em">${esc(node.meta.personality)}</div></div>''',
)
replace_once(
    "ui/lanimals_live_map.html",
    '''  addScanLine('→ GET /api/diff','muted'); activateTab('scanout');
''',
    '''  addScanLine('→ GET /api/diff · last two explicit Discovery scans','muted'); activateTab('scanout');
''',
)

print("state/evidence integrity patch applied successfully")
