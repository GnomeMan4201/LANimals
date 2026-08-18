from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.nexus_paths import DATA_DIR

DB_PATH = DATA_DIR / "lanimals.db"

_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def init_db() -> None:
    with _lock:
        c = _conn()
        try:
            c.executescript("""
        CREATE TABLE IF NOT EXISTS hosts (
            ip          TEXT PRIMARY KEY,
            mac         TEXT,
            hostname    TEXT,
            vendor      TEXT,
            interface   TEXT,
            status      TEXT DEFAULT 'normal',
            notes       TEXT DEFAULT '',
            risk_score  INTEGER DEFAULT 15,
            group_cidr  TEXT,
            first_seen  TEXT,
            last_seen   TEXT,
            meta        TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS services (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip           TEXT NOT NULL,
            port         TEXT,
            protocol     TEXT DEFAULT 'tcp',
            service_name TEXT,
            product      TEXT,
            version      TEXT,
            extra_info   TEXT,
            source       TEXT,
            last_seen    TEXT,
            UNIQUE(ip, port, protocol)
        );
        CREATE TABLE IF NOT EXISTS events (
            id          TEXT PRIMARY KEY,
            ts          TEXT NOT NULL,
            severity    TEXT NOT NULL,
            title       TEXT NOT NULL,
            summary     TEXT,
            node_id     TEXT,
            ip          TEXT
        );
        CREATE TABLE IF NOT EXISTS mac_baseline (
            ip          TEXT PRIMARY KEY,
            mac         TEXT,
            hostname    TEXT,
            first_seen  TEXT,
            last_seen   TEXT
        );
        CREATE TABLE IF NOT EXISTS baseline_decisions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts            TEXT NOT NULL,
            ip            TEXT NOT NULL,
            action        TEXT NOT NULL CHECK(action IN ('accept','defer')),
            observed_mac  TEXT,
            previous_mac  TEXT,
            hostname      TEXT,
            note          TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
        CREATE INDEX IF NOT EXISTS idx_services_ip ON services(ip);
        CREATE INDEX IF NOT EXISTS idx_baseline_decisions_ip
            ON baseline_decisions(ip, id DESC);
            """)
            # Migrate legacy hosts schemas based on actual column metadata.
            columns = {row[1] for row in c.execute("PRAGMA table_info(hosts)").fetchall()}
            if "notes" not in columns:
                c.execute("ALTER TABLE hosts ADD COLUMN notes TEXT DEFAULT ''")
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def upsert_host(host: Dict[str, Any]) -> None:
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
    # Trim CVEs list to avoid blob-too-big — keep max 10 CVEs
    if "cves" in meta and isinstance(meta.get("cves"), list):
        meta["cves"] = meta["cves"][:10]
    # Trim risk_reasons to max 20
    if "risk_reasons" in meta and isinstance(meta.get("risk_reasons"), list):
        meta["risk_reasons"] = meta["risk_reasons"][:20]
    with _lock:
        c = _conn()
        c.execute("""
            INSERT INTO hosts (ip,mac,hostname,vendor,interface,status,risk_score,
                               group_cidr,first_seen,last_seen,meta)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                mac        = COALESCE(excluded.mac, mac),
                hostname   = COALESCE(NULLIF(excluded.hostname,excluded.ip), hostname),
                vendor     = COALESCE(NULLIF(excluded.vendor,''), vendor),
                interface  = COALESCE(excluded.interface, interface),
                status     = CASE WHEN excluded.status != 'normal' THEN excluded.status
                                  WHEN excluded.risk_score > 0 THEN excluded.status
                                  ELSE status END,
                risk_score = CASE WHEN excluded.risk_score > 0 THEN excluded.risk_score
                                  ELSE risk_score END,
                group_cidr = COALESCE(excluded.group_cidr, group_cidr),
                last_seen  = excluded.last_seen,
                meta       = excluded.meta
        """, (
            ip, host.get("mac"), host.get("hostname", ip),
            host.get("vendor",""), host.get("interface"),
            host.get("status","normal"), host.get("risk_score",15),
            host.get("group_cidr"), now, now, json.dumps(meta),
        ))
        c.commit()
        c.close()


def upsert_hosts(hosts: List[Dict[str, Any]]) -> None:
    for h in hosts:
        upsert_host(h)


def get_all_hosts() -> List[Dict[str, Any]]:
    with _lock:
        c = _conn()
        rows = c.execute("SELECT * FROM hosts ORDER BY ip").fetchall()
        c.close()
    return [dict(r) for r in rows]


def get_host(ip: str) -> Optional[Dict[str, Any]]:
    with _lock:
        c = _conn()
        row = c.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
        c.close()
    return dict(row) if row else None


def upsert_services(services: List[Dict[str, Any]]) -> None:
    now = _now()
    with _lock:
        c = _conn()
        for svc in services:
            c.execute("""
                INSERT INTO services
                    (ip,port,protocol,service_name,product,version,extra_info,source,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ip,port,protocol) DO UPDATE SET
                    service_name = excluded.service_name,
                    product      = excluded.product,
                    version      = excluded.version,
                    extra_info   = excluded.extra_info,
                    source       = excluded.source,
                    last_seen    = excluded.last_seen
            """, (
                svc.get("ip"), svc.get("port",""), svc.get("protocol","tcp"),
                svc.get("service_name",""), svc.get("product",""),
                svc.get("version",""), svc.get("extra_info",""),
                svc.get("source",""), now,
            ))
        c.commit()
        c.close()


def get_services_for_ip(ip: str) -> List[Dict[str, Any]]:
    with _lock:
        c = _conn()
        rows = c.execute(
            "SELECT * FROM services WHERE ip=? ORDER BY CAST(port AS INTEGER)", (ip,)
        ).fetchall()
        c.close()
    return [dict(r) for r in rows]


def get_all_services() -> List[Dict[str, Any]]:
    with _lock:
        c = _conn()
        rows = c.execute(
            "SELECT * FROM services ORDER BY ip, CAST(port AS INTEGER)"
        ).fetchall()
        c.close()
    return [dict(r) for r in rows]


def insert_event(event: Dict[str, Any]) -> None:
    with _lock:
        c = _conn()
        c.execute("""
            INSERT OR IGNORE INTO events (id,ts,severity,title,summary,node_id,ip)
            VALUES (?,?,?,?,?,?,?)
        """, (
            event.get("id", _now()),
            event.get("ts", _now()),
            event.get("severity","info"),
            event.get("title",""),
            event.get("summary",""),
            event.get("node_id"),
            event.get("ip"),
        ))
        c.commit()
        c.close()


def insert_events(events: List[Dict[str, Any]]) -> None:
    for e in events:
        insert_event(e)


def get_recent_events(limit: int = 60, ip: Optional[str] = None) -> List[Dict[str, Any]]:
    with _lock:
        c = _conn()
        if ip:
            rows = c.execute(
                "SELECT * FROM events WHERE ip=? ORDER BY ts DESC LIMIT ?", (ip, limit)
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        c.close()
    return [dict(r) for r in rows]


def get_mac_baseline() -> Dict[str, Dict[str, Any]]:
    with _lock:
        c = _conn()
        rows = c.execute("SELECT * FROM mac_baseline").fetchall()
        c.close()
    return {r["ip"]: dict(r) for r in rows}


def update_mac_baseline(ip: str, mac: str, hostname: str) -> None:
    now = _now()
    with _lock:
        c = _conn()
        c.execute("""
            INSERT INTO mac_baseline (ip,mac,hostname,first_seen,last_seen)
            VALUES (?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                mac=excluded.mac, hostname=excluded.hostname, last_seen=excluded.last_seen
        """, (ip, mac, hostname, now, now))
        c.commit()
        c.close()


def get_pending_baseline_changes() -> List[Dict[str, Any]]:
    """Return observations that require an explicit operator decision."""
    with _lock:
        c = _conn()
        rows = c.execute("""
            SELECT h.ip, h.mac AS observed_mac, h.hostname, h.vendor,
                   h.first_seen, h.last_seen,
                   b.mac AS baseline_mac, b.hostname AS baseline_hostname
            FROM hosts h
            LEFT JOIN mac_baseline b ON b.ip = h.ip
            WHERE h.mac IS NOT NULL
              AND (b.ip IS NULL
                   OR (b.mac IS NOT NULL AND lower(h.mac) != lower(b.mac)))
            ORDER BY h.ip
        """).fetchall()
        c.close()
    pending = []
    for row in rows:
        item = dict(row)
        item["status"] = "new" if not item.get("baseline_mac") else "changed"
        item["reason"] = (
            "Host is not in the accepted baseline"
            if item["status"] == "new"
            else "Observed MAC differs from the accepted baseline"
        )
        pending.append(item)
    return pending


def accept_baseline_observation(ip: str, note: str = "") -> Dict[str, Any]:
    """Atomically accept the current host identity and record the decision."""
    now = _now()
    with _lock:
        c = _conn()
        try:
            c.execute("BEGIN IMMEDIATE")
            host = c.execute(
                "SELECT ip,mac,hostname FROM hosts WHERE ip=?", (ip,)
            ).fetchone()
            if not host:
                raise ValueError("host has not been observed")
            if not host["mac"]:
                raise ValueError("host has no observed MAC address")
            previous = c.execute(
                "SELECT mac FROM mac_baseline WHERE ip=?", (ip,)
            ).fetchone()
            previous_mac = previous["mac"] if previous else None
            c.execute("""
                INSERT INTO mac_baseline (ip,mac,hostname,first_seen,last_seen)
                VALUES (?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac=excluded.mac,
                    hostname=excluded.hostname,
                    last_seen=excluded.last_seen
            """, (ip, host["mac"], host["hostname"] or ip, now, now))
            cursor = c.execute("""
                INSERT INTO baseline_decisions
                    (ts,ip,action,observed_mac,previous_mac,hostname,note)
                VALUES (?,?,?,?,?,?,?)
            """, (
                now, ip, "accept", host["mac"], previous_mac,
                host["hostname"] or ip, note.strip(),
            ))
            c.commit()
            return {
                "id": cursor.lastrowid,
                "ts": now,
                "ip": ip,
                "action": "accept",
                "observed_mac": host["mac"],
                "previous_mac": previous_mac,
                "hostname": host["hostname"] or ip,
                "note": note.strip(),
            }
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()


def defer_baseline_observation(ip: str, note: str = "") -> Dict[str, Any]:
    """Record a fail-closed decision without mutating the accepted baseline."""
    now = _now()
    with _lock:
        c = _conn()
        try:
            c.execute("BEGIN IMMEDIATE")
            host = c.execute(
                "SELECT ip,mac,hostname FROM hosts WHERE ip=?", (ip,)
            ).fetchone()
            if not host:
                raise ValueError("host has not been observed")
            previous = c.execute(
                "SELECT mac FROM mac_baseline WHERE ip=?", (ip,)
            ).fetchone()
            previous_mac = previous["mac"] if previous else None
            cursor = c.execute("""
                INSERT INTO baseline_decisions
                    (ts,ip,action,observed_mac,previous_mac,hostname,note)
                VALUES (?,?,?,?,?,?,?)
            """, (
                now, ip, "defer", host["mac"], previous_mac,
                host["hostname"] or ip, note.strip(),
            ))
            c.commit()
            return {
                "id": cursor.lastrowid,
                "ts": now,
                "ip": ip,
                "action": "defer",
                "observed_mac": host["mac"],
                "previous_mac": previous_mac,
                "hostname": host["hostname"] or ip,
                "note": note.strip(),
            }
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()


def get_baseline_decisions(limit: int = 100) -> List[Dict[str, Any]]:
    with _lock:
        c = _conn()
        rows = c.execute(
            "SELECT * FROM baseline_decisions ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 500)),),
        ).fetchall()
        c.close()
    return [dict(row) for row in rows]


def get_db_stats() -> Dict[str, Any]:
    with _lock:
        c = _conn()
        stats = {
            "hosts":            c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0],
            "services":         c.execute("SELECT COUNT(*) FROM services").fetchone()[0],
            "events":           c.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "warnings":         c.execute("SELECT COUNT(*) FROM hosts WHERE status='warning'").fetchone()[0],
            "critical":         c.execute("SELECT COUNT(*) FROM hosts WHERE status='critical'").fetchone()[0],
            "baseline_entries": c.execute("SELECT COUNT(*) FROM mac_baseline").fetchone()[0],
        }
        c.close()
    return stats




def get_host_notes(ip: str) -> str:
    with _lock:
        c = _conn()
        row = c.execute("SELECT notes FROM hosts WHERE ip=?", (ip,)).fetchone()
        c.close()
    return (row["notes"] or "") if row else ""


def set_host_notes(ip: str, notes: str) -> None:
    now = _now()
    with _lock:
        c = _conn()
        c.execute(
            "INSERT INTO hosts (ip, notes, first_seen, last_seen) "
            "VALUES (?,?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET notes=excluded.notes",
            (ip, notes, now, now)
        )
        c.commit()
        c.close()
