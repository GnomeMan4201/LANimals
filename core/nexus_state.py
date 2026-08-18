from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from core.nexus_paths import DATA_DIR

SNAPSHOT_STATE_FILE = DATA_DIR / "network_snapshot.json"
LEGACY_STATE_FILE = DATA_DIR / "nexus_state.json"
SNAPSHOT_SCHEMA_VERSION = 2


class SnapshotStateError(RuntimeError):
    """Raised when persisted observation history exists but is not trustworthy."""


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


def _empty_pair() -> Dict[str, Any]:
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "previous": None,
        "current": None,
    }


def _normalize_persisted_snapshot(value: Any, *, label: str, path: Path) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    normalized = _normalize_snapshot(value)
    if normalized is None:
        raise SnapshotStateError(f"invalid {label} snapshot structure: {path}")
    return normalized


def load_snapshot_pair() -> Dict[str, Any]:
    path = _state_path()
    if not path.exists():
        return _empty_pair()
    if path.is_symlink():
        raise SnapshotStateError(f"refusing symlinked snapshot state: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotStateError(f"cannot read snapshot state: {path}") from exc

    if isinstance(data, dict) and "schema_version" in data:
        if data.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
            raise SnapshotStateError(
                f"unsupported snapshot schema version in {path}: "
                f"{data.get('schema_version')!r}"
            )
        return {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "previous": _normalize_persisted_snapshot(
                data.get("previous"), label="previous", path=path
            ),
            "current": _normalize_persisted_snapshot(
                data.get("current"), label="current", path=path
            ),
        }

    # Compatibility with the pre-v2 single-snapshot file. Treat it as current;
    # the next explicit acquisition will shift it to previous.
    legacy = _normalize_snapshot(data)
    if legacy is None:
        raise SnapshotStateError(f"invalid legacy snapshot structure: {path}")
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "previous": None,
        "current": legacy,
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
            stream.write("\n")
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
