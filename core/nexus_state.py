from __future__ import annotations

import json
from typing import Any, Dict

from core.nexus_paths import DATA_DIR

SNAPSHOT_STATE_FILE = DATA_DIR / "network_snapshot.json"
LEGACY_STATE_FILE = DATA_DIR / "nexus_state.json"


def load_snapshot_state() -> Dict[str, Any]:
    path = SNAPSHOT_STATE_FILE
    if not path.exists() and LEGACY_STATE_FILE.exists():
        path = LEGACY_STATE_FILE
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    hosts = data.get("hosts")
    return {"hosts": hosts, "saved_at": data.get("saved_at")} if isinstance(hosts, dict) else {}


def save_snapshot_state(data: Dict[str, Any]) -> None:
    hosts = data.get("hosts")
    if not isinstance(hosts, dict):
        raise ValueError("snapshot state requires a hosts mapping")
    payload = {"hosts": hosts, "saved_at": data.get("saved_at")}
    SNAPSHOT_STATE_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp_path = SNAPSHOT_STATE_FILE.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    tmp_path.replace(SNAPSHOT_STATE_FILE)


# Compatibility aliases for older callers. These now represent snapshots only;
# MAC baselines are authoritative in SQLite and must never share this file.
load_state = load_snapshot_state
save_state = save_snapshot_state
