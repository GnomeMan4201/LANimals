from __future__ import annotations

import json
from typing import Any, Dict

from core.nexus_paths import DATA_DIR

SERVICE_STATE_FILE = DATA_DIR / "nexus_services.json"


def load_service_state() -> Dict[str, Any]:
    if not SERVICE_STATE_FILE.exists():
        return {}
    try:
        return json.loads(SERVICE_STATE_FILE.read_text())
    except Exception:
        return {}


def save_service_state(data: Dict[str, Any]) -> None:
    SERVICE_STATE_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    SERVICE_STATE_FILE.write_text(json.dumps(data, indent=2, sort_keys=True))
