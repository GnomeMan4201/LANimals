from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parent.parent
TMP_DIR = ROOT / "tmp"
TMP_DIR.mkdir(exist_ok=True)

SERVICE_STATE_FILE = TMP_DIR / "nexus_services.json"


def load_service_state() -> Dict[str, Any]:
    if not SERVICE_STATE_FILE.exists():
        return {}
    try:
        return json.loads(SERVICE_STATE_FILE.read_text())
    except Exception:
        return {}


def save_service_state(data: Dict[str, Any]) -> None:
    SERVICE_STATE_FILE.write_text(json.dumps(data, indent=2, sort_keys=True))
