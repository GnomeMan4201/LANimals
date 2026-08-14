from __future__ import annotations

import os
from pathlib import Path


def _home() -> Path:
    return Path.home()


def _xdg_path(environment_name: str, fallback: Path) -> Path:
    value = os.environ.get(environment_name, "").strip()
    return Path(value).expanduser() if value else fallback


DATA_DIR = Path(
    os.environ.get(
        "LANIMALS_DATA_DIR",
        _xdg_path("XDG_DATA_HOME", _home() / ".local" / "share") / "lanimals",
    )
).expanduser()
CACHE_DIR = Path(
    os.environ.get(
        "LANIMALS_CACHE_DIR",
        _xdg_path("XDG_CACHE_HOME", _home() / ".cache") / "lanimals",
    )
).expanduser()
STATE_DIR = Path(
    os.environ.get(
        "LANIMALS_STATE_DIR",
        _xdg_path("XDG_STATE_HOME", _home() / ".local" / "state") / "lanimals",
    )
).expanduser()
CONFIG_DIR = Path(
    os.environ.get(
        "LANIMALS_CONFIG_DIR",
        _xdg_path("XDG_CONFIG_HOME", _home() / ".config") / "lanimals",
    )
).expanduser()
REPORTS_DIR = Path(
    os.environ.get("LANIMALS_REPORTS_DIR", DATA_DIR / "reports")
).expanduser()


def ensure_runtime_dirs() -> None:
    for path in (DATA_DIR, CACHE_DIR, STATE_DIR, CONFIG_DIR, REPORTS_DIR):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
