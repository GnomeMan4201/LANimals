from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

if not VERSION:
    raise RuntimeError("VERSION is empty")
