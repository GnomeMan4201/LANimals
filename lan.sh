#!/usr/bin/env bash
set -eu

ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
    PYTHON="$(command -v python3 || true)"
fi
if [[ -z "$PYTHON" ]]; then
    echo "[FAIL] Python 3 is required" >&2
    exit 2
fi

cd "$ROOT"
exec "$PYTHON" -m core.appliance start "$@"
