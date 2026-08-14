#!/usr/bin/env bash
set -eu

ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
    echo "[FAIL] LANimals is not installed. Run: ./install.sh" >&2
    exit 2
fi
exec "$ROOT/bin/lanimals" start "$@"
