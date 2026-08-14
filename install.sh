#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
SCOPE=""
if [[ "${1:-}" == "--scope" ]]; then
    SCOPE="${2:-}"
    if [[ -z "$SCOPE" || $# -ne 2 ]]; then
        echo "usage: ./install.sh [--scope PRIVATE-CIDR]" >&2
        exit 2
    fi
elif [[ $# -ne 0 ]]; then
    echo "usage: ./install.sh [--scope PRIVATE-CIDR]" >&2
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "[FAIL] Python 3.10 or newer is required." >&2
    exit 2
fi
python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("[FAIL] Python 3.10 or newer is required.")
PY

echo "[....] Creating isolated LANimals runtime"
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt"

USER_BIN="${HOME}/.local/bin"
mkdir -p "$USER_BIN"
for source in "$ROOT"/bin/lanimals*; do
    target="$USER_BIN/$(basename "$source")"
    if [[ -e "$target" && ! -L "$target" ]]; then
        echo "[FAIL] Refusing to replace existing file: $target" >&2
        exit 2
    fi
    ln -sfn "$source" "$target"
done

if [[ -n "$SCOPE" ]]; then
    "$ROOT/.venv/bin/python" -m core.appliance setup "$SCOPE"
    "$ROOT/.venv/bin/python" -m core.appliance doctor
elif [[ -t 0 ]]; then
    "$ROOT/.venv/bin/python" -m core.appliance setup
fi

echo "[ OK ] LANimals runtime installed"
echo "[ OK ] Command directory: $USER_BIN"
if ! command -v nmap >/dev/null 2>&1; then
    echo "[WARN] nmap is not installed; discovery will be limited until you run:"
    echo "       sudo apt install nmap"
fi
if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
    echo "[INFO] Add this line to your shell profile:"
    echo "       export PATH=\"$USER_BIN:\$PATH\""
fi
if [[ -z "$SCOPE" ]]; then
    echo "[NEXT] If setup was skipped, approve a scope: $ROOT/bin/lanimals setup"
else
    echo "[NEXT] Start the local browser appliance: $ROOT/bin/lanimals start"
fi
