#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
SMOKE_ROOT="$(mktemp -d /tmp/lanimals-smoke.XXXXXX)"
export XDG_CONFIG_HOME="$SMOKE_ROOT/config"
export XDG_DATA_HOME="$SMOKE_ROOT/data"
export XDG_CACHE_HOME="$SMOKE_ROOT/cache"
export XDG_STATE_HOME="$SMOKE_ROOT/state"
export LANIMALS_PORT=18080

cleanup() {
    python3 -m core.appliance stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$ROOT"
python3 -m core.appliance setup 192.168.50.0/24
python3 -m core.appliance start --no-browser
python3 -m core.appliance status --json | python3 -c '
import json, sys
status = json.load(sys.stdin)
assert status["running"] is True
assert status["healthy"] is True
assert status["url"] == "http://127.0.0.1:18080"
'
python3 - <<'PY'
import json
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:18080/api/health", timeout=2) as response:
    health = json.loads(response.read())
assert health["ok"] is True
assert health["version"] == "2.1.0"
PY
python3 -m core.appliance stop
if python3 -m core.appliance status --json >/dev/null; then
    echo "LANimals unexpectedly remained healthy after stop" >&2
    exit 1
fi
