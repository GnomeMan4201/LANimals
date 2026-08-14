#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
JOURNEY_ROOT="$(mktemp -d /tmp/lanimals-journey.XXXXXX)"
ORIGINAL_HOME="${HOME}"
export HOME="$JOURNEY_ROOT/home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_DATA_HOME="$HOME/.local/share"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_STATE_HOME="$HOME/.local/state"
export PATH="$HOME/.local/bin:$PATH"
export LANIMALS_PORT=18081
SCOPE="192.168.250.0/30"
TARGET="192.168.250.2"
API="http://127.0.0.1:${LANIMALS_PORT}"
NAMESPACE="lanimals-fixture"
HOST_IFACE="lanimals0"
NODE_IFACE="node0"
SERVER_PID=""

cleanup() {
    set +e
    if command -v lanimals >/dev/null 2>&1; then
        lanimals stop >/dev/null 2>&1 || true
    else
        "$ROOT/bin/lanimals" stop >/dev/null 2>&1 || true
    fi
    if [[ -n "$SERVER_PID" ]]; then
        sudo kill "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    sudo ip netns del "$NAMESPACE" >/dev/null 2>&1 || true
    sudo ip link del "$HOST_IFACE" >/dev/null 2>&1 || true
    rm -rf "$JOURNEY_ROOT"
    export HOME="$ORIGINAL_HOME"
}
trap cleanup EXIT

mkdir -p "$HOME"
cd "$ROOT"
rm -rf .venv

# Build a deterministic private LAN entirely inside the CI runner. The host-side
# veth name intentionally avoids LANimals' virtual-interface name filters so the
# collectors exercise a normal interface/ARP path. Nothing leaves this runner.
sudo ip netns add "$NAMESPACE"
sudo ip link add "$HOST_IFACE" type veth peer name "$NODE_IFACE"
sudo ip link set "$NODE_IFACE" netns "$NAMESPACE"
sudo ip addr add 192.168.250.1/30 dev "$HOST_IFACE"
sudo ip link set "$HOST_IFACE" up
sudo ip netns exec "$NAMESPACE" ip addr add "$TARGET/30" dev "$NODE_IFACE"
sudo ip netns exec "$NAMESPACE" ip link set lo up
sudo ip netns exec "$NAMESPACE" ip link set "$NODE_IFACE" up

PYTHON_BIN="$(command -v python3)"
sudo ip netns exec "$NAMESPACE" "$PYTHON_BIN" -m http.server 8080 --bind "$TARGET" \
    >"$JOURNEY_ROOT/fixture-http.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
    if curl -fsS --connect-timeout 1 "http://$TARGET:8080/" >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
curl -fsS --connect-timeout 2 "http://$TARGET:8080/" >/dev/null

# Fresh checkout-first install under an isolated HOME/XDG tree.
./install.sh --scope "$SCOPE"
command -v lanimals >/dev/null
[[ "$(readlink -f "$(command -v lanimals)")" == "$ROOT/bin/lanimals" ]]
lanimals version | grep -F "2.1.0" >/dev/null
lanimals doctor --json | "$ROOT/.venv/bin/python" -c '
import json, sys
checks = json.load(sys.stdin)["checks"]
failed = [c for c in checks if c["level"] == "fail"]
assert not failed, failed
assert any(c["name"] == "scope" and "192.168.250.0/30" in c["detail"] for c in checks)
'

lanimals start --no-browser
lanimals status --json | "$ROOT/.venv/bin/python" -c '
import json, sys
status = json.load(sys.stdin)
assert status["running"] is True
assert status["healthy"] is True
assert status["configured"] is True
assert status["url"] == "http://127.0.0.1:18081"
'

"$ROOT/.venv/bin/python" - <<'PY'
import json
import time
import urllib.request

API = "http://127.0.0.1:18081"
TARGET = "192.168.250.2"
HEADER = {"X-LANimals-Operator": "1", "Content-Type": "application/json"}


def request(method, path, payload=None, headers=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(API + path, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=15) as response:
        raw = response.read()
        ctype = response.headers.get("content-type", "")
        if "application/json" in ctype:
            return json.loads(raw), response.headers
        return raw.decode(errors="replace"), response.headers


def run_job(path):
    body, _ = request("POST", path, payload={}, headers=HEADER)
    jid = body["job_id"]
    for _ in range(120):
        job, _ = request("GET", f"/api/jobs/{jid}")
        if job["status"] == "done":
            return job
        if job["status"] == "error":
            raise AssertionError(f"{path} failed: {job.get('error')}\n" + "\n".join(job.get("lines", [])))
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {path} job {jid}")

health, _ = request("GET", "/api/health")
assert health["ok"] is True and health["version"] == "2.1.0"
scope, _ = request("GET", "/api/scope")
assert scope["allowed_cidrs"] == ["192.168.250.0/30"], scope

first = run_job("/api/scan/discovery?cidr=192.168.250.0%2F30")
assert first["result"]["host_count"] >= 1, first
hosts, _ = request("GET", "/api/hosts")
remote = next((host for host in hosts["hosts"] if host["ip"] == TARGET), None)
assert remote is not None, hosts
assert remote.get("mac"), remote

baseline, _ = request("GET", "/api/baseline")
pending = next((item for item in baseline["pending"] if item["ip"] == TARGET), None)
assert pending is not None and pending["status"] == "new", baseline
accepted, _ = request(
    "POST", "/api/baseline/accept",
    payload={"ip": TARGET, "note": "fresh-journey fixture identity"}, headers=HEADER,
)
assert accepted["ok"] is True
baseline, _ = request("GET", "/api/baseline")
assert any(entry["ip"] == TARGET for entry in baseline["entries"]), baseline
assert not any(item["ip"] == TARGET for item in baseline["pending"]), baseline

services_job = run_job(f"/api/scan/services/{TARGET}")
services = services_job["result"]["services"]
assert any(str(service.get("port")) == "8080" for service in services), services
persisted_services, _ = request("GET", f"/api/hosts/{TARGET}/services")
assert any(str(service.get("port")) == "8080" for service in persisted_services["services"]), persisted_services

notes, _ = request(
    "PATCH", f"/api/hosts/{TARGET}/notes",
    payload={"notes": "Known CI fixture service; operator-reviewed."}, headers=HEADER,
)
assert notes["notes"].startswith("Known CI fixture")
read_notes, _ = request("GET", f"/api/hosts/{TARGET}/notes")
assert read_notes["notes"] == notes["notes"]

report_html, report_headers = request("GET", "/api/export/report")
assert "LANimals" in report_html and TARGET in report_html and "8080" in report_html
report_name = report_headers.get("X-LANimals-Report")
assert report_name and report_name.startswith("report_")
reports, _ = request("GET", "/api/reports")
assert any(item["name"] == report_name for item in reports["reports"]), reports

second = run_job("/api/scan/discovery?cidr=192.168.250.0%2F30")
assert second["result"]["diff"]["comparable"] is True, second
stable_diff, _ = request("GET", "/api/diff")
assert stable_diff["comparable"] is True, stable_diff
assert not stable_diff["appeared"] and not stable_diff["disappeared"], stable_diff

trap, _ = request(
    "POST", "/api/traps",
    payload={"type": "port", "port": 18082, "name": "journey-canary", "banner": "generic"},
    headers=HEADER,
)
assert trap["ok"] is True
trap_id = trap["trap"]["id"]
active, _ = request("GET", "/api/traps")
assert any(item["id"] == trap_id and item["status"] == "active" for item in active["traps"]), active
with open("/tmp/lanimals-journey-trap-id", "w", encoding="utf-8") as handle:
    handle.write(trap_id)
PY

# Force a real identity transition on the private fixture. The accepted baseline
# must not silently move; the operator should see a pending MAC change.
sudo ip netns exec "$NAMESPACE" ip link set "$NODE_IFACE" down
sudo ip netns exec "$NAMESPACE" ip link set "$NODE_IFACE" address 02:42:ac:11:00:99
sudo ip netns exec "$NAMESPACE" ip link set "$NODE_IFACE" up
sudo ip neigh flush dev "$HOST_IFACE" >/dev/null 2>&1 || true

"$ROOT/.venv/bin/python" - <<'PY'
import json
import time
import urllib.request

API = "http://127.0.0.1:18081"
TARGET = "192.168.250.2"
HEADER = {"X-LANimals-Operator": "1", "Content-Type": "application/json"}


def request(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(API + path, data=data, method=method, headers=HEADER if method != "GET" else {})
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.loads(response.read())

body = request("POST", "/api/scan/rogue?cidr=192.168.250.0%2F30", {})
jid = body["job_id"]
for _ in range(120):
    job = request("GET", f"/api/jobs/{jid}")
    if job["status"] == "done":
        break
    if job["status"] == "error":
        raise AssertionError(job)
    time.sleep(0.25)
else:
    raise AssertionError("rogue scan timed out")

baseline = request("GET", "/api/baseline")
changed = next((item for item in baseline["pending"] if item["ip"] == TARGET), None)
assert changed is not None and changed["status"] == "changed", baseline
assert changed["observed_mac"].lower() == "02:42:ac:11:00:99", changed
previous = changed["baseline_mac"]
assert previous and previous.lower() != changed["observed_mac"].lower(), changed

deferred = request("POST", "/api/baseline/defer", {"ip": TARGET, "note": "fixture MAC changed; defer for review"})
assert deferred["ok"] is True and deferred["baseline_changed"] is False
baseline_after = request("GET", "/api/baseline")
assert any(item["ip"] == TARGET for item in baseline_after["pending"]), baseline_after
PY

# Restart must preserve evidence while leaving traps inactive/interrupted.
lanimals stop
if lanimals status --json >/dev/null; then
    echo "LANimals unexpectedly remained healthy after stop" >&2
    exit 1
fi
lanimals start --no-browser

"$ROOT/.venv/bin/python" - <<'PY'
import json
import urllib.request

API = "http://127.0.0.1:18081"
TARGET = "192.168.250.2"
trap_id = open("/tmp/lanimals-journey-trap-id", encoding="utf-8").read().strip()


def get(path):
    with urllib.request.urlopen(API + path, timeout=10) as response:
        return json.loads(response.read())

hosts = get("/api/hosts")
assert any(host["ip"] == TARGET for host in hosts["hosts"]), hosts
services = get(f"/api/hosts/{TARGET}/services")
assert any(str(service.get("port")) == "8080" for service in services["services"]), services
notes = get(f"/api/hosts/{TARGET}/notes")
assert notes["notes"].startswith("Known CI fixture"), notes
baseline = get("/api/baseline")
assert any(item["ip"] == TARGET and item["status"] == "changed" for item in baseline["pending"]), baseline
traps = get("/api/traps")
restored = next((item for item in traps["traps"] if item["id"] == trap_id), None)
assert restored is not None, traps
assert restored["status"] != "active", restored
reports = get("/api/reports")
assert reports["reports"], reports
PY

lanimals stop
echo "Fresh install and full operator journey passed"
