#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   LANimals — operator console boot   ║
# ╚══════════════════════════════════════╝
set -e
cd "$(dirname "$(realpath "$0")")"

PORT="${LANIMALS_PORT:-8080}"
HOST="${LANIMALS_HOST:-127.0.0.1}"
LOG="/tmp/lanimals_nexus.log"
PID_FILE="/tmp/lanimals_nexus.pid"
URL="http://127.0.0.1:${PORT}"

if [[ "$HOST" != "127.0.0.1" && "$HOST" != "::1" && "${LANIMALS_ALLOW_REMOTE:-0}" != "1" ]]; then
  echo "[!] Refusing non-loopback bind without LANIMALS_ALLOW_REMOTE=1"
  exit 1
fi

# Stop only the LANimals process recorded by this launcher.
if [[ -f "$PID_FILE" ]]; then
  OLD_PID=$(<"$PID_FILE")
  if [[ "$OLD_PID" =~ ^[0-9]+$ ]] && [[ -r "/proc/${OLD_PID}/cmdline" ]] && \
      tr '\0' ' ' < "/proc/${OLD_PID}/cmdline" | grep -q "core.nexus_api:app"; then
    kill "$OLD_PID" 2>/dev/null || true
    sleep 0.4
  fi
  rm -f "$PID_FILE"
fi

# Dependency check
for dep in python3; do
  command -v nmap >/dev/null || echo "  [!] nmap not found — discovery scan will use ARP only"
  command -v "$dep" >/dev/null || { echo "[!] missing: $dep"; exit 1; }
done

echo ""
echo "  ██╗      █████╗ ███╗  ██╗██╗███╗   ███╗ █████╗ ██╗     ███████╗"
echo "  ██║     ██╔══██╗████╗ ██║██║████╗ ████║██╔══██╗██║     ██╔════╝"
echo "  ██║     ███████║██╔██╗██║██║██╔████╔██║███████║██║     ███████╗"
echo "  ██║     ██╔══██║██║╚████║██║██║╚██╔╝██║██╔══██║██║     ╚════██║"
echo "  ███████╗██║  ██║██║ ╚███║██║██║ ╚═╝ ██║██║  ██║███████╗███████║"
echo "  ╚══════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝"
echo ""
echo "  Nexus operator console — starting on ${HOST}:${PORT}"
if [[ "$HOST" != "127.0.0.1" && "$HOST" != "::1" ]]; then
  echo "  [!] Remote bind enabled. Place LANimals behind authenticated network access."
fi
echo ""

# Start server
nohup python3 -m uvicorn core.nexus_api:app \
  --host "$HOST" \
  --port "${PORT}" \
  --log-level warning \
  > "${LOG}" 2>&1 &

PID=$!
echo "$PID" > "$PID_FILE"
disown $PID

# Wait for ready
for i in $(seq 1 12); do
  sleep 0.4
  if curl -sf "${URL}/api/health" >/dev/null 2>&1; then
    echo "  [✓] Server up  (pid ${PID})"
    echo "  [✓] UI         ${URL}"
    echo "  [✓] Log        ${LOG}"
    echo ""
    # Auto-detect subnet and print it
    CIDR=$(ip route | awk '/scope link/ && /wlp|eth|enp|wlan/ {print $1}' | head -1)
    if [ -n "$CIDR" ]; then
      echo "  [i] Detected subnet: ${CIDR}"
      echo "      Run discovery:  curl -s -X POST -H 'X-LANimals-Operator: 1' \"${URL}/api/scan/discovery?cidr=${CIDR}\""
    fi
    echo ""
    # Open browser if available
    xdg-open "${URL}" 2>/dev/null || true
    # Auto-run ARP refresh on boot
    curl -sf "${URL}/api/scan/arp" -X POST -H "X-LANimals-Operator: 1" >/dev/null 2>&1 &
    echo "  [✓] ARP refresh queued"
    echo "  [✓] Browser refresh scheduler active while the console is open"
    exit 0
  fi
done

echo "  [!] Server failed to start — check ${LOG}"
rm -f "$PID_FILE"
cat "${LOG}" | tail -20
exit 1
