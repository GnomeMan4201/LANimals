#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   LANimals — operator console boot   ║
# ╚══════════════════════════════════════╝
set -e
cd "$(dirname "$(realpath "$0")")"

PORT="${LANIMALS_PORT:-8080}"
LOG="/tmp/lanimals_nexus.log"
URL="http://127.0.0.1:${PORT}"

# Kill any stale instance
pkill -f "nexus_api" 2>/dev/null && sleep 0.4 || true

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
echo "  Nexus operator console — starting on ${URL}"
echo ""

# Start server
nohup python3 -m uvicorn core.nexus_api:app \
  --host 0.0.0.0 \
  --port "${PORT}" \
  --log-level warning \
  > "${LOG}" 2>&1 &

PID=$!
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
      echo "      Run discovery:  curl -s -X POST \"${URL}/api/scan/discovery?cidr=${CIDR}\""
    fi
    echo ""
    # Open browser if available
    xdg-open "${URL}" 2>/dev/null || true
    # Auto-run ARP refresh on boot
    curl -sf "${URL}/api/scan/arp" -X POST >/dev/null 2>&1 &
    echo "  [✓] ARP refresh queued"
    exit 0
  fi
done

echo "  [!] Server failed to start — check ${LOG}"
cat "${LOG}" | tail -20
exit 1
