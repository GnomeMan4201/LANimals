#!/usr/bin/env bash
# LANimals Nexus — operator console launcher
set -e
cd "$(dirname "$0")"

PORT="${LANIMALS_PORT:-8080}"
HOST="${LANIMALS_HOST:-0.0.0.0}"
LOG="${LANIMALS_LOG:-/tmp/lanimals_nexus.log}"

# Kill any existing instance on this port
pkill -f "nexus_api\|lanimals-ui" 2>/dev/null || true
sleep 0.5

echo "[LANimals] Starting Nexus on http://${HOST}:${PORT}"
echo "[LANimals] Log: ${LOG}"

nohup uvicorn core.nexus_api:app \
  --host "${HOST}" \
  --port "${PORT}" \
  --reload \
  --log-level info \
  > "${LOG}" 2>&1 &

PID=$!
echo "[LANimals] PID: ${PID}"
sleep 1.5

if kill -0 "${PID}" 2>/dev/null; then
  echo "[LANimals] Server up — http://127.0.0.1:${PORT}"
else
  echo "[LANimals] Server failed to start — check ${LOG}"
  exit 1
fi
