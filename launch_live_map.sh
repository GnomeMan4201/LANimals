#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! python -c "import fastapi, uvicorn" >/dev/null 2>&1; then
  echo "[LANimals] missing fastapi/uvicorn; install them first"
  exit 1
fi

echo "[LANimals] starting live map on http://127.0.0.1:8099"
python -m uvicorn core.nexus_api:app --host 127.0.0.1 --port 8099 --reload
