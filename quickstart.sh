#!/bin/bash
# LANimals quickstart
set -e

echo "[*] Checking dependencies..."
python3 -c "import fastapi, uvicorn, scapy, rich" 2>/dev/null || {
    echo "[*] Installing dependencies..."
    pip install -r requirements.txt
}

command -v nmap >/dev/null || echo "[!] nmap not found — install with: sudo apt install nmap"

echo "[*] Starting LANimals..."
exec bash lan.sh
