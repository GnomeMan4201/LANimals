#!/usr/bin/env bash
set -eu

ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

RED="\033[0;31m"
GRN="\033[0;32m"
NC="\033[0m"

echo -e "${GRN}[*] Installing LANimals requirements...${NC}"
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    python3 -m pip install -r "$ROOT/requirements.txt"
else
    python3 -m pip install --user -r "$ROOT/requirements.txt"
fi

echo -e "${GRN}[+] LANimals dependencies installed.${NC}\n"
echo -e "${RED}To use the checkout-first CLI in this shell, run:${NC}"
echo -e "    export PATH=\"$ROOT/bin:\$PATH\"\n"

echo -e "${GRN}Example commands:${NC}"
echo "    lanimals_sysinfo        # System info"
echo "    lanimals_traffic        # Network traffic analyzer"
echo "    lanimals_lootlog        # View loot logs"
echo "    lanimals_lootsummary    # Summarize loot analytics"
echo "    lanimals_tripwire       # Tripwire monitor"
echo "    lanimals_roguescan      # Rogue device scanner"
echo "    lanimals_asciiroll      # Rotating ASCII banner"
echo "    lanimals_ghostscan      # Outbound infra detection"
echo "    lanimals_anomalydetector # Network anomaly detector"
echo "    lanimals_threatenrich   # Live threat enrichment"
echo "    lanimals_sessionlogger  # Session logger/report"
echo "    lanimals_darkwebhost    # Dark web host detector"
echo "    lanimals_wlanbeacon     # WLAN beacon hunter"
echo "    lanimals_fortress       # Security hardening"
echo "    lanimals_alert          # Threat alert system"
echo "    lanimals_viznet         # Interactive network viz"
echo "    lanimals_vulscan        # Vuln scanner"
echo "    lanimals_netmap         # Visual network map"
echo "    lanimals_recon          # Autonomous recon"
echo "    lanimals dashboard      # LANimals browser dashboard"
echo
echo -e "${RED}Run: $ROOT/bin/lanimals help${NC}"
