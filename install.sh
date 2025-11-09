#!/usr/bin/env bash
set -e

RED="\033[0;31m"
GRN="\033[0;32m"
NC="\033[0m"

echo -e "${GRN}[*] Installing LANimals requirements...${NC}"
pip3 install --user -r requirements.txt

# Try to detect if venv/conda is active, else install system-wide
if [[ -d "venv" ]] || [[ -n "$VIRTUAL_ENV" ]]; then
    echo -e "${GRN}[i] Using virtual environment. Skipping user PATH change.${NC}"
else
    # Add to .bashrc and .zshrc for PATH persistency
    LA_BIN="$PWD/bin"
    if [[ ":$PATH:" != *":$LA_BIN:"* ]]; then
        echo -e "\n# LANimals CLI tools" >> ~/.bashrc
        echo "export PATH=\"$LA_BIN:\$PATH\"" >> ~/.bashrc
        echo -e "\n# LANimals CLI tools" >> ~/.zshrc
        echo "export PATH=\"$LA_BIN:\$PATH\"" >> ~/.zshrc
        echo -e "${GRN}[+] Added LANimals bin to PATH in .bashrc and .zshrc${NC}"
    fi
    export PATH="$LA_BIN:$PATH"
fi

echo -e "${GRN}[] LANimals installed.${NC}\n"
echo -e "${RED}To use LANimals from any terminal, open a new shell or run:${NC}"
echo -e "    export PATH=\"$PWD/bin:\$PATH\"\n"

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
echo "    lanimals_dash           # LANimals dashboard"
echo
echo -e "${RED}Run: lanimals_sysinfo or any other module command.${NC}"
