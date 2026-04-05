#!/usr/bin/env bash
set -euo pipefail
export PYTHONWARNINGS=ignore

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GRN='\033[0;32m'; YEL='\033[1;33m'; RED='\033[0;31m'
CYN='\033[0;36m'; DIM='\033[2m'; BLD='\033[1m'; RST='\033[0m'

sep() { echo -e "${DIM}────────────────────────────────────────${RST}"; }

sep
echo -e "  ${BLD}LANimals${RST} — Network Deception & Risk Intelligence Platform"
sep
echo ""

python3 -c "from core.nexus_models import GraphNode; from core.nexus_risk import score_host" 2>/dev/null || {
  echo -e "  ${RED}✗${RST}  missing deps — run: pip install -r requirements.txt"
  exit 1
}
echo -e "  ${GRN}✓${RST}  core engine loaded"
echo -e "  ${CYN}→${RST}  scanning synthetic network: 192.168.1.0/24"
echo ""

python3 - << 'PYEOF'
import sys, time
sys.path.insert(0, '.')
from core.nexus_risk import score_host

GRN='\033[0;32m'; YEL='\033[1;33m'; RED='\033[0;31m'
CYN='\033[0;36m'; DIM='\033[2m'; BLD='\033[1m'; RST='\033[0m'

def delay(t=0.25): time.sleep(t)

hosts = [
    {
        "host": {"ip": "192.168.1.1",  "hostname": "gateway",      "mac": "aa:bb:cc:dd:ee:01"},
        "services": [{"port": "80", "proto": "tcp"}, {"port": "443", "proto": "tcp"}],
        "in_baseline": True, "cve_count": 0, "honeypot_hits": 0,
    },
    {
        "host": {"ip": "192.168.1.10", "hostname": "workstation-a", "mac": "aa:bb:cc:dd:ee:02"},
        "services": [{"port": "22", "proto": "tcp"}, {"port": "80", "proto": "tcp"}],
        "in_baseline": True, "cve_count": 1, "honeypot_hits": 0,
    },
    {
        "host": {"ip": "192.168.1.44", "hostname": "unknown-host",  "mac": "aa:bb:cc:dd:ee:03"},
        "services": [{"port": "445", "proto": "tcp"}, {"port": "3389", "proto": "tcp"}, {"port": "4444", "proto": "tcp"}],
        "in_baseline": False, "cve_count": 3, "honeypot_hits": 2,
    },
    {
        "host": {"ip": "192.168.1.99", "hostname": "canary-01",     "mac": "aa:bb:cc:dd:ee:04"},
        "services": [{"port": "22", "proto": "tcp"}, {"port": "23", "proto": "tcp"}],
        "in_baseline": True, "cve_count": 0, "honeypot_hits": 4,
    },
    {
        "host": {"ip": "192.168.1.200","hostname": "db-internal",   "mac": "aa:bb:cc:dd:ee:05"},
        "services": [{"port": "3306", "proto": "tcp"}, {"port": "5432", "proto": "tcp"}, {"port": "6379", "proto": "tcp"}],
        "in_baseline": True, "cve_count": 2, "honeypot_hits": 0,
    },
]

print(f"  {BLD}NETWORK SCAN{RST}")
delay(0.3)

results = []
for h in hosts:
    score, level, reasons = score_host(
        h["host"], h["services"],
        in_baseline=h["in_baseline"],
        cve_count=h["cve_count"],
        honeypot_hits=h["honeypot_hits"],
    )
    results.append((h["host"]["ip"], h["host"]["hostname"], score, level, reasons))
    delay(0.2)
    col = GRN if score < 30 else YEL if score < 60 else RED
    bar = "#" * (score // 5) + "-" * (20 - score // 5)
    print(f"  {h['host']['ip']:<16} {h['host']['hostname']:<14} [{bar}] {col}{score:>3}{RST}  {DIM}{level}{RST}")

print()
delay(0.3)
print(f"  {BLD}RISK SUMMARY{RST}")
critical = [(ip, hn, s, l, r) for ip, hn, s, l, r in results if s >= 60]
for ip, hn, score, level, reasons in critical:
    print(f"  {RED}▲ CRITICAL{RST}  {ip}  {hn}")
    for r in reasons[:3]:
        print(f"    {DIM}↳ {r}{RST}")
    delay(0.2)

print()
delay(0.3)
print(f"  {BLD}TRAP STATUS{RST}")
traps = [
    ("192.168.1.99", "canary-01",  "ACTIVE",    4, "ssh+telnet"),
    ("192.168.1.44", "unknown-host","TRIGGERED", 2, "smb+rdp"),
]
for ip, name, status, hits, ports in traps:
    col = YEL if status == "ACTIVE" else RED
    print(f"  {ip:<16} {name:<14} {col}{status:<10}{RST} hits={hits}  ports={ports}")
PYEOF

echo ""
sep
echo -e "  ${GRN}✓${RST}  scan complete — 5 hosts scored"
echo -e "  ${RED}▲${RST}  1 critical host detected (port 4444 + not in baseline)"
echo -e "  ${CYN}→${RST}  full graph UI: uvicorn core.nexus_api:app --port 8000"
sep
echo ""
