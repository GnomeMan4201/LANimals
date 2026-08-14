[![CI](https://github.com/GnomeMan4201/LANimals/actions/workflows/ci.yml/badge.svg)](https://github.com/GnomeMan4201/LANimals/actions/workflows/ci.yml)

<p align="center">

  <img src="assets/logos/LANimals.png" alt="LANimals" width="380"/>
</p>

# LANimals

**Local network intelligence platform — self-hosted, operator-grade, terminal-native.**

## Demo

    ./scripts/demo.sh

![LANimals demo](demo_recordings/demo.gif)

---

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](#)
[![Latest tagged release](https://img.shields.io/badge/latest_tag-v1.0.0-blue.svg)](https://github.com/GnomeMan4201/LANimals/releases)

---

LANimals is a network intelligence platform that runs on your machine. It scans your approved local scope, tracks every device it finds, proposes MAC address baseline changes for operator review, flags new or changed devices, fingerprints services, and renders the observations as a live force-directed graph in your browser.

nmap tells you what's there right now. LANimals tells you what changed, what's new, and what deserves investigation — and keeps the history so you can reconstruct and evidence those changes.

---

![LANimals Personality Overlay](assets/lanimals_personality_overlay.png)
*Personality overlay mode — hosts assigned heuristic interface labels (scout/mimic/parasite/leech) from configured risk signals. These labels support triage; they are not behavioral attribution. Force-directed graph with live risk scoring and a per-host investigation panel.*

---

## Requirements

- Python 3.10+
- Linux (Pop!_OS / Ubuntu tested)
- nmap: `sudo apt install nmap`
- Optional: `export VT_API_KEY=your_key` for VirusTotal enrichment

---

## Install
```bash
git clone https://github.com/GnomeMan4201/LANimals.git
cd LANimals
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
sudo apt install nmap
```

LANimals currently uses a checkout-first installation because its CLI, browser UI,
assets, and local state are operated together. `pip install .` is intentionally not
advertised as a supported installation path.

## Run
```bash
bash lan.sh
```

Opens at `http://127.0.0.1:8080` — auto-launches browser and starts background ARP refresh.

LANimals binds to loopback by default. To approve a scan boundary explicitly:

```bash
export LANIMALS_ALLOWED_CIDRS=192.168.1.0/24
bash lan.sh
```

The browser terminal is an allowlisted LANimals command bridge, not an operating-system shell. A non-loopback server bind is refused unless both `LANIMALS_HOST` and `LANIMALS_ALLOW_REMOTE=1` are set. If remote access is necessary, put LANimals behind authenticated network access.

Direct state-changing API calls require `X-LANimals-Operator: 1`. This non-simple header prevents ordinary cross-site forms from silently triggering localhost operations; it is a browser boundary, not remote-user authentication.

## CLI

Run the command center directly from any working directory:

```bash
./bin/lanimals help
./bin/lanimals version
./bin/lanimals dashboard
```

To make the checkout's commands available in the current shell:

```bash
export PATH="$PWD/bin:$PATH"
lanimals help
```

The dispatcher resolves its own checkout, so supported commands do not depend on
the caller's working directory. Network inspection commands may require elevated
capabilities. Browser scans and targeted `netmap`/`vulnscan` operations apply the
same approved-private-CIDR boundary; older standalone research modules are not all
part of that supported operator path.

---

## Operations

| Operation | What runs |
|---|---|
| Discovery Scan | nmap ping sweep + ARP + interface enumeration |
| ARP Refresh | Fast `ip neigh` pull, instant graph update |
| Host Mapping | nmap with full hostname resolution |
| Rogue Detection | MAC baseline comparison — flags new/changed devices for accept/defer review |
| Inventory | Local system: CPU, RAM, disk, interfaces |
| Anomaly Scan | Live outbound connection scoring |
| Service Scan | nmap -sV per host, stored in DB |

---

## Interface

- Force-directed canvas graph with physics simulation
- Click any node to inspect identity, MAC/vendor, services, risk, timeline, and notes
- Hosts tab, Events tab, Sysinfo tab
- VirusTotal enrichment via `VT_API_KEY`
- One-click HTML network report export
- Explicit baseline accept/defer decisions with an audit trail
- Honest empty state by default; synthetic graph data requires `LANIMALS_DEMO_MODE=1`

---

## API
```
GET  /api/health
GET  /api/scope
GET  /api/graph
GET  /api/hosts
GET  /api/hosts/{ip}/services
GET  /api/hosts/{ip}/events
GET  /api/events
GET  /api/sysinfo
GET  /api/export/report
GET  /api/baseline
POST /api/scan/discovery?cidr=X
POST /api/scan/arp
POST /api/scan/rogue?cidr=X
POST /api/scan/services/{ip}
POST /api/scan/anomaly
POST /api/watchdog
PATCH /api/hosts/{ip}/notes
POST /api/baseline/accept
POST /api/baseline/defer
```

---

*LANimals // badBANANA research // GnomeMan4201*
