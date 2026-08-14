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
[![Version](https://img.shields.io/badge/version-2.1.0-maroon.svg)](VERSION)

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
- venv, nmap, and local route tooling: `sudo apt install python3-venv nmap iproute2`
- Optional: `export VT_API_KEY=your_key` for VirusTotal enrichment

---

## Install
```bash
git clone https://github.com/GnomeMan4201/LANimals.git
cd LANimals
sudo apt install python3-venv nmap iproute2
./install.sh
```

The installer creates an isolated `.venv` inside the checkout and links the
checkout-aware commands into `~/.local/bin`. It refuses to overwrite a real file
already using one of those command names. LANimals remains a checkout-first
installation because the CLI, browser UI, assets, and runtime are operated together;
`pip install .` is intentionally not advertised as a supported installation path.
When run interactively, `install.sh` proposes an eligible private subnet and asks for
approval. For unattended installation, use `./install.sh --scope 192.168.1.0/24`.

## First run

Approve the exact private network LANimals may inspect. Interactive setup proposes an
eligible local subnet and requires confirmation, or you can provide it explicitly:

```bash
./bin/lanimals setup
# or
./bin/lanimals setup 192.168.1.0/24
./bin/lanimals start
```

`lanimals start` opens `http://127.0.0.1:8080`. It does not automatically scan.
Collection begins only after an operator action in the local console.

Useful lifecycle commands:

```bash
lanimals status
lanimals open
lanimals doctor
lanimals config
lanimals stop
```

Configuration is stored at `${XDG_CONFIG_HOME:-~/.config}/lanimals/config.json`.
SQLite evidence and durable state live under
`${XDG_DATA_HOME:-~/.local/share}/lanimals`; logs use
`${XDG_STATE_HOME:-~/.local/state}/lanimals`; disposable scan artifacts use
`${XDG_CACHE_HOME:-~/.cache}/lanimals`. Moving or updating the checkout does not move
or delete the evidence store.

On the first v2.1 start, LANimals non-destructively imports a checkout-relative v2.0
SQLite database and supported state files when the new XDG destination is empty. The
legacy files remain untouched as a recovery copy.

The browser terminal is an allowlisted LANimals command bridge, not an operating-system shell. A non-loopback server bind is refused unless both `LANIMALS_HOST` and `LANIMALS_ALLOW_REMOTE=1` are set. If remote access is necessary, put LANimals behind authenticated network access.

Direct state-changing API calls require `X-LANimals-Operator: 1`. This non-simple header prevents ordinary cross-site forms from silently triggering localhost operations; it is a browser boundary, not remote-user authentication.

## CLI

Run the command center directly from any working directory:

```bash
./bin/lanimals help
./bin/lanimals version
./bin/lanimals setup 192.168.1.0/24
./bin/lanimals start
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

## Capability contract

[`capabilities.json`](capabilities.json) is the machine-checked statement of
what LANimals implements, what requires a self-hosted Linux/network runtime,
and what remains an experimental legacy module. CI verifies its version,
operator-command grammar, API routes, evidence paths, and hosted-demo boundary.

The hosted site is a representative, in-memory workflow surface. It never
claims access to the visitor's LAN. Operational collection and persistence are
provided only by the self-hosted runtime.

---

*LANimals // badBANANA research // GnomeMan4201*
