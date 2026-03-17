# LANimals Nexus

**Local network intelligence platform. Self-hosted, operator-grade, terminal-native.**

LANimals Nexus turns your machine into an always-on network monitoring console. It runs scans, persists everything to a local SQLite database, tracks MAC address history, flags rogue devices, fingerprints services, and renders the live network as a force-directed graph in your browser.

---

## What it does

| Capability | How |
|---|---|
| Host discovery | nmap ping sweep + ARP table + local interface enumeration |
| MAC baseline tracking | Compares every scan against saved MAC history, flags changes |
| Rogue detection | New MACs and MAC-changed hosts flagged with reason |
| Service fingerprinting | nmap -sV per host, stored in SQLite |
| Vendor identification | OUI prefix lookup (offline, no API needed) |
| Anomaly detection | Live outbound connections scored against known host list |
| Host timeline | Per-host event history stored across sessions |
| Network graph | Force-directed D3-style canvas renderer, auto-simulation |
| HTML report export | One-click full network inventory report at `/api/export/report` |
| Persistent state | SQLite — survives reboots, builds history over time |

---

## Quickstart
```bash
# One command to start everything
lan

# Or directly
cd ~/LANimals && bash lan.sh
```

Open: **http://127.0.0.1:8080**

---

## Aliases

| Command | Action |
|---|---|
| `lan` | Start the operator console |
| `lan-stop` | Kill the server |
| `lan-log` | Tail the server log |
| `lan-scan` | Run discovery on detected subnet |

---

## Operations (UI left rail)

| Operation | What runs |
|---|---|
| **Discovery Scan** | nmap ping sweep + ARP + cache write → graph refresh |
| **ARP Refresh** | Fast `ip neigh` pull, no nmap, instant graph update |
| **Host Mapping** | nmap with full hostname resolution |
| **Rogue Detection** | MAC baseline comparison, flags new/changed devices |
| **Inventory** | Local system info — CPU, RAM, disk, interfaces |
| **Anomaly Scan** | Live outbound connection analysis |

---

## API reference
```
GET  /api/health                    Server status
GET  /api/graph                     Full graph snapshot (nodes + edges + events)
GET  /api/stats                     DB counts + graph stats
GET  /api/hosts                     All known hosts from DB
GET  /api/hosts/{ip}/services       Services for a specific host
GET  /api/hosts/{ip}/events         Event timeline for a host
GET  /api/events                    Recent events feed
GET  /api/sysinfo                   Local system information
GET  /api/export/report             Full HTML network report (open in browser)
GET  /api/scan/anomaly              Live connection anomaly check

POST /api/scan/discovery?cidr=X     Full discovery scan
POST /api/scan/arp                  Fast ARP refresh
POST /api/scan/hostmap?cidr=X       Hostname resolution sweep
POST /api/scan/rogue?cidr=X         Rogue device detection
POST /api/scan/services/{ip}        Service fingerprint scan
POST /api/scan/inventory            System inventory

GET  /api/jobs                      Recent job list
GET  /api/jobs/{jid}                Job detail + live log lines
```

---

## Architecture
```
lan.sh
  └── uvicorn core.nexus_api:app (port 8080)
        ├── core/nexus_collectors.py   ARP, nmap, psutil collectors
        ├── core/nexus_builder.py      Graph snapshot builder (cache-backed)
        ├── core/nexus_db.py           SQLite persistence layer
        ├── core/nexus_models.py       Pydantic graph models
        ├── core/nexus_state.py        JSON state (MAC baseline, host state)
        └── ui/lanimals_live_map.html  Single-file operator console UI
```

**Key design decisions:**
- `/api/graph` never runs nmap live — it reads from the discovery cache. Fast.
- Scans run as background jobs with line-by-line log streaming to the UI.
- SQLite uses WAL mode — concurrent reads during active scans.
- Force-directed graph simulation runs in the browser canvas, no D3 dependency.
- All scan state survives server restarts via SQLite + JSON cache files.

---

## Requirements

- Python 3.10+
- `nmap` (for discovery and service scans)
- `pip3 install fastapi uvicorn psutil` (system-wide or in venv)
- Linux — tested on Pop!_OS 24.04 / Ubuntu Noble

Optional but recommended:
- `sudo` NOPASSWD for nmap (enables MAC address collection in ping sweep)

---

## Data that persists

| File | Contents |
|---|---|
| `tmp/lanimals.db` | Hosts, services, events, MAC baseline (SQLite) |
| `tmp/nexus_discovery_cache.json` | Last discovery results for graph builder |
| `tmp/nexus_state.json` | Host state change tracking |

---

## Why not just use nmap

nmap tells you what's there right now.

LANimals tells you what **changed**, what's **new**, what's **suspicious**, and keeps the history so you can **prove it**.

Specifically:
- nmap has no memory. LANimals builds a MAC baseline and diffs every scan against it.
- nmap output evaporates. LANimals persists everything to SQLite across reboots.
- nmap requires a terminal. LANimals runs in a browser tab accessible from any device on the LAN.
- nmap is a tool. LANimals is infrastructure you can extend.

---

*LANimals // badBANANA lab // GnomeMan4201*
