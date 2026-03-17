<p align="center">
  <img src="assets/logos/LANimals.png" alt="LANimals" width="380"/>
</p>

<p align="center">
  <strong>Local network intelligence platform. Self-hosted. Operator-grade. Terminal-native.</strong>
</p>

---

## What it is

LANimals is a network intelligence platform that runs on your machine. It scans your LAN, tracks every device it finds, builds a MAC address baseline, flags rogue devices, fingerprints services, and renders everything as a live force-directed graph in your browser.

It remembers what it sees. Every scan writes to a local SQLite database. When something changes — a new device, a MAC address that changed, a service that appeared — LANimals records it with a timestamp. You can look at the history of any host, see exactly when it first appeared, and export a full HTML network report in one click.


---

## Operations

| Operation | What runs |
|---|---|
| **Discovery Scan** | nmap ping sweep + ARP + interface enumeration → SQLite |
| **ARP Refresh** | Fast `ip neigh` pull, instant graph update |
| **Host Mapping** | nmap with full hostname resolution |
| **Rogue Detection** | MAC baseline comparison — flags new/changed devices |
| **Inventory** | Local system: CPU, RAM, disk, interfaces |
| **Anomaly Scan** | Live outbound connection scoring |
| **Service Scan** | nmap -sV per host, stored in DB |

---

## Interface

- **Graph** — Force-directed canvas, physics simulation, click any node to inspect
- **Detail panel** — Identity, MAC/vendor, services, risk, timeline, notes, VT lookup
- **Hosts tab** — Full DB inventory table
- **Events tab** — Persistent event feed from SQLite
- **Sysinfo tab** — Live local system metrics
- **Report** — `http://127.0.0.1:8080/api/export/report`

---

## API
```
GET  /api/health
GET  /api/graph
GET  /api/stats
GET  /api/hosts
GET  /api/hosts/{ip}/services
GET  /api/hosts/{ip}/events
GET  /api/hosts/{ip}/notes
GET  /api/events
GET  /api/sysinfo
GET  /api/scan/anomaly
GET  /api/export/report
GET  /api/enrich/vt/{ip}

POST /api/scan/discovery?cidr=X
POST /api/scan/arp
POST /api/scan/hostmap?cidr=X
POST /api/scan/rogue?cidr=X
POST /api/scan/services/{ip}
POST /api/scan/inventory

PATCH /api/hosts/{ip}/notes
GET   /api/jobs
GET   /api/jobs/{jid}
```

---

## Persistence

| File | Contents |
|---|---|
| `tmp/lanimals.db` | Hosts, services, events, MAC baseline (SQLite WAL) |
| `tmp/nexus_discovery_cache.json` | Last discovery for fast graph reload |

---

## Requirements

- Python 3.10+, `nmap`
- `pip3 install fastapi uvicorn psutil`
- Linux (Pop!\_OS 24.04 / Ubuntu Noble tested)
- Optional: `VT_API_KEY` env var for VirusTotal enrichment

---

## Why not just use nmap

nmap tells you what's there right now.  
LANimals tells you what **changed**, what's **new**, what's **suspicious** — and keeps the history so you can prove it.

---

*LANimals // badBANANA research // GnomeMan4201*
