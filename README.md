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

## Quickstart
```bash
The get_host_notes/set_host_notes functions never made it into nexus_db.py — the patch assertion failed silently. Fix it directly.
bash

# Check what's actually at the end of nexus_db.py
tail -20 ~/LANimals/core/nexus_db.py

bash

# Check the exact ending string
python3 -c "
content = open('core/nexus_db.py').read()
print(repr(content[-200:]))
"

bash

# Write the notes functions + notes column directly
python3 - << 'PYEOF'
from pathlib import Path

path = Path("/home/bad_banana/LANimals/core/nexus_db.py")
content = path.read_text()

# 1 — Add notes column to CREATE TABLE if not already there
if "notes       TEXT" not in content:
    content = content.replace(
        "            status      TEXT DEFAULT 'normal',",
        "            status      TEXT DEFAULT 'normal',\n            notes       TEXT DEFAULT '',"
    )
    print("notes column added to schema")
else:
    print("notes column already present")

# 2 — Add migration to init_db so existing DB gets the column
old_init = '        CREATE INDEX IF NOT EXISTS idx_services_ip ON services(ip);\n        """)'
new_init = '''        CREATE INDEX IF NOT EXISTS idx_services_ip ON services(ip);
        """)
        # Migrate: add notes column if upgrading from older DB
        try:
            c.execute("ALTER TABLE hosts ADD COLUMN notes TEXT DEFAULT \\'\\'"  )
        except Exception:
            pass  # column already exists'''
if old_init in content and "Migrate: add notes" not in content:
    content = content.replace(old_init, new_init)
    print("migration added to init_db")

# 3 — Add functions at end of file (before init_db() call)
notes_funcs = '''

def get_host_notes(ip: str) -> str:
    with _lock:
        c = _conn()
        row = c.execute("SELECT notes FROM hosts WHERE ip=?", (ip,)).fetchone()
        c.close()
    return (row["notes"] or "") if row else ""


def set_host_notes(ip: str, notes: str) -> None:
    now = _now()
    with _lock:
        c = _conn()
        c.execute(
            "INSERT INTO hosts (ip, notes, first_seen, last_seen) "
            "VALUES (?,?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET notes=excluded.notes",
            (ip, notes, now, now)
        )
        c.commit()
        c.close()

'''

if "def get_host_notes" not in content:
    # Insert before the final init_db() call
    content = content.rstrip()
    if content.endswith("init_db()"):
        content = content[:-len("init_db()")] + notes_funcs + "\ninit_db()\n"
    else:
        content = content + notes_funcs + "\ninit_db()\n"
    print("get_host_notes / set_host_notes added")
else:
    print("notes functions already present")

path.write_text(content)
PYEOF

bash

python3 -c "import ast; ast.parse(open('core/nexus_db.py').read()); print('syntax OK')"
python3 -c "from core.nexus_db import get_host_notes, set_host_notes; print('import OK'); set_host_notes('192.168.0.1','test'); print('write OK:', get_host_notes('192.168.0.1'))"

bash

# Also write the README that got ^C'd
cat > ~/LANimals/README.md << 'EOF'
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

## Quickstart
```bash
lan
```

Open: **http://127.0.0.1:8080**

If `lan` isn't aliased yet:
```bash
cd ~/LANimals && bash lan.sh
```

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
