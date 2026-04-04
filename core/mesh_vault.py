from __future__ import annotations

"""
LANimals :: MeshVault
Ported and integrated from LANIMORPH mesh/ and chain/ systems.

Provides:
  - Vault storage for mutated payloads
  - Mirror node registry
  - Sealed mesh export (zip + SHA256)
  - Chain replay from mutation_chain DB table
"""

import hashlib
import json
import os
import sqlite3
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "tmp" / "lanimals.db"
VAULT_DIR = ROOT / "tmp" / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)
(VAULT_DIR / "mutants").mkdir(exist_ok=True)
(VAULT_DIR / "mirrors").mkdir(exist_ok=True)
(VAULT_DIR / "sealed").mkdir(exist_ok=True)
(VAULT_DIR / "replays").mkdir(exist_ok=True)


# ── Vault storage ─────────────────────────────────────────────────────────────

def store_mutant(ip: str, b64_data: str, xor_key: int) -> Path:
    """Store a mutated payload binary to the vault."""
    import base64
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{ip.replace('.', '_')}_k{xor_key}_{ts}.bin"
    out_path = VAULT_DIR / "mutants" / filename
    raw = base64.b64decode(b64_data)
    out_path.write_bytes(raw)
    print(f"[+] Stored mutant: {out_path.name}")
    return out_path


def list_vault(ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all stored mutants, optionally filtered by IP."""
    results = []
    for f in sorted((VAULT_DIR / "mutants").glob("*.bin")):
        if ip and not f.name.startswith(ip.replace(".", "_")):
            continue
        results.append({
            "filename": f.name,
            "size": f.stat().st_size,
            "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
        })
    return results


# ── Mirror nodes ──────────────────────────────────────────────────────────────

def register_mirror(ip: str, payload: Optional[str] = None) -> Path:
    """Register a mirror node beacon for a host."""
    import base64
    payload = payload or f"MIRROR NODE ACTIVE @ {ip} - {datetime.utcnow().isoformat()}"
    encoded = base64.b64encode(payload.encode()).decode()
    mirror_path = VAULT_DIR / "mirrors" / f"mirror_{ip.replace('.', '_')}.bin"
    mirror_path.write_text(encoded)

    # Also log to DB
    c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    c.execute("""
        CREATE TABLE IF NOT EXISTS mirror_nodes (
            ip          TEXT PRIMARY KEY,
            registered  TEXT,
            payload     TEXT,
            active      INTEGER DEFAULT 1
        )
    """)
    c.execute("""
        INSERT INTO mirror_nodes (ip, registered, payload, active)
        VALUES (?, ?, ?, 1)
        ON CONFLICT(ip) DO UPDATE SET
            registered=excluded.registered,
            payload=excluded.payload,
            active=1
    """, (ip, datetime.utcnow().isoformat(), encoded))
    c.commit()
    c.close()
    print(f"[+] Mirror node registered: {ip}")
    return mirror_path


def get_mirrors() -> List[Dict[str, Any]]:
    """Return all registered mirror nodes."""
    try:
        c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        c.row_factory = sqlite3.Row
        rows = c.execute("SELECT * FROM mirror_nodes ORDER BY registered DESC").fetchall()
        c.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


# ── Sealed mesh export ────────────────────────────────────────────────────────

def seal_mesh(password: str = "banana") -> Dict[str, str]:
    """
    Export the full mutation chain DB into a password-protected zip.
    Returns dict with path and SHA256 hash.
    """
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = VAULT_DIR / "sealed" / f"sealed_mesh_{ts}.zip"

    with zipfile.ZipFile(str(out_path), "w", zipfile.ZIP_DEFLATED) as z:
        z.setpassword(password.encode())
        # Include the main DB
        if DB_PATH.exists():
            z.write(str(DB_PATH), arcname="lanimals.db")
        # Include vault mutants index
        mutants = list_vault()
        z.writestr("vault_index.json", json.dumps(mutants, indent=2))
        # Include mutation chain export
        chain = _export_chain_json()
        z.writestr("mutation_chain.json", chain)

    sha256 = hashlib.sha256(out_path.read_bytes()).hexdigest()

    print(f"[✓] Mesh sealed: {out_path.name}")
    print(f"[✓] SHA256: {sha256}")
    return {"path": str(out_path), "sha256": sha256, "ts": ts}


def _export_chain_json() -> str:
    """Export full mutation chain as JSON string."""
    try:
        c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        c.row_factory = sqlite3.Row
        rows = c.execute(
            "SELECT * FROM mutation_chain ORDER BY ts DESC"
        ).fetchall()
        c.close()
        return json.dumps([dict(r) for r in rows], indent=2)
    except Exception:
        return "[]"


def list_sealed() -> List[Dict[str, Any]]:
    """List all sealed mesh exports."""
    results = []
    for f in sorted((VAULT_DIR / "sealed").glob("*.zip"), reverse=True):
        sha256 = hashlib.sha256(f.read_bytes()).hexdigest()
        results.append({
            "filename": f.name,
            "size": f.stat().st_size,
            "sha256": sha256,
            "created": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
        })
    return results


# ── Chain replay ──────────────────────────────────────────────────────────────

def get_chain_for_ip(ip: str) -> List[Dict[str, Any]]:
    """Return full mutation chain for an IP from DB."""
    try:
        c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        c.row_factory = sqlite3.Row
        rows = c.execute(
            "SELECT * FROM mutation_chain WHERE ip = ? ORDER BY ts ASC",
            (ip,)
        ).fetchall()
        c.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def replay_chain(ip: str) -> Dict[str, Any]:
    """
    Replay mutation chain for a host — generates replay bundle.
    Returns summary of replayed events.
    """
    chain = get_chain_for_ip(ip)
    if not chain:
        return {"ip": ip, "events": 0, "status": "no chain found"}

    replay_dir = VAULT_DIR / "replays" / ip.replace(".", "_")
    replay_dir.mkdir(parents=True, exist_ok=True)

    replayed = []
    for entry in chain:
        ts = entry["ts"].replace(":", "").replace("-", "").replace("T", "_")[:15]
        mutation_id = entry.get("child_hash", "unknown")
        payload_name = entry.get("payload_name", "unknown")

        # Write replay shell
        pfile = replay_dir / f"replay_{ts}.sh"
        pfile.write_text(
            f"#!/bin/bash\n"
            f"# Replay: {mutation_id} on {ip}\n"
            f"# Payload: {payload_name}\n"
            f"# Timestamp: {entry['ts']}\n"
            f"echo 'Replaying mutation {mutation_id} for {ip}'\n"
        )

        # Write HTML flyer
        flyer = replay_dir / f"flyer_{ts}.html"
        flyer.write_text(
            f"<html><body style='background:#0a0a0a;color:#39ff14;font-family:monospace'>"
            f"<h2>Replay: {ip}</h2>"
            f"<p>Mutation: <code>{mutation_id}</code></p>"
            f"<p>Payload: <code>{payload_name}</code></p>"
            f"<p>XOR Key: <code>{entry.get('xor_key', 'n/a')}</code></p>"
            f"<p>Timestamp: {entry['ts']}</p>"
            f"</body></html>"
        )
        replayed.append({"mutation_id": mutation_id, "ts": entry["ts"], "payload": payload_name})

    # Bundle into zip
    ts_now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    bundle = VAULT_DIR / "replays" / f"replay_{ip.replace('.', '_')}_{ts_now}.zip"
    with zipfile.ZipFile(str(bundle), "w", zipfile.ZIP_DEFLATED) as z:
        for f in replay_dir.glob("*"):
            z.write(str(f), arcname=f.name)

    print(f"[✓] Replay bundle: {bundle.name} ({len(replayed)} events)")
    return {
        "ip": ip,
        "events": len(replayed),
        "bundle": str(bundle),
        "chain": replayed,
    }


def full_chain_summary() -> List[Dict[str, Any]]:
    """Return chain summary grouped by IP."""
    try:
        c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        c.row_factory = sqlite3.Row
        rows = c.execute("""
            SELECT ip,
                   COUNT(*) as mutations,
                   MIN(ts) as first_seen,
                   MAX(ts) as last_seen
            FROM mutation_chain
            GROUP BY ip
            ORDER BY mutations DESC
        """).fetchall()
        c.close()
        return [dict(r) for r in rows]
    except Exception:
        return []
