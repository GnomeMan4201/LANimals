from __future__ import annotations

"""
LANimals Trap Engine
====================
Deploys and manages honeypot listeners on the local machine.
Each trap is a fake service that logs every connection attempt.
All hits fire into the LANimals event system and update trap node risk.

Trap types:
  port    — raw TCP listener on a chosen port, logs banner grabs
  http    — fake HTTP service (login page, admin panel, etc.)
  multi   — deploys a preset bundle of traps (SSH, Telnet, FTP, RDP, MySQL)
"""

import json
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
TMP_DIR = ROOT / "tmp"
TMP_DIR.mkdir(exist_ok=True)
TRAPS_FILE = TMP_DIR / "nexus_traps.json"

# ── Fake service banners — what the trap presents to whoever connects ─────────
_BANNERS: Dict[str, bytes] = {
    "ssh":     b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    "ftp":     b"220 ProFTPD 1.3.5e Server (ProFTPD) [192.168.0.1]\r\n",
    "telnet":  b"\xff\xfd\x18\xff\xfd\x20\xff\xfd#\xff\xfd'\r\nLogin: ",
    "smtp":    b"220 mail.local ESMTP Postfix (Ubuntu)\r\n",
    "rdp":     b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x08\x00\x02\x00\x00\x00",
    "mysql":   b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x32\x00",
    "vnc":     b"RFB 003.008\n",
    "http":    b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><body><h1>It works!</h1></body></html>",
    "generic": b"220 Service ready\r\n",
}

# Fake HTTP login page served by HTTP traps
_HTTP_LOGIN_PAGE = b"""HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html><head><title>Network Admin</title>
<style>body{background:#1a1a1a;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:monospace;}
.box{background:#222;border:1px solid #444;padding:32px;width:300px;}
h2{color:#d61f2c;margin:0 0 20px;}
input{width:100%;background:#111;color:#eee;border:1px solid #444;padding:8px;margin-bottom:12px;box-sizing:border-box;}
button{width:100%;background:#d61f2c;color:#fff;border:none;padding:10px;cursor:pointer;}
</style></head><body><div class="box">
<h2>Network Admin</h2>
<input type="text" placeholder="Username" name="user"/>
<input type="password" placeholder="Password" name="pass"/>
<button type="submit">Login</button>
</div></body></html>"""

_HTTP_CAPTURE_RESPONSE = b"""HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n"""

# ── Trap state ────────────────────────────────────────────────────────────────
_ACTIVE_TRAPS: Dict[str, Dict[str, Any]] = {}
_TRAPS_LOCK = threading.Lock()


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _fire_event(trap_id: str, source_ip: str, source_port: int,
                data: str, trap_name: str, trap_port: int) -> None:
    """Write a trap hit into the LANimals event system."""
    try:
        from core.nexus_db import insert_event, upsert_host, get_mac_baseline
        from core.nexus_risk import _is_randomized_mac

        ts = _now()
        event_id = f"evt:trap:{trap_id}:{source_ip}:{ts}"

        insert_event({
            "id": event_id,
            "ts": ts,
            "severity": "critical",
            "title": f"TRAP HIT: {trap_name} on port {trap_port}",
            "summary": (
                f"Connection from {source_ip}:{source_port} — "
                f"{len(data)} bytes received"
                + (f" — data: {data[:80]!r}" if data else "")
            ),
            "node_id": f"trap:{trap_id}",
            "ip": source_ip,
        })

        # Upsert the attacker as a host with elevated risk
        from core.nexus_db import get_host as _get_host
        existing = _get_host(source_ip) or {}
        existing_meta: dict = {}
        try:
            existing_meta = json.loads(existing.get("meta") or "{}") if existing else {}
        except Exception:
            pass

        # Increment honeypot hit counter on this attacker
        prev_hits = int(existing_meta.get("honeypot_hits", 0))
        new_hits = prev_hits + 1

        upsert_host({
            "ip": source_ip,
            "hostname": existing.get("hostname") or source_ip,
            "mac": existing.get("mac"),
            "vendor": existing.get("vendor") or "",
            "status": "critical",
            "risk_score": min(95 + new_hits, 100),
            "group_cidr": _cidr_from_ip(source_ip),
            "honeypot_hits": new_hits,
            "meta": json.dumps({
                **existing_meta,
                "source": "trap_hit",
                "honeypot_hits": new_hits,
                "trap_id": trap_id,
                "trap_name": trap_name,
                "trap_port": trap_port,
                "risk_reasons": [
                    f"Honeypot interaction observed ({new_hits} hit{'s' if new_hits != 1 else ''})",
                    f"Triggered trap '{trap_name}' on port {trap_port}",
                    "No legitimate traffic should reach honeypot services",
                ],
            }),
        })
        # Trigger rescore so graph reflects immediately
        try:
            from core.nexus_risk import rescore_all_hosts as _rescore
            _rescore()
        except Exception:
            pass

    except Exception as e:
        print(f"[trap] event fire error: {e}")


def _cidr_from_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24"
    return "unknown"


# ── Trap hit logging ──────────────────────────────────────────────────────────
def _log_trap_hit(trap_id: str, source_ip: str, source_port: int,
                  data: bytes, trap_name: str, trap_port: int) -> None:
    decoded = ""
    try:
        decoded = data.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        pass

    hit = {
        "ts": _now(),
        "source_ip": source_ip,
        "source_port": source_port,
        "data": decoded,
        "trap_name": trap_name,
        "trap_port": trap_port,
    }

    with _TRAPS_LOCK:
        if trap_id in _ACTIVE_TRAPS:
            hits = _ACTIVE_TRAPS[trap_id].get("hits", [])
            hits.append(hit)
            _ACTIVE_TRAPS[trap_id]["hits"] = hits[-100:]  # keep last 100
            _ACTIVE_TRAPS[trap_id]["hit_count"] = _ACTIVE_TRAPS[trap_id].get("hit_count", 0) + 1
            _ACTIVE_TRAPS[trap_id]["last_hit"] = _now()

    _save_traps()
    _fire_event(trap_id, source_ip, source_port, decoded, trap_name, trap_port)
    print(f"[TRAP HIT] {trap_name}:{trap_port} ← {source_ip}:{source_port}  data={decoded[:40]!r}")


# ── TCP listener ──────────────────────────────────────────────────────────────
def _tcp_listener(trap_id: str, port: int, banner_key: str,
                  trap_name: str, stop_event: threading.Event) -> None:
    banner = _BANNERS.get(banner_key, _BANNERS["generic"])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)
    try:
        sock.bind(("0.0.0.0", port))
        sock.listen(10)
    except Exception as e:
        print(f"[trap] Failed to bind port {port}: {e}")
        with _TRAPS_LOCK:
            if trap_id in _ACTIVE_TRAPS:
                _ACTIVE_TRAPS[trap_id]["status"] = "error"
                _ACTIVE_TRAPS[trap_id]["error"] = str(e)
        return

    with _TRAPS_LOCK:
        if trap_id in _ACTIVE_TRAPS:
            _ACTIVE_TRAPS[trap_id]["status"] = "active"

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except Exception:
            break

        def handle(c: socket.socket, a: tuple) -> None:
            src_ip, src_port = a
            try:
                c.settimeout(5.0)
                try:
                    c.sendall(banner)
                except Exception:
                    pass
                try:
                    data = c.recv(4096)
                except Exception:
                    data = b""
                _log_trap_hit(trap_id, src_ip, src_port, data, trap_name, port)
            except Exception:
                pass
            finally:
                try:
                    c.close()
                except Exception:
                    pass

        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()

    sock.close()
    with _TRAPS_LOCK:
        if trap_id in _ACTIVE_TRAPS:
            _ACTIVE_TRAPS[trap_id]["status"] = "stopped"


# ── HTTP trap listener ────────────────────────────────────────────────────────
def _http_listener(trap_id: str, port: int,
                   trap_name: str, stop_event: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)
    try:
        sock.bind(("0.0.0.0", port))
        sock.listen(10)
    except Exception as e:
        print(f"[trap] Failed to bind HTTP port {port}: {e}")
        with _TRAPS_LOCK:
            if trap_id in _ACTIVE_TRAPS:
                _ACTIVE_TRAPS[trap_id]["status"] = "error"
                _ACTIVE_TRAPS[trap_id]["error"] = str(e)
        return

    with _TRAPS_LOCK:
        if trap_id in _ACTIVE_TRAPS:
            _ACTIVE_TRAPS[trap_id]["status"] = "active"

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except Exception:
            break

        def handle(c: socket.socket, a: tuple) -> None:
            src_ip, src_port = a
            try:
                c.settimeout(5.0)
                raw = b""
                try:
                    raw = c.recv(8192)
                except Exception:
                    pass

                decoded = raw.decode("utf-8", errors="replace")

                # Serve login page for GET, log credentials for POST
                if decoded.startswith("POST"):
                    c.sendall(_HTTP_CAPTURE_RESPONSE)
                    # Extract any body data (credentials)
                    body = decoded.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in decoded else ""
                    _log_trap_hit(trap_id, src_ip, src_port,
                                  f"POST body: {body[:200]}".encode(),
                                  trap_name, port)
                else:
                    c.sendall(_HTTP_LOGIN_PAGE)
                    _log_trap_hit(trap_id, src_ip, src_port,
                                  raw[:200], trap_name, port)
            except Exception:
                pass
            finally:
                try:
                    c.close()
                except Exception:
                    pass

        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()

    sock.close()


# ── Persistence ───────────────────────────────────────────────────────────────
def _save_traps() -> None:
    try:
        with _TRAPS_LOCK:
            serializable = {}
            for tid, trap in _ACTIVE_TRAPS.items():
                serializable[tid] = {k: v for k, v in trap.items()
                                     if k not in ("stop_event", "thread")}
        TRAPS_FILE.write_text(json.dumps(serializable, indent=2))
    except Exception as e:
        print(f"[trap] save error: {e}")


def _load_traps_state() -> Dict[str, Any]:
    try:
        if TRAPS_FILE.exists():
            return json.loads(TRAPS_FILE.read_text())
    except Exception:
        pass
    return {}


# ── Public API ────────────────────────────────────────────────────────────────
def deploy_trap(trap_type: str, port: int, name: str,
                banner_key: str = "generic") -> Dict[str, Any]:
    """Deploy a single trap. Returns trap info dict."""
    import uuid
    trap_id = str(uuid.uuid4())[:8]

    stop_event = threading.Event()
    trap_info = {
        "id": trap_id,
        "type": trap_type,
        "name": name,
        "port": port,
        "banner": banner_key,
        "status": "starting",
        "deployed_at": _now(),
        "hit_count": 0,
        "last_hit": None,
        "hits": [],
        "error": None,
    }

    with _TRAPS_LOCK:
        _ACTIVE_TRAPS[trap_id] = trap_info

    if trap_type == "http":
        t = threading.Thread(
            target=_http_listener,
            args=(trap_id, port, name, stop_event),
            daemon=True,
        )
    else:
        t = threading.Thread(
            target=_tcp_listener,
            args=(trap_id, port, banner_key, name, stop_event),
            daemon=True,
        )

    with _TRAPS_LOCK:
        _ACTIVE_TRAPS[trap_id]["stop_event"] = stop_event
        _ACTIVE_TRAPS[trap_id]["thread"] = t

    t.start()
    time.sleep(0.3)  # let it bind
    _save_traps()

    with _TRAPS_LOCK:
        return {k: v for k, v in _ACTIVE_TRAPS[trap_id].items()
                if k not in ("stop_event", "thread")}


def stop_trap(trap_id: str) -> bool:
    with _TRAPS_LOCK:
        trap = _ACTIVE_TRAPS.get(trap_id)
        if not trap:
            return False
        stop_event = trap.get("stop_event")
        if stop_event:
            stop_event.set()
        _ACTIVE_TRAPS[trap_id]["status"] = "stopped"

    _save_traps()
    return True


def get_all_traps() -> List[Dict[str, Any]]:
    with _TRAPS_LOCK:
        return [
            {k: v for k, v in t.items() if k not in ("stop_event", "thread")}
            for t in _ACTIVE_TRAPS.values()
        ]


def get_trap(trap_id: str) -> Optional[Dict[str, Any]]:
    with _TRAPS_LOCK:
        t = _ACTIVE_TRAPS.get(trap_id)
        if not t:
            return None
        return {k: v for k, v in t.items() if k not in ("stop_event", "thread")}


def get_trap_hits(trap_id: str) -> List[Dict[str, Any]]:
    with _TRAPS_LOCK:
        t = _ACTIVE_TRAPS.get(trap_id)
        return list(t.get("hits", [])) if t else []


def deploy_bundle(bundle_name: str = "default") -> List[Dict[str, Any]]:
    """Deploy a preset bundle of traps that look like real infrastructure."""
    bundles: Dict[str, List[Dict[str, Any]]] = {
        "default": [
            {"type": "port", "port": 2222, "name": "Fake SSH",    "banner": "ssh"},
            {"type": "port", "port": 2323, "name": "Fake Telnet", "banner": "telnet"},
            {"type": "port", "port": 2121, "name": "Fake FTP",    "banner": "ftp"},
            {"type": "http", "port": 8888, "name": "Fake Admin",  "banner": "http"},
            {"type": "port", "port": 3307, "name": "Fake MySQL",  "banner": "mysql"},
        ],
        "office": [
            {"type": "http", "port": 9090, "name": "Fake Router Admin", "banner": "http"},
            {"type": "port", "port": 3389, "name": "Fake RDP",          "banner": "rdp"},
            {"type": "port", "port": 5901, "name": "Fake VNC",          "banner": "vnc"},
            {"type": "http", "port": 8880, "name": "Fake NAS Login",    "banner": "http"},
        ],
        "minimal": [
            {"type": "http", "port": 8888, "name": "Fake Admin Panel", "banner": "http"},
            {"type": "port", "port": 2222, "name": "Fake SSH",         "banner": "ssh"},
        ],
    }

    configs = bundles.get(bundle_name, bundles["default"])
    deployed = []
    for cfg in configs:
        try:
            result = deploy_trap(
                trap_type=cfg["type"],
                port=cfg["port"],
                name=cfg["name"],
                banner_key=cfg.get("banner", "generic"),
            )
            deployed.append(result)
        except Exception as e:
            deployed.append({"error": str(e), "name": cfg["name"], "port": cfg["port"]})
    return deployed


def get_all_hits() -> List[Dict[str, Any]]:
    """All hits across all traps, sorted newest first."""
    all_hits = []
    with _TRAPS_LOCK:
        for trap in _ACTIVE_TRAPS.values():
            for hit in trap.get("hits", []):
                all_hits.append({**hit, "trap_id": trap["id"], "trap_name": trap["name"]})
    return sorted(all_hits, key=lambda h: h.get("ts", ""), reverse=True)
