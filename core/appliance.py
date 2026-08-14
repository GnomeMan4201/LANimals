from __future__ import annotations

import argparse
import fcntl
import importlib.util
import ipaddress
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import webbrowser
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_MAX_SCAN_ADDRESSES = 4096


class ApplianceError(RuntimeError):
    """Raised when the local appliance cannot safely complete an operation."""


def _xdg_dir(environment_name: str, fallback: Path) -> Path:
    value = os.environ.get(environment_name, "").strip()
    return Path(value).expanduser() if value else fallback


def config_dir() -> Path:
    explicit = os.environ.get("LANIMALS_CONFIG_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    return _xdg_dir("XDG_CONFIG_HOME", Path.home() / ".config") / "lanimals"


def data_dir() -> Path:
    explicit = os.environ.get("LANIMALS_DATA_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    return _xdg_dir("XDG_DATA_HOME", Path.home() / ".local" / "share") / "lanimals"


def cache_dir() -> Path:
    explicit = os.environ.get("LANIMALS_CACHE_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    return _xdg_dir("XDG_CACHE_HOME", Path.home() / ".cache") / "lanimals"


def state_dir() -> Path:
    explicit = os.environ.get("LANIMALS_STATE_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    return _xdg_dir("XDG_STATE_HOME", Path.home() / ".local" / "state") / "lanimals"


def config_path() -> Path:
    return config_dir() / "config.json"


def pid_path() -> Path:
    return state_dir() / "lanimals.pid"


def log_path() -> Path:
    return state_dir() / "lanimals.log"


def lock_path() -> Path:
    return state_dir() / "lanimals.lock"


def _ensure_directories() -> None:
    for path in (config_dir(), data_dir(), cache_dir(), state_dir()):
        if path.exists() and path.is_symlink():
            raise ApplianceError(f"refusing symlinked LANimals directory: {path}")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)


def _atomic_write(path: Path, value: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


@contextmanager
def _controller_lock():
    _ensure_directories()
    with lock_path().open("a+", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _read_config() -> dict[str, Any]:
    path = config_path()
    if not path.exists():
        return {}
    if path.is_symlink():
        raise ApplianceError(f"refusing symlinked configuration: {path}")
    if path.stat().st_size > 64 * 1024:
        raise ApplianceError(f"configuration is unexpectedly large: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ApplianceError(f"cannot read configuration: {path}") from exc
    if not isinstance(value, dict):
        raise ApplianceError("configuration root must be a JSON object")
    if value and value.get("schema_version") != 1:
        raise ApplianceError("unsupported LANimals configuration schema")
    return value


def _write_config(value: dict[str, Any]) -> None:
    _ensure_directories()
    path = config_path()
    if path.exists() and path.is_symlink():
        raise ApplianceError(f"refusing symlinked configuration: {path}")
    _atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _rfc1918_networks() -> tuple[ipaddress.IPv4Network, ...]:
    return (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )


def validate_approved_cidr(value: str, max_addresses: int) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ApplianceError(f"invalid IPv4 CIDR: {value}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ApplianceError("LANimals currently supports IPv4 LAN scopes only")
    if not any(network.subnet_of(parent) for parent in _rfc1918_networks()):
        raise ApplianceError("approved scope must be inside an RFC1918 private network")
    if network.num_addresses > max_addresses:
        raise ApplianceError(
            f"scope contains {network.num_addresses} addresses; limit is {max_addresses}"
        )
    return str(network)


def _configured_scope() -> tuple[str, int]:
    config = _read_config()
    max_addresses = int(
        os.environ.get(
            "LANIMALS_MAX_SCAN_ADDRESSES",
            config.get("max_scan_addresses", DEFAULT_MAX_SCAN_ADDRESSES),
        )
    )
    if max_addresses < 1 or max_addresses > 65536:
        raise ApplianceError("max scan addresses must be between 1 and 65536")
    raw = os.environ.get("LANIMALS_ALLOWED_CIDRS", "").strip()
    if not raw:
        configured = config.get("allowed_cidrs", [])
        if not isinstance(configured, list) or not all(
            isinstance(item, str) for item in configured
        ):
            raise ApplianceError("configured allowed_cidrs must be a list of strings")
        raw = ",".join(configured)
    if not raw:
        raise ApplianceError(
            "no approved LAN scope; run 'lanimals setup <private-CIDR>' first"
        )
    rendered = [
        validate_approved_cidr(item.strip(), max_addresses)
        for item in raw.split(",")
        if item.strip()
    ]
    if not rendered:
        raise ApplianceError("approved LAN scope is empty")
    return ",".join(rendered), max_addresses


def _detected_candidates() -> list[str]:
    from core.nexus_scope import detected_local_networks

    candidates = []
    for network in detected_local_networks():
        if network.num_addresses <= DEFAULT_MAX_SCAN_ADDRESSES:
            candidates.append(str(network))
    return candidates


def setup_scope(cidr: str | None) -> int:
    selected = cidr
    if not selected:
        candidates = _detected_candidates()
        if not candidates:
            raise ApplianceError(
                "no eligible private LAN was detected; provide one explicitly"
            )
        selected = candidates[0]
        if not sys.stdin.isatty():
            raise ApplianceError(
                f"detected {selected}, but approval requires an interactive terminal or "
                f"'lanimals setup {selected}'"
            )
        answer = input(f"Approve {selected} as the LANimals scan boundary? [y/N] ").strip()
        if answer.lower() not in {"y", "yes"}:
            raise ApplianceError("scope approval cancelled")
    approved = validate_approved_cidr(selected, DEFAULT_MAX_SCAN_ADDRESSES)
    value = _read_config()
    value.update(
        {
            "schema_version": 1,
            "allowed_cidrs": [approved],
            "max_scan_addresses": DEFAULT_MAX_SCAN_ADDRESSES,
        }
    )
    _write_config(value)
    print(f"[ OK ] Approved LAN scope: {approved}")
    print(f"[ OK ] Configuration: {config_path()}")
    return 0


def _port() -> int:
    try:
        value = int(os.environ.get("LANIMALS_PORT", str(DEFAULT_PORT)))
    except ValueError as exc:
        raise ApplianceError("LANIMALS_PORT must be an integer") from exc
    if value < 1 or value > 65535:
        raise ApplianceError("LANIMALS_PORT must be between 1 and 65535")
    return value


def _host() -> str:
    value = os.environ.get("LANIMALS_HOST", DEFAULT_HOST).strip()
    if value not in {"127.0.0.1", "::1"} and os.environ.get(
        "LANIMALS_ALLOW_REMOTE", "0"
    ) != "1":
        raise ApplianceError("refusing non-loopback bind without LANIMALS_ALLOW_REMOTE=1")
    return value


def _url() -> str:
    host = _host()
    rendered = f"[{host}]" if ":" in host else host
    return f"http://{rendered}:{_port()}"


def _health(url: str, timeout: float = 0.7) -> bool:
    try:
        with urllib.request.urlopen(f"{url}/api/health", timeout=timeout) as response:
            payload = json.loads(response.read())
        return response.status == 200 and payload.get("ok") is True
    except (OSError, ValueError, urllib.error.URLError):
        return False


def _read_pid() -> int | None:
    try:
        raw = pid_path().read_text(encoding="ascii").strip()
    except OSError:
        return None
    return int(raw) if raw.isdigit() else None


def _is_lanimals_process(pid: int) -> bool:
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ")
    except OSError:
        return False
    return b"uvicorn" in command and b"core.nexus_api:app" in command


def _write_pid(pid: int) -> None:
    _atomic_write(pid_path(), f"{pid}\n")


def _runtime_environment() -> dict[str, str]:
    scope, max_addresses = _configured_scope()
    _ensure_directories()
    environment = os.environ.copy()
    environment.update(
        {
            "LANIMALS_ALLOWED_CIDRS": scope,
            "LANIMALS_MAX_SCAN_ADDRESSES": str(max_addresses),
            "LANIMALS_DATA_DIR": str(data_dir()),
            "LANIMALS_CACHE_DIR": str(cache_dir()),
            "LANIMALS_STATE_DIR": str(state_dir()),
            "LANIMALS_CONFIG_DIR": str(config_dir()),
            "LANIMALS_REPORTS_DIR": str(data_dir() / "reports"),
        }
    )
    return environment


def _preflight_runtime() -> None:
    missing = [
        module
        for module in ("fastapi", "uvicorn", "scapy", "psutil")
        if importlib.util.find_spec(module) is None
    ]
    if missing:
        raise ApplianceError(
            "missing Python runtime modules: "
            + ", ".join(missing)
            + "; run './install.sh'"
        )
    if not shutil.which("ip"):
        raise ApplianceError("missing required 'ip' command; install iproute2")


def migrate_legacy_state() -> list[str]:
    """Copy checkout-relative v2.0 state into XDG storage without overwriting."""
    legacy_data = ROOT / "tmp"
    destination = data_dir()
    if not legacy_data.exists():
        return []
    _ensure_directories()
    migrated: list[str] = []
    old_database = legacy_data / "lanimals.db"
    new_database = destination / "lanimals.db"
    if old_database.is_file() and not new_database.exists():
        try:
            with (
                sqlite3.connect(f"file:{old_database}?mode=ro", uri=True) as source,
                sqlite3.connect(new_database) as destination_connection,
            ):
                source.backup(destination_connection)
        except Exception:
            new_database.unlink(missing_ok=True)
            raise
        new_database.chmod(0o600)
        migrated.append("lanimals.db")
    for name in (
        "network_snapshot.json",
        "nexus_state.json",
        "nexus_services.json",
        "nexus_traps.json",
    ):
        source = legacy_data / name
        target = destination / name
        if source.is_file() and not source.is_symlink() and not target.exists():
            try:
                value = json.loads(source.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ApplianceError(f"legacy state is invalid JSON: {source}") from exc
            _atomic_write(target, json.dumps(value, indent=2, sort_keys=True) + "\n")
            migrated.append(name)
    return migrated


def _start_locked(no_browser: bool = False) -> int:
    host = _host()
    port = _port()
    url = _url()
    environment = _runtime_environment()
    _preflight_runtime()
    existing = _read_pid()
    if existing and _is_lanimals_process(existing):
        if _health(url):
            print(f"[ OK ] LANimals is already running at {url} (pid {existing})")
            if not no_browser:
                webbrowser.open(url)
            return 0
        raise ApplianceError(
            f"LANimals process {existing} exists but is not healthy; run 'lanimals stop'"
        )
    if _health(url):
        raise ApplianceError(
            f"a LANimals-compatible service is already listening at {url}, but it is "
            "not owned by this appliance controller"
        )
    pid_path().unlink(missing_ok=True)
    migrated = migrate_legacy_state()
    if migrated:
        print(f"[ OK ] Preserved legacy state: {', '.join(migrated)}")
    with log_path().open("ab", buffering=0) as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "core.nexus_api:app",
                "--host",
                host,
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    _write_pid(process.pid)
    for _ in range(30):
        if process.poll() is not None:
            break
        if _health(url):
            print(f"[ OK ] LANimals local appliance: {url}")
            print(f"[ OK ] Approved scope: {environment['LANIMALS_ALLOWED_CIDRS']}")
            print(f"[ OK ] Local data: {data_dir()}")
            print(f"[ OK ] Process: {process.pid}")
            if not no_browser:
                webbrowser.open(url)
            return 0
        time.sleep(0.25)
    pid_path().unlink(missing_ok=True)
    if process.poll() is None:
        process.terminate()
    tail = ""
    try:
        tail = "\n".join(log_path().read_text(errors="replace").splitlines()[-12:])
    except OSError:
        pass
    raise ApplianceError(f"LANimals failed to start; log: {log_path()}\n{tail}")


def start(no_browser: bool = False) -> int:
    with _controller_lock():
        return _start_locked(no_browser=no_browser)


def _stop_locked() -> int:
    pid = _read_pid()
    if not pid:
        print("[ OK ] LANimals is not running")
        return 0
    if not _is_lanimals_process(pid):
        pid_path().unlink(missing_ok=True)
        print("[ OK ] Removed stale LANimals process record")
        return 0
    os.kill(pid, signal.SIGTERM)
    for _ in range(30):
        if not Path(f"/proc/{pid}").exists():
            pid_path().unlink(missing_ok=True)
            print("[ OK ] LANimals stopped")
            return 0
        time.sleep(0.1)
    raise ApplianceError(f"LANimals process {pid} did not stop cleanly")


def stop() -> int:
    with _controller_lock():
        return _stop_locked()


def status(as_json: bool = False) -> int:
    pid = _read_pid()
    process_ok = bool(pid and _is_lanimals_process(pid))
    healthy = process_ok and _health(_url())
    try:
        _configured_scope()
        configured = True
    except (ApplianceError, ValueError):
        configured = False
    payload = {
        "running": process_ok,
        "healthy": healthy,
        "pid": pid if process_ok else None,
        "url": _url(),
        "configured": configured,
    }
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    elif healthy:
        print(f"[ OK ] LANimals is healthy at {payload['url']} (pid {pid})")
    elif process_ok:
        print(f"[ WARN ] LANimals process {pid} is running but unhealthy")
    else:
        print("[ INFO ] LANimals is stopped")
    return 0 if healthy else 1


def open_console() -> int:
    if not _health(_url()):
        raise ApplianceError("LANimals is not healthy; run 'lanimals start'")
    if not webbrowser.open(_url()):
        print(f"Open {_url()} in your browser")
    return 0


def _doctor_checks() -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []

    def add(name: str, level: str, detail: str) -> None:
        checks.append({"name": name, "level": level, "detail": detail})

    add(
        "python",
        "pass" if sys.version_info >= (3, 10) else "fail",
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )
    for module in ("fastapi", "uvicorn", "scapy", "psutil"):
        add(
            f"module:{module}",
            "pass" if importlib.util.find_spec(module) else "fail",
            "available" if importlib.util.find_spec(module) else "missing",
        )
    for command, required in (("ip", True), ("nmap", False)):
        found = shutil.which(command)
        add(
            f"command:{command}",
            "pass" if found else ("fail" if required else "warn"),
            found or "missing",
        )
    try:
        scope, _ = _configured_scope()
        add("scope", "pass", scope)
    except ApplianceError as exc:
        add("scope", "fail", str(exc))
    try:
        _ensure_directories()
        probe = state_dir() / ".write-test"
        probe.write_text("ok", encoding="ascii")
        probe.unlink()
        add("local-state", "pass", str(data_dir()))
    except OSError as exc:
        add("local-state", "fail", str(exc))
    return checks


def doctor(as_json: bool = False) -> int:
    checks = _doctor_checks()
    if as_json:
        print(json.dumps({"checks": checks}, sort_keys=True))
    else:
        for check in checks:
            print(f"[{check['level'].upper():4s}] {check['name']}: {check['detail']}")
    return 1 if any(check["level"] == "fail" for check in checks) else 0


def show_config() -> int:
    value = _read_config()
    print(json.dumps({"path": str(config_path()), "config": value}, indent=2))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lanimals", add_help=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    start_parser = subparsers.add_parser("start")
    start_parser.add_argument("--no-browser", action="store_true")
    subparsers.add_parser("stop")
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--json", action="store_true")
    subparsers.add_parser("open")
    setup_parser = subparsers.add_parser("setup")
    setup_parser.add_argument("cidr", nargs="?")
    doctor_parser = subparsers.add_parser("doctor")
    doctor_parser.add_argument("--json", action="store_true")
    subparsers.add_parser("config")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "start":
            return start(no_browser=arguments.no_browser)
        if arguments.command == "stop":
            return stop()
        if arguments.command == "status":
            return status(as_json=arguments.json)
        if arguments.command == "open":
            return open_console()
        if arguments.command == "setup":
            return setup_scope(arguments.cidr)
        if arguments.command == "doctor":
            return doctor(as_json=arguments.json)
        if arguments.command == "config":
            return show_config()
    except (ApplianceError, OSError, ValueError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
