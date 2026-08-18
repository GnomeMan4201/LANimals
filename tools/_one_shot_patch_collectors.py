from pathlib import Path

path = Path("core/nexus_collectors.py")
text = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str, label: str) -> None:
    global text
    matches = text.count(old)
    if matches != 1:
        raise SystemExit(f"unexpected source shape for {label}: {matches} matches")
    text = text.replace(old, new, 1)


replace_once(
    "TMP_DIR = CACHE_DIR\n\n",
    "TMP_DIR = CACHE_DIR\n\n\nclass CollectorError(RuntimeError):\n"
    "    \"\"\"Required collector execution failed; zero observations were not established.\"\"\"\n\n",
    "CollectorError insertion",
)

replace_once(
    '''def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return (result.stdout + "\\n" + result.stderr).strip()
    except Exception:
        return ""
''',
    '''def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise CollectorError(
            f"collector command timed out after {timeout}s: {' '.join(cmd)}"
        ) from exc
    except OSError as exc:
        raise CollectorError(
            f"collector command failed to start: {' '.join(cmd)}: {exc}"
        ) from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise CollectorError(
            f"collector command exited {result.returncode}: {' '.join(cmd)}{suffix}"
        )
    return (result.stdout + "\\n" + result.stderr).strip()
''',
    "_run",
)

replace_once(
    '''def collect_nmap_ping_sweep(cidr: str = "192.168.1.0/24") -> List[Dict[str, Any]]:
    cidr = validate_scan_cidr(cidr)
    if shutil.which("nmap") is None:
        return []
    xml_path = TMP_DIR / "nexus_ping_scan.xml"
    xml_path.unlink(missing_ok=True)
    _run(_nmap_cmd(["-sn", cidr, "-oX", str(xml_path)]), timeout=90)
    if not xml_path.exists():
        return []
    try:
        from xml.etree import ElementTree as ET
        root = ET.parse(xml_path).getroot()
    except Exception:
        return []
''',
    '''def collect_nmap_ping_sweep(cidr: str = "192.168.1.0/24") -> List[Dict[str, Any]]:
    cidr = validate_scan_cidr(cidr)
    if shutil.which("nmap") is None:
        raise CollectorError("required collector command unavailable: nmap")
    xml_path = TMP_DIR / "nexus_ping_scan.xml"
    xml_path.unlink(missing_ok=True)
    _run(_nmap_cmd(["-sn", cidr, "-oX", str(xml_path)]), timeout=90)
    if not xml_path.exists():
        raise CollectorError("nmap ping sweep completed without XML output")
    try:
        from xml.etree import ElementTree as ET
        root = ET.parse(xml_path).getroot()
    except Exception as exc:
        raise CollectorError(f"invalid nmap ping XML: {exc}") from exc
''',
    "nmap ping sweep",
)

replace_once(
    '''    uname = _run(["uname", "-a"])
    if uname:
        info["uname"] = uname
''',
    '''    try:
        uname = _run(["uname", "-a"])
    except CollectorError as exc:
        info["uname_error"] = str(exc)
    else:
        if uname:
            info["uname"] = uname
''',
    "optional uname",
)

replace_once(
    '''def collect_service_scan(targets: List[str]) -> List[Dict[str, Any]]:
    if shutil.which("nmap") is None:
        return []
''',
    '''def collect_service_scan(targets: List[str]) -> List[Dict[str, Any]]:
    if shutil.which("nmap") is None:
        raise CollectorError("required collector command unavailable: nmap")
''',
    "service scan nmap availability",
)

replace_once(
    '''def collect_services_for_ip(ip: str) -> List[Dict[str, Any]]:
    ip = validate_host_target(ip)
    if shutil.which("nmap") is None:
        return []
''',
    '''def collect_services_for_ip(ip: str) -> List[Dict[str, Any]]:
    ip = validate_host_target(ip)
    if shutil.which("nmap") is None:
        raise CollectorError("required collector command unavailable: nmap")
''',
    "targeted service scan nmap availability",
)

replace_once(
    '''def _parse_nmap_services(
    xml_path: Path, source: str = "nmap", filter_ip: str | None = None
) -> List[Dict[str, Any]]:
    if not xml_path.exists():
        return []
    try:
        from xml.etree import ElementTree as ET
        root = ET.parse(xml_path).getroot()
    except Exception:
        return []
''',
    '''def _parse_nmap_services(
    xml_path: Path, source: str = "nmap", filter_ip: str | None = None
) -> List[Dict[str, Any]]:
    if not xml_path.exists():
        raise CollectorError(f"nmap service scan completed without XML output: {xml_path}")
    try:
        from xml.etree import ElementTree as ET
        root = ET.parse(xml_path).getroot()
    except Exception as exc:
        raise CollectorError(f"invalid nmap service XML {xml_path}: {exc}") from exc
''',
    "service XML parser",
)

path.write_text(text, encoding="utf-8")
