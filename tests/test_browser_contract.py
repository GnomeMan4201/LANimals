from pathlib import Path

from core.nexus_terminal import TerminalCommandError, parse_terminal_command


ROOT = Path(__file__).resolve().parents[1]
UI = (ROOT / "ui" / "lanimals_live_map.html").read_text(encoding="utf-8")
API = (ROOT / "core" / "nexus_api.py").read_text(encoding="utf-8")
TERMINAL = (ROOT / "core" / "nexus_terminal.py").read_text(encoding="utf-8")


def test_visible_browser_actions_map_to_supported_runtime_routes():
    expected = [
        "/api/scan/discovery",
        "/api/scan/arp",
        "/api/scan/hostmap",
        "/api/scan/rogue",
        "/api/scan/anomaly",
        "/api/watchdog",
        "/api/diff",
        "/api/scan/rescore",
        "/api/export/report",
        "/api/traps",
    ]
    for route in expected:
        assert route in UI, route
        assert route in API, route

    assert "'/api/scan/arp?cidr='+encodeURIComponent(cidr())" in UI
    assert 'def scan_arp(cidr: Optional[str] = Query(default=None))' in API
    assert 'scan arp [CIDR]' in TERMINAL


def test_terminal_arp_accepts_only_optional_cidr_targets():
    default = parse_terminal_command("scan arp")
    explicit = parse_terminal_command("scan arp 192.168.50.0/24")
    assert (default.action, default.target) == ("scan:arp", None)
    assert (explicit.action, explicit.target) == ("scan:arp", "192.168.50.0/24")
    try:
        parse_terminal_command("scan arp 192.168.50.9")
    except TerminalCommandError:
        pass
    else:
        raise AssertionError("ARP terminal target accepted a host IP instead of a CIDR")


def test_browser_mutations_share_fail_closed_status_checking():
    assert "async function apiMutate(method,path,body)" in UI
    assert "async function apiPatch(path,body){ return apiMutate('PATCH',path,body); }" in UI
    assert "async function apiDelete(path){ return apiMutate('DELETE',path); }" in UI
    assert "await apiPatch('/api/hosts/'" in UI
    assert "await apiDelete('/api/traps/'" in UI
    assert "notesBtn.textContent='Saved';" in UI
    assert "notesBtn.textContent='Save failed';" in UI
    assert "await fetch('/api/hosts/'+encodeURIComponent(node.ip)+'/notes'" not in UI
    assert "await fetch('/api/traps/'+encodeURIComponent(trapId)" not in UI


def test_page_open_is_read_only_with_respect_to_network_collection_and_mutation():
    init = UI.split("// ── Init ─", 1)[1].split("</script>", 1)[0]
    init_before_intervals = init.split("setInterval(fetchGraph", 1)[0]
    assert "runOp(" not in init_before_intervals
    assert "apiPost(" not in init_before_intervals
    assert "apiPatch(" not in init_before_intervals
    assert "apiDelete(" not in init_before_intervals
    assert "fetchScope();" in init_before_intervals
    assert "fetchGraph();" in init_before_intervals
    assert "fetchStats();" in init_before_intervals


def test_major_inline_actions_surface_backend_errors():
    for label in ["anomaly scan", "watchdog", "network diff", "risk rescore", "trap deployment", "stop all traps", "note save"]:
        assert f"showActionError('{label}'" in UI


def test_trap_bundle_ui_distinguishes_partial_failure_from_success():
    assert "const failures=(d.deployed||[]).filter(t=>t.status==='error'||t.error);" in UI
    assert "setStatus('trap bundle partial','error');" in UI
    assert "d.failure_count??failures.length" in UI
