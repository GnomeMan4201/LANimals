#!/usr/bin/env python3
"""
modules/phantom_intel.py
PHANTOM Intel module for LANimals.
"""
import sys, os, json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

def _find_phantom():
    for c in [
        os.path.expanduser("~/repos/PHANTOM"),
        os.path.expanduser("~/PHANTOM"),
        os.path.join(os.path.dirname(__file__), "..", "..", "PHANTOM"),
    ]:
        if os.path.isdir(c) and os.path.exists(os.path.join(c, "phantom", "__init__.py")):
            return os.path.abspath(c)
    return None

_phantom_path = _find_phantom()
if _phantom_path:
    sys.path.insert(0, _phantom_path)
    try:
        from phantom import PhantomEngine
        PHANTOM_AVAILABLE = True
    except ImportError:
        PHANTOM_AVAILABLE = False
else:
    PHANTOM_AVAILABLE = False

LOOT_PATH = Path.home() / ".lanimals" / "data" / "loot.log"

def _append_loot(entry):
    LOOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOOT_PATH, "a") as f:
        f.write(entry + "\n")

def _p(msg, style=""):
    if RICH: console.print(msg, style=style)
    else: print(msg)

def _show_topology(t):
    if RICH:
        tbl = Table(title="[bold red]DECEPTION TOPOLOGY[/bold red]", show_lines=True, box=None)
        tbl.add_column("Field", style="cyan")
        tbl.add_column("Value", style="white")
        tbl.add_row("Host", t.host)
        tbl.add_row("Strategy", f"[yellow]{t.strategy.value}[/yellow]")
        tbl.add_row("Threat Level", f"[red]{t.threat_level}[/red]")
        tbl.add_row("Scanned", str(t.total_scanned))
        tbl.add_row("Real / Fake", f"[green]{t.real_count}[/green] / [red]{t.fake_count}[/red]")
        tbl.add_row("Fake Ratio", f"{t.fake_ratio:.0%}")
        tbl.add_row("Dominant Platform", t.dominant_platform.value)
        if t.avg_response_ms:
            tp = " [red][TARPIT][/red]" if t.tarpit_suspected else ""
            tbl.add_row("Avg Response", f"{t.avg_response_ms:.0f}ms{tp}")
        console.print(tbl)
    else:
        print(f"  Strategy    : {t.strategy.value}")
        print(f"  Threat      : {t.threat_level}")
        print(f"  Real / Fake : {t.real_count} / {t.fake_count} ({t.fake_ratio:.0%})")

def _show_classifications(classifications):
    if not classifications:
        _p("  No fake ports classified.", "dim")
        return
    if RICH:
        tbl = Table(title="[bold red]HONEYPOT CLASSIFICATIONS[/bold red]", show_lines=True, box=None)
        tbl.add_column("Port", style="cyan")
        tbl.add_column("Platform", style="yellow")
        tbl.add_column("Conf", style="white")
        tbl.add_column("Signature", style="dim")
        tbl.add_column("Risk", style="red")
        for c in sorted(classifications, key=lambda x: x.port):
            col = "red" if c.confidence >= 0.70 else "yellow"
            tbl.add_row(str(c.port), c.platform.value,
                f"[{col}]{c.confidence:.0%}[/{col}]",
                c.matched_signature, c.risk_label)
        console.print(tbl)
    else:
        for c in sorted(classifications, key=lambda x: x.port):
            print(f"  port {c.port} — {c.platform.value} ({c.confidence:.0%}) [{c.risk_label}]")

def _show_playbook(p):
    if RICH:
        tbl = Table(title="[bold red]COUNTER-DECEPTION PLAYBOOK[/bold red]", show_lines=True, box=None)
        tbl.add_column("Field", style="cyan")
        tbl.add_column("Value", style="white")
        tbl.add_row("Approach", p.approach)
        tbl.add_row("Prioritize", str(p.prioritize_ports or "none confirmed"))
        avoid = str(p.avoid_ports[:15])
        if len(p.avoid_ports) > 15: avoid += f" +{len(p.avoid_ports)-15} more"
        tbl.add_row("Avoid", avoid)
        tbl.add_row("Canary Risk", str(p.canary_risk_ports or "none"))
        tbl.add_row("LANimals Risk", f"[bold]{p.lanimals_risk_score:.2f}[/bold]")
        tbl.add_row("Tags", ", ".join(p.lanimals_tags))
        console.print(tbl)
        for n in p.operator_notes:
            console.print(f"  [yellow]⚠[/yellow]  {n}")
    else:
        print(f"  Prioritize : {p.prioritize_ports}")
        print(f"  Avoid      : {p.avoid_ports[:10]}")
        print(f"  Risk Score : {p.lanimals_risk_score:.2f}")

def analyze(target, scan_file=None):
    if not PHANTOM_AVAILABLE:
        _p(f"[!] PHANTOM not found. Expected: {_phantom_path or '~/repos/PHANTOM'}", "bold red")
        return None
    engine = PhantomEngine()
    if not scan_file:
        _p("[!] Provide --scan-file with Decoy-Hunter output.", "yellow")
        return None
    try:
        raw = Path(scan_file).read_text()
    except FileNotFoundError:
        _p(f"[!] File not found: {scan_file}", "bold red")
        return None
    results = PhantomEngine.parse_decoy_hunter_output(raw, target)
    if not results:
        _p("[!] No [REAL]/[FAKE] lines in scan file.", "bold red")
        return None
    return engine.analyze(target, results)

def run():
    import argparse
    parser = argparse.ArgumentParser(prog="lanimals_phantomintel")
    parser.add_argument("target", nargs="?")
    parser.add_argument("--scan-file", "-f")
    parser.add_argument("--json", action="store_true")
    args, _ = parser.parse_known_args()

    if RICH:
        console.print(Rule("[bold red]PHANTOM INTEL[/bold red]"))
        console.print(Panel(
            "[bold]Deception Intelligence Layer[/bold]\n"
            "Honeypot fingerprinting · Topology mapping · Counter-playbook",
            style="red"))
    else:
        print("\n=== PHANTOM INTEL ===")

    if not args.target:
        _p("[!] Usage: lanimals_phantomintel <target> --scan-file <file>", "bold red")
        return

    report = analyze(args.target, args.scan_file)
    if not report: return

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return

    _show_topology(report.topology)
    _show_classifications(report.classifications)
    _show_playbook(report.playbook)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (f"[{ts}] [PHANTOM] host={report.host} "
             f"strategy={report.topology.strategy.value!r} "
             f"risk={report.playbook.lanimals_risk_score:.2f} "
             f"real={report.playbook.prioritize_ports} "
             f"tags={report.playbook.lanimals_tags}")
    _append_loot(entry)
    _p(f"\n[✓] Logged to {LOOT_PATH}", "green")
    _p(f"[✓] LANimals risk score: {report.playbook.lanimals_risk_score:.2f}", "green")

if __name__ == "__main__":
    run()
