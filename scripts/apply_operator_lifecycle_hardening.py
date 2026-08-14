from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "core" / "nexus_api.py"
UI = ROOT / "ui" / "lanimals_live_map.html"
CAPS = ROOT / "capabilities.json"
TEST = ROOT / "tests" / "test_operator_lifecycle.py"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, replacement: str, label: str) -> str:
    rendered, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one regex match, found {count}")
    return rendered


api = API.read_text(encoding="utf-8")

api = replace_once(
    api,
    'return {"ok": True, "service": "lanimals-nexus", "version": VERSION}',
    'return {"ok": True, "service": "lanimals", "product": "LANimals", "version": VERSION}',
    "canonical health identity",
)

reports_block = '''@app.get("/api/reports")
def get_reports():
    REPORTS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = []
    for path in sorted(
        REPORTS_DIR.glob("report_*.html"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    ):
        if not path.is_file() or path.is_symlink():
            continue
        stat = path.stat()
        files.append({
            "name": path.name,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "url": f"/api/reports/{path.name}",
        })
    return {"reports": files[:20]}


def _safe_report_name(value: str) -> str:
    name = Path(value).name
    if name != value or not name.startswith("report_") or not name.endswith(".html"):
        raise HTTPException(status_code=400, detail="invalid report name")
    if not re.fullmatch(r"report_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}_[0-9]{6}\\.html", name):
        raise HTTPException(status_code=400, detail="invalid report name")
    return name


@app.get("/api/reports/{name}")
def get_report(name: str):
    safe_name = _safe_report_name(name)
    path = REPORTS_DIR / safe_name
    if not path.is_file() or path.is_symlink():
        raise HTTPException(status_code=404, detail="report not found")
    return FileResponse(path, media_type="text/html", filename=safe_name)
'''

api = regex_once(
    api,
    r'@app\.get\("/api/reports"\)\ndef get_reports\(\):.*?(?=\n@app\.get\("/api/logs"\))',
    reports_block.rstrip(),
    "report history routes",
)

export_block = '''@app.get("/api/export/report")
def export_report():
    """Generate, persist, and return a local HTML operator report."""
    from fastapi.responses import HTMLResponse
    from html import escape as html_escape

    hosts = get_all_hosts()
    events = get_recent_events(limit=100)
    stats = get_db_stats()
    now = _now_iso()

    def h(value: Any) -> str:
        return html_escape(str(value if value is not None else ""), quote=True)

    rows = ""
    for host in sorted(hosts, key=lambda item: item.get("ip") or ""):
        services = get_services_for_ip(host["ip"])
        svc_str = ", ".join(
            f"{service.get('service_name') or 'service'}:{service.get('port') or '?'}"
            for service in services
        ) or "—"
        status = str(host.get("status") or "normal")
        status_color = "#ff4455" if status == "critical" else "#c97b00" if status == "warning" else "#2a9d4e"
        rows += f"""<tr>
            <td>{h(host.get("ip"))}</td>
            <td>{h(host.get("hostname"))}</td>
            <td>{h(host.get("mac") or "—")}</td>
            <td>{h(host.get("vendor") or "—")}</td>
            <td style="color:{status_color}">{h(status)}</td>
            <td>{h(host.get("risk_score", 0))}</td>
            <td style="font-size:11px">{h(svc_str)}</td>
            <td>{h(host.get("last_seen") or "—")}</td>
        </tr>"""

    event_rows = ""
    for event in events[:50]:
        severity = str(event.get("severity") or "info")
        sev_color = "#ff4455" if severity in ("critical", "high") else "#c97b00" if severity == "warning" else "#3b7ecf"
        event_rows += f"""<tr>
            <td style="color:{sev_color}">{h(severity.upper())}</td>
            <td>{h(event.get("ts"))}</td>
            <td>{h(event.get("title"))}</td>
            <td>{h(event.get("summary"))}</td>
            <td>{h(event.get("ip") or "—")}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<title>LANimals Report — {h(now)}</title>
<style>
  body{{font-family:'JetBrains Mono',monospace;background:#0b0b0d;color:#f0f1f3;padding:32px;}}
  h1{{color:#d61f2c;font-size:28px;margin-bottom:4px;}}
  h2{{color:#7a8090;font-size:13px;font-weight:400;margin-bottom:32px;}}
  h3{{color:#d61f2c;font-size:14px;text-transform:uppercase;letter-spacing:.1em;margin:32px 0 12px;}}
  table{{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:32px;}}
  th{{background:#17171d;color:#7a8090;text-align:left;padding:8px 10px;border-bottom:1px solid #252530;font-size:10px;text-transform:uppercase;letter-spacing:.08em;}}
  td{{padding:7px 10px;border-bottom:1px solid #17171d;}}
  tr:hover td{{background:#111115;}}
  .stat{{display:inline-block;background:#111115;border:1px solid #252530;border-radius:6px;padding:12px 20px;margin:0 8px 8px 0;}}
  .sv{{font-size:28px;font-weight:800;color:#d61f2c;}}
  .sl{{font-size:10px;color:#7a8090;text-transform:uppercase;}}
  .footer{{color:#7a8090;font-size:10px;margin-top:48px;}}
</style>
</head><body>
<h1>LANimals</h1>
<h2>Network Intelligence Report — Generated {h(now)}</h2>
<div>
  <div class="stat"><div class="sv">{h(stats["hosts"])}</div><div class="sl">Hosts</div></div>
  <div class="stat"><div class="sv">{h(stats["services"])}</div><div class="sl">Services</div></div>
  <div class="stat"><div class="sv" style="color:#c97b00">{h(stats["warnings"])}</div><div class="sl">Warnings</div></div>
  <div class="stat"><div class="sv">{h(stats["baseline_entries"])}</div><div class="sl">Baseline</div></div>
  <div class="stat"><div class="sv">{h(stats["events"])}</div><div class="sl">Events</div></div>
</div>
<h3>Host Inventory</h3>
<table><thead><tr>
  <th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th>
  <th>Status</th><th>Risk</th><th>Services</th><th>Last Seen</th>
</tr></thead><tbody>{rows}</tbody></table>
<h3>Recent Events</h3>
<table><thead><tr>
  <th>Severity</th><th>Timestamp</th><th>Event</th><th>Summary</th><th>IP</th>
</tr></thead><tbody>{event_rows}</tbody></table>
<div class="footer">LANimals v{h(VERSION)} — badBANANA/LANimals</div>
</body></html>"""

    REPORTS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    filename = datetime.now(timezone.utc).strftime("report_%Y-%m-%d_%H-%M-%S_%f.html")
    report_path = REPORTS_DIR / filename
    report_path.write_text(html, encoding="utf-8")
    report_path.chmod(0o600)

    return HTMLResponse(
        content=html,
        headers={"X-LANimals-Report": filename, "Cache-Control": "no-store"},
    )
'''

api = regex_once(
    api,
    r'@app\.get\("/api/export/report"\)\ndef export_report\(\):.*?\n\s*return HTMLResponse\(content=html\)',
    export_block.rstrip(),
    "safe persisted HTML report",
)

cve_helpers = '''def _parse_cvss(value: Any) -> Optional[float]:
    try:
        score = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def _cve_severity(value: Any) -> str:
    score = _parse_cvss(value)
    if score is None:
        return "warning"
    if score >= 7.0:
        return "critical"
    if score >= 4.0:
        return "warning"
    return "info"


'''
api = replace_once(
    api,
    'def _run_cve_scan(jid: str, ip: str) -> None:\n',
    cve_helpers + 'def _run_cve_scan(jid: str, ip: str) -> None:\n',
    "CVSS helper insertion",
)
api = regex_once(
    api,
    r'"severity": "critical" if float\(cve\["score"\]\) >= 7\.0 else "warning"\s+if float\(cve\["score"\]\) >= 4\.0 else "info"\s+if cve\["score"\] != "\?" else "warning",',
    '"severity": _cve_severity(cve.get("score")),',
    "unknown CVSS severity handling",
)

API.write_text(api, encoding="utf-8")

ui = UI.read_text(encoding="utf-8")
ui = replace_once(
    ui,
    "    recs.push({pri:'low',text:`${noServices.length} host(s) without service data — scan services`,action:()=>{}});",
    "    recs.push({pri:'low',text:`${noServices.length} host(s) without service data — inspect first host`,action:()=>selectIpOnGraph(noServices[0].ip)});",
    "service recommendation action",
)
ui = replace_once(
    ui,
    "setInterval(()=>apiPost('/api/scan/arp').catch(()=>{}),300000);\n",
    "",
    "remove autonomous ARP collection",
)

render_reports = '''function renderReports(reports){
  const wrap=$('reportsList');
  wrap.innerHTML='';
  if(!reports.length){ wrap.innerHTML='<div class="log-line muted">No reports generated in this operator data directory.</div>'; return; }
  reports.forEach(r=>{
    const d=document.createElement('div');
    d.className='log-line';
    d.style.cursor='pointer';
    d.setAttribute('role','button');
    d.tabIndex=0;
    d.textContent=`${r.name}  ${(r.size/1024).toFixed(1)}kb  ${new Date(r.modified*1000).toLocaleString()}`;
    const open=()=>window.open(r.url||('/api/reports/'+encodeURIComponent(r.name)),'_blank','noopener');
    d.onclick=open;
    d.onkeydown=e=>{ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); open(); } };
    wrap.appendChild(d);
  });
}
'''
ui = regex_once(
    ui,
    r'function renderReports\(reports\)\{.*?\n\}\n\n// ── Render Sysinfo',
    render_reports.rstrip() + "\n\n// ── Render Sysinfo",
    "actionable report history UI",
)
UI.write_text(ui, encoding="utf-8")

caps = json.loads(CAPS.read_text(encoding="utf-8"))
for capability in caps["capabilities"]:
    if capability["id"] == "evidence-export":
        capability["routes"] = [
            "/api/export/report",
            "/api/reports",
            "/api/reports/{name}",
        ]
        evidence = capability.setdefault("evidence", [])
        if "tests/test_operator_lifecycle.py" not in evidence:
            evidence.append("tests/test_operator_lifecycle.py")
        break
else:
    raise SystemExit("evidence-export capability missing")
CAPS.write_text(json.dumps(caps, indent=2) + "\n", encoding="utf-8")

TEST.write_text(r'''from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["LANIMALS_ALLOWED_CIDRS"] = "192.168.50.0/24"
os.environ["LANIMALS_MAX_SCAN_ADDRESSES"] = "256"

from fastapi.testclient import TestClient

from core import nexus_db
from core import nexus_api
from core.nexus_api import app


class OperatorLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.db_patch = patch.object(nexus_db, "DB_PATH", root / "lanimals.db")
        self.reports_patch = patch.object(nexus_api, "REPORTS_DIR", root / "reports")
        self.db_patch.start()
        self.reports_patch.start()
        nexus_db.init_db()

    def tearDown(self) -> None:
        self.reports_patch.stop()
        self.db_patch.stop()
        self.tempdir.cleanup()

    def test_report_escapes_untrusted_network_and_event_strings_and_persists(self) -> None:
        nexus_db.upsert_host({
            "ip": "192.168.50.10",
            "hostname": "<script>alert(1)</script>",
            "mac": "AA:BB:CC:DD:EE:10",
            "vendor": 'Bad & <img src=x onerror="alert(2)">',
        })
        nexus_db.insert_events([{
            "id": "evt:xss",
            "ts": "2026-08-14T22:00:00Z",
            "severity": "warning",
            "title": "<script>event()</script>",
            "summary": 'quote=" & <img onerror=boom>',
            "ip": "192.168.50.10",
        }])

        response = self.client.get("/api/export/report")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("<script>alert(1)</script>", response.text)
        self.assertNotIn("<script>event()</script>", response.text)
        self.assertNotIn("<img src=x", response.text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", response.text)
        self.assertIn("Bad &amp; &lt;img", response.text)

        name = response.headers.get("X-LANimals-Report")
        self.assertTrue(name and name.startswith("report_") and name.endswith(".html"))

        listing = self.client.get("/api/reports")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["reports"][0]["name"], name)
        stored = self.client.get(f"/api/reports/{name}")
        self.assertEqual(stored.status_code, 200)
        self.assertEqual(stored.text, response.text)

    def test_report_name_validation_is_fail_closed(self) -> None:
        response = self.client.get("/api/reports/not-a-report.html")
        self.assertEqual(response.status_code, 400)

    def test_unknown_cvss_is_stable_warning(self) -> None:
        self.assertIsNone(nexus_api._parse_cvss("?"))
        self.assertEqual(nexus_api._cve_severity("?"), "warning")
        self.assertEqual(nexus_api._cve_severity("9.8"), "critical")
        self.assertEqual(nexus_api._cve_severity("5.0"), "warning")
        self.assertEqual(nexus_api._cve_severity("2.0"), "info")

    def test_health_uses_canonical_product_identity(self) -> None:
        payload = self.client.get("/api/health").json()
        self.assertEqual(payload["service"], "lanimals")
        self.assertEqual(payload["product"], "LANimals")

    def test_ui_never_starts_collection_on_page_open(self) -> None:
        ui = (Path(__file__).resolve().parents[1] / "ui" / "lanimals_live_map.html").read_text(encoding="utf-8")
        self.assertNotIn("setInterval(()=>apiPost('/api/scan/arp')", ui)
        self.assertNotIn("without service data — scan services`,action:()=>{}", ui)
        self.assertIn("without service data — inspect first host", ui)
        self.assertIn("window.open(r.url", ui)


if __name__ == "__main__":
    unittest.main()
''', encoding="utf-8")

print("operator lifecycle hardening patch applied successfully")
