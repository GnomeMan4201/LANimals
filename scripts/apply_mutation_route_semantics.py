from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one occurrence, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# API: side-effecting operator actions must be mutations.
replace_once(
    "core/nexus_api.py",
    '@app.get("/api/export/report")\ndef export_report():',
    '@app.post("/api/export/report")\ndef export_report():',
)
replace_once(
    "core/nexus_api.py",
    '    from fastapi.responses import HTMLResponse\n    from html import escape as html_escape\n',
    '    from html import escape as html_escape\n',
)
replace_once(
    "core/nexus_api.py",
    '''    return HTMLResponse(\n        content=html,\n        headers={"X-LANimals-Report": filename, "Cache-Control": "no-store"},\n    )\n''',
    '''    return {\n        "ok": True,\n        "name": filename,\n        "url": f"/api/reports/{filename}",\n        "size": report_path.stat().st_size,\n        "generated_at": now,\n    }\n''',
)
replace_once(
    "core/nexus_api.py",
    '@app.get("/api/enrich/vt/{ip}")\ndef enrich_vt(ip: str):',
    '@app.post("/api/enrich/vt/{ip}")\ndef enrich_vt(ip: str):',
)

# Browser: both actions go through the fail-closed mutation helper.
replace_once(
    "ui/lanimals_live_map.html",
    "actions.push({label:'VirusTotal Lookup',icon:'⚡',why:'Check IP reputation',cls:'',fn:async()=>{ const d=await apiGet('/api/enrich/vt/'+encodeURIComponent(node.ip)); addScanLine(JSON.stringify(d),''); }});",
    "actions.push({label:'VirusTotal Lookup',icon:'⚡',why:'Check IP reputation',cls:'',fn:async()=>{ try{ const d=await apiPost('/api/enrich/vt/'+encodeURIComponent(node.ip)); addScanLine(JSON.stringify(d),''); }catch(e){ showActionError('VirusTotal lookup',e); } }});",
)
replace_once(
    "ui/lanimals_live_map.html",
    "$('btnReport').onclick=()=>window.open('/api/export/report','_blank');",
    """$('btnReport').onclick=async()=>{\n  const reportWin=window.open('about:blank','_blank');\n  try{\n    const d=await apiPost('/api/export/report');\n    if(!d?.url) throw new Error('Report export did not return a retrieval URL');\n    if(reportWin) reportWin.location=d.url; else window.location.href=d.url;\n  }catch(e){\n    if(reportWin) reportWin.close();\n    showActionError('report export',e);\n  }\n};""",
)

# Real fresh-install journey: create via POST, retrieve via GET.
replace_once(
    "scripts/smoke_operator_journey.sh",
    '''report_html, report_headers = request("GET", "/api/export/report")\nassert "LANimals" in report_html and TARGET in report_html and "8080" in report_html\nreport_name = report_headers.get("X-LANimals-Report")\nassert report_name and report_name.startswith("report_")\nreports, _ = request("GET", "/api/reports")\nassert any(item["name"] == report_name for item in reports["reports"]), reports\n''',
    '''report_result, _ = request("POST", "/api/export/report", payload={}, headers=HEADER)\nassert report_result["ok"] is True, report_result\nreport_name = report_result["name"]\nassert report_name.startswith("report_") and report_result["url"] == f"/api/reports/{report_name}"\nreport_html, _ = request("GET", report_result["url"])\nassert "LANimals" in report_html and TARGET in report_html and "8080" in report_html\nreports, _ = request("GET", "/api/reports")\nassert any(item["name"] == report_name for item in reports["reports"]), reports\n''',
)

# Operator lifecycle regression: POST creates, GET only retrieves.
replace_once(
    "tests/test_operator_lifecycle.py",
    '''        response = self.client.get("/api/export/report")\n        self.assertEqual(response.status_code, 200)\n        self.assertNotIn("<script>alert(1)</script>", response.text)\n        self.assertNotIn("<script>event()</script>", response.text)\n        self.assertNotIn("<img src=x", response.text)\n        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", response.text)\n        self.assertIn("Bad &amp; &lt;img", response.text)\n\n        name = response.headers.get("X-LANimals-Report")\n        self.assertTrue(name and name.startswith("report_") and name.endswith(".html"))\n\n        listing = self.client.get("/api/reports")\n        self.assertEqual(listing.status_code, 200)\n        self.assertEqual(listing.json()["reports"][0]["name"], name)\n        stored = self.client.get(f"/api/reports/{name}")\n        self.assertEqual(stored.status_code, 200)\n        self.assertEqual(stored.text, response.text)\n''',
    '''        response = self.client.post(\n            "/api/export/report",\n            headers={"X-LANimals-Operator": "1"},\n        )\n        self.assertEqual(response.status_code, 200)\n        result = response.json()\n        self.assertTrue(result["ok"])\n        name = result["name"]\n        self.assertTrue(name.startswith("report_") and name.endswith(".html"))\n        self.assertEqual(result["url"], f"/api/reports/{name}")\n\n        stored = self.client.get(result["url"])\n        self.assertEqual(stored.status_code, 200)\n        self.assertNotIn("<script>alert(1)</script>", stored.text)\n        self.assertNotIn("<script>event()</script>", stored.text)\n        self.assertNotIn("<img src=x", stored.text)\n        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", stored.text)\n        self.assertIn("Bad &amp; &lt;img", stored.text)\n\n        listing = self.client.get("/api/reports")\n        self.assertEqual(listing.status_code, 200)\n        self.assertEqual(listing.json()["reports"][0]["name"], name)\n\n    def test_side_effecting_operator_routes_reject_get_and_require_mutation_header(self) -> None:\n        before = self.client.get("/api/reports").json()["reports"]\n        self.assertEqual(self.client.get("/api/export/report").status_code, 405)\n        after = self.client.get("/api/reports").json()["reports"]\n        self.assertEqual(after, before)\n\n        self.assertEqual(self.client.get("/api/enrich/vt/192.168.50.10").status_code, 405)\n        self.assertEqual(self.client.post("/api/export/report").status_code, 403)\n        self.assertEqual(self.client.post("/api/enrich/vt/192.168.50.10").status_code, 403)\n''',
)

# Browser contracts prove the controls use POST and visibly surface failures.
replace_once(
    "tests/test_browser_contract.py",
    '''    assert "await fetch('/api/traps/'+encodeURIComponent(trapId)" not in UI\n''',
    '''    assert "await fetch('/api/traps/'+encodeURIComponent(trapId)" not in UI\n    assert "await apiPost('/api/export/report')" in UI\n    assert "await apiPost('/api/enrich/vt/'" in UI\n    assert "window.open('/api/export/report'" not in UI\n''',
)
replace_once(
    "tests/test_browser_contract.py",
    '''    for label in ["anomaly scan", "watchdog", "network diff", "risk rescore", "trap deployment", "stop all traps", "note save"]:\n''',
    '''    for label in ["anomaly scan", "watchdog", "network diff", "risk rescore", "trap deployment", "stop all traps", "note save", "report export", "VirusTotal lookup"]:\n''',
)

# Sites contract: no remaining GET-with-side-effect exceptions.
site_path = ROOT / "site_capabilities.json"
site = json.loads(site_path.read_text(encoding="utf-8"))
ops = {item["id"]: item for item in site["operations"]}
for op_id in ("report-export", "vt-enrichment"):
    local = ops[op_id]["local_runtime"]
    local["method"] = "POST"
    local["operator_header_required"] = True
ops["report-export"]["notes"] = "POST creates and persists the report; the returned /api/reports/{name} URL is read-only retrieval."
ops["report-export"]["retrieval_route"] = "/api/reports/{name}"
ops["vt-enrichment"]["notes"] = "Explicit operator-triggered external lookup; requires operator-supplied VT_API_KEY and records an event when a lookup succeeds."
site["known_limitations"] = [
    item for item in site.get("known_limitations", [])
    if item.get("id") not in {"report-export-get-side-effect", "vt-enrichment-get-side-effect"}
]
site_path.write_text(json.dumps(site, indent=2) + "\n", encoding="utf-8")

replace_once(
    "tests/test_site_capability_contract.py",
    '''def test_get_routes_with_known_side_effects_are_explicitly_declared():\n    limitations = {item["id"]: item for item in SITE["known_limitations"]}\n    assert limitations["report-export-get-side-effect"]["route"] == "/api/export/report"\n    assert limitations["vt-enrichment-get-side-effect"]["route"] == "/api/enrich/vt/{ip}"\n\n    operations = {item["id"]: item for item in SITE["operations"]}\n    assert operations["report-export"]["local_runtime"]["persistence"] == "local_report_file"\n    assert operations["vt-enrichment"]["local_runtime"]["external_network_dependency"] is True\n''',
    '''def test_side_effecting_site_actions_are_explicit_post_mutations():\n    operations = {item["id"]: item for item in SITE["operations"]}\n    report = operations["report-export"]\n    vt = operations["vt-enrichment"]\n\n    assert report["local_runtime"]["method"] == "POST"\n    assert report["local_runtime"]["operator_header_required"] is True\n    assert report["retrieval_route"] == "/api/reports/{name}"\n    assert _route_supports("/api/export/report", "POST")\n    assert not _route_supports("/api/export/report", "GET")\n\n    assert vt["local_runtime"]["method"] == "POST"\n    assert vt["local_runtime"]["operator_header_required"] is True\n    assert vt["local_runtime"]["external_network_dependency"] is True\n    assert _route_supports("/api/enrich/vt/{ip}", "POST")\n    assert not _route_supports("/api/enrich/vt/{ip}", "GET")\n\n    limitation_ids = {item["id"] for item in SITE.get("known_limitations", [])}\n    assert "report-export-get-side-effect" not in limitation_ids\n    assert "vt-enrichment-get-side-effect" not in limitation_ids\n''',
)

# Docs: the debt is now an invariant, not a warning.
replace_once(
    "docs/SITES_HANDOFF.md",
    '''## Known API semantic debt\n\nTwo current GET routes have operator-visible side effects and therefore must **never** be used as page-load fetches:\n\n- `GET /api/export/report` generates and persists a report file.\n- `GET /api/enrich/vt/{ip}` performs an external VirusTotal lookup and records an event.\n\nThey are explicitly recorded in `site_capabilities.json` until their HTTP semantics are tightened in a later runtime change.\n''',
    '''## Mutation semantics\n\nSide-effecting operator actions use mutation methods:\n\n- `POST /api/export/report` generates and persists a report, then returns its read-only `/api/reports/{name}` retrieval URL.\n- `POST /api/enrich/vt/{ip}` performs the explicit external VirusTotal lookup and may record an event.\n\nBoth routes require the operator mutation header and reject GET. They must never be invoked during page-load hydration.\n''',
)
replace_once(
    "docs/BROWSER_RUNTIME_CONTRACT.md",
    '''## Page-load boundary\n''',
    '''## Side-effecting action semantics\n\nReport generation and VirusTotal enrichment are explicit mutations. `POST /api/export/report` creates the durable local report and returns a read-only report URL; `POST /api/enrich/vt/{ip}` performs the operator-requested external lookup. Both require the operator header and reject GET. Page-load hydration must never invoke either route.\n\n## Page-load boundary\n''',
)

# README route table reflects the tightened semantics.
replace_once(
    "README.md",
    "GET  /api/export/report\n",
    "POST /api/export/report\n",
)
replace_once(
    "README.md",
    "POST /api/scan/rescore\n",
    "POST /api/scan/rescore\nPOST /api/enrich/vt/{ip}\n",
)

print("Mutation route semantics patch applied")
