from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# ARP refresh must obey the exact same approved CIDR boundary as Discovery/Rogue.
replace_once(
    "core/nexus_api.py",
    '''def _run_arp_refresh(jid: str) -> None:\n    try:\n        _job_log(jid, "ARP neighbor refresh")\n        rows = collect_arp_neighbors()\n        local = collect_local_interfaces()\n        for r in rows:\n            _job_log(jid, f"  {r.get('ip',''):18s}  mac={r.get('mac') or '--':20s}  state={r.get('state','')}")\n        save_discovery_cache({\n            "arp_neighbors": rows,\n            "local_interfaces": local,\n            "nmap_hosts": [],\n        })\n        upsert_hosts(rows + local)\n        _job_log(jid, f"ARP refresh complete: {len(rows)} entries — graph cache updated")\n        _job_done(jid, {"count": len(rows), "neighbors": rows})\n    except Exception as exc:\n        _job_log(jid, f"ERROR: {exc}")\n        _job_done(jid, None, str(exc))\n''',
    '''def _run_arp_refresh(jid: str, cidr: str) -> None:\n    try:\n        _job_log(jid, f"ARP neighbor refresh: {cidr}")\n        rows = filter_observations_to_cidr(collect_arp_neighbors(), cidr)\n        local = filter_observations_to_cidr(collect_local_interfaces(), cidr)\n        for r in rows:\n            _job_log(jid, f"  {r.get('ip',''):18s}  mac={r.get('mac') or '--':20s}  state={r.get('state','')}")\n        save_discovery_cache({\n            "arp_neighbors": rows,\n            "local_interfaces": local,\n            "nmap_hosts": [],\n            "cidr": cidr,\n        })\n        upsert_hosts(rows + local)\n        _job_log(jid, f"ARP refresh complete: {len(rows)} in-scope entries — graph cache updated")\n        _job_done(jid, {"count": len(rows), "neighbors": rows, "cidr": cidr})\n    except Exception as exc:\n        _job_log(jid, f"ERROR: {exc}")\n        _job_done(jid, None, str(exc))\n''',
)

replace_once(
    "core/nexus_api.py",
    '''@app.post("/api/scan/arp")\ndef scan_arp():\n    jid = _job_create("arp_refresh", {})\n    threading.Thread(target=_run_arp_refresh, args=(jid,), daemon=True).start()\n    return {"ok": True, "job_id": jid, "op": "arp_refresh"}\n''',
    '''@app.post("/api/scan/arp")\ndef scan_arp(cidr: Optional[str] = Query(default=None)):\n    cidr = _cidr_or_422(cidr)\n    jid = _job_create("arp_refresh", {"cidr": cidr})\n    threading.Thread(target=_run_arp_refresh, args=(jid, cidr), daemon=True).start()\n    return {"ok": True, "job_id": jid, "op": "arp_refresh", "cidr": cidr}\n''',
)

replace_once(
    "core/nexus_api.py",
    '''    if action == "scan:arp":\n        jid = _job_create("arp_refresh", {})\n        runner, args = _run_arp_refresh, (jid,)\n''',
    '''    if action == "scan:arp":\n        cidr = _cidr_or_422(target)\n        jid = _job_create("arp_refresh", {"cidr": cidr})\n        runner, args = _run_arp_refresh, (jid, cidr)\n''',
)

# Terminal ARP may optionally name an approved CIDR, matching the browser/API.
replace_once(
    "core/nexus_terminal.py",
    '''    if operation == "arp" and target:\n        raise TerminalCommandError("scan arp does not accept a target")\n    return TerminalCommand(f"scan:{operation}", target)\n''',
    '''    return TerminalCommand(f"scan:{operation}", target)\n''',
)
replace_once(
    "core/nexus_terminal.py",
    '        "  scan arp                   refresh ARP observations",\n',
    '        "  scan arp [CIDR]            refresh ARP observations in approved scope",\n',
)

# One fail-closed browser mutation path for POST/PATCH/DELETE.
replace_once(
    "ui/lanimals_live_map.html",
    '''async function apiGet(path){ const r=await fetch(path); if(!r.ok) throw new Error(r.status); return r.json(); }\nasync function apiPost(path,body){\n  const headers={'X-LANimals-Operator':'1'};\n  if(body) headers['Content-Type']='application/json';\n  const r=await fetch(path,{method:'POST',headers,body:body?JSON.stringify(body):undefined});\n  if(!r.ok){ let detail=''; try{ detail=(await r.json()).detail||''; }catch(e){} throw new Error(detail||r.status); }\n  return r.json();\n}\n''',
    '''async function apiGet(path){\n  const r=await fetch(path);\n  if(!r.ok){ let detail=''; try{ detail=(await r.json()).detail||''; }catch(e){} throw new Error(detail||`GET ${path} failed (${r.status})`); }\n  return r.json();\n}\nasync function apiMutate(method,path,body){\n  const headers={'X-LANimals-Operator':'1'};\n  if(body!==undefined) headers['Content-Type']='application/json';\n  const r=await fetch(path,{method,headers,body:body!==undefined?JSON.stringify(body):undefined});\n  if(!r.ok){ let detail=''; try{ detail=(await r.json()).detail||''; }catch(e){} throw new Error(detail||`${method} ${path} failed (${r.status})`); }\n  const ctype=r.headers.get('content-type')||'';\n  return ctype.includes('application/json')?r.json():null;\n}\nasync function apiPost(path,body){ return apiMutate('POST',path,body); }\nasync function apiPatch(path,body){ return apiMutate('PATCH',path,body); }\nasync function apiDelete(path){ return apiMutate('DELETE',path); }\nfunction showActionError(label,e){\n  const msg=e?.message||String(e);\n  addScanLine(`ERROR: ${label}: ${msg}`,'err');\n  setStatus(`${label} failed`,'error');\n}\n''',
)

replace_once(
    "ui/lanimals_live_map.html",
    "$('btnArp').onclick=()=>runOp('/api/scan/arp');\n",
    "$('btnArp').onclick=()=>runOp('/api/scan/arp?cidr='+encodeURIComponent(cidr()));\n",
)

# Notes may never claim success after a rejected PATCH.
replace_once(
    "ui/lanimals_live_map.html",
    '''  if(notesBtn&&node.ip){\n    notesBtn.addEventListener('click',async()=>{\n      notesBtn.textContent='Saving…';\n      await fetch('/api/hosts/'+encodeURIComponent(node.ip)+'/notes',{method:'PATCH',headers:{'Content-Type':'application/json','X-LANimals-Operator':'1'},body:JSON.stringify({notes:$('notesArea').value})});\n      notesBtn.textContent='Saved ✓';\n      setTimeout(()=>notesBtn.textContent='Save Notes',1500);\n    });\n  }\n''',
    '''  if(notesBtn&&node.ip){\n    notesBtn.addEventListener('click',async()=>{\n      notesBtn.textContent='Saving…';\n      try{\n        await apiPatch('/api/hosts/'+encodeURIComponent(node.ip)+'/notes',{notes:$('notesArea').value});\n        notesBtn.textContent='Saved';\n        setStatus('notes saved','ready');\n      }catch(e){\n        notesBtn.textContent='Save failed';\n        showActionError('note save',e);\n      }\n      setTimeout(()=>notesBtn.textContent='Save Notes',1500);\n    });\n  }\n''',
)

# Individual trap stop must check the DELETE result before refreshing/claiming success.
replace_once(
    "ui/lanimals_live_map.html",
    '''async function stopTrap(trapId){\n  await fetch('/api/traps/'+encodeURIComponent(trapId),{method:'DELETE',headers:{'X-LANimals-Operator':'1'}});\n  await fetchTraps(); await fetchGraph();\n}\n\nasync function deployTrapBundle(){\n  addScanLine('→ Deploying trap bundle…','muted'); activateTab('scanout');\n  const d=await apiPost('/api/traps/bundle/default');\n  addScanLine(`${d.active_count} traps deployed`,'ok');\n  d.deployed?.forEach(t=>addScanLine(`  ◈ ${t.name} port=${t.port} ${t.status}`,'ok'));\n  await fetchTraps(); await fetchGraph(); activateTab('traps');\n}\n''',
    '''async function stopTrap(trapId){\n  activateTab('scanout');\n  try{\n    await apiDelete('/api/traps/'+encodeURIComponent(trapId));\n    addScanLine(`Trap stopped: ${trapId}`,'ok');\n    setStatus('trap stopped','ready');\n    await fetchTraps(); await fetchGraph();\n  }catch(e){\n    showActionError('trap stop',e);\n  }\n}\n\nasync function deployTrapBundle(){\n  addScanLine('→ Deploying trap bundle…','muted'); activateTab('scanout');\n  setStatus('deploying traps…','scanning');\n  try{\n    const d=await apiPost('/api/traps/bundle/default');\n    addScanLine(`${d.active_count} traps deployed`,'ok');\n    d.deployed?.forEach(t=>addScanLine(`  ◈ ${t.name} port=${t.port} ${t.status}`,'ok'));\n    setStatus('traps deployed','ready');\n    await fetchTraps(); await fetchGraph(); activateTab('traps');\n  }catch(e){\n    showActionError('trap deployment',e);\n  }\n}\n''',
)

# Stop-all must fail closed instead of printing success after a rejected DELETE.
replace_once(
    "ui/lanimals_live_map.html",
    '''$('btnStopAllTraps').onclick=async()=>{\n  const data=await apiGet('/api/traps');\n  for(const t of data.traps||[]){ if(t.status==='active') await fetch('/api/traps/'+t.id,{method:'DELETE',headers:{'X-LANimals-Operator':'1'}}); }\n  addScanLine('All traps stopped','muted'); await fetchTraps(); await fetchGraph();\n};\n''',
    '''$('btnStopAllTraps').onclick=async()=>{\n  activateTab('scanout');\n  setStatus('stopping traps…','scanning');\n  try{\n    const data=await apiGet('/api/traps');\n    const active=(data.traps||[]).filter(t=>t.status==='active');\n    for(const t of active) await apiDelete('/api/traps/'+encodeURIComponent(t.id));\n    addScanLine(`Stopped ${active.length} active trap(s)`,'ok');\n    setStatus('traps stopped','ready');\n    await fetchTraps(); await fetchGraph();\n  }catch(e){\n    showActionError('stop all traps',e);\n  }\n};\n''',
)

# Make inline browser operations surface backend rejection in the durable Scan Output pane.
replace_once(
    "ui/lanimals_live_map.html",
    '''$('btnAnomaly').onclick=async()=>{\n  addScanLine('→ POST /api/scan/anomaly','muted'); activateTab('scanout');\n  const d=await apiPost('/api/scan/anomaly');\n  if(d.anomalies?.length){ d.anomalies.forEach(a=>addScanLine(`  ${a.ip}:${a.port} ${a.status}`,'warn')); }\n  else addScanLine('[ OK ] No anomalies','ok');\n  fetchIntelFeed();\n};\n''',
    '''$('btnAnomaly').onclick=async()=>{\n  addScanLine('→ POST /api/scan/anomaly','muted'); activateTab('scanout');\n  setStatus('anomaly scan…','scanning');\n  try{\n    const d=await apiPost('/api/scan/anomaly');\n    if(d.error) throw new Error(d.error);\n    if(d.anomalies?.length){ d.anomalies.forEach(a=>addScanLine(`  ${a.ip}:${a.port} ${a.status}`,'warn')); }\n    else addScanLine('[ OK ] No anomalies','ok');\n    setStatus('done','ready');\n    fetchIntelFeed();\n  }catch(e){ showActionError('anomaly scan',e); }\n};\n''',
)

replace_once(
    "ui/lanimals_live_map.html",
    '''$('btnWatchdog').onclick=async()=>{\n  addScanLine('→ POST /api/watchdog','muted'); activateTab('scanout');\n  const d=await apiPost('/api/watchdog');\n  addScanLine(`Watchdog: ${d.online_count} online, ${d.offline_count} offline`,'ok');\n  d.offline?.forEach(o=>addScanLine(`  [OFFLINE] ${o.ip} ${o.hostname}`,'warn'));\n  fetchIntelFeed();\n};\n''',
    '''$('btnWatchdog').onclick=async()=>{\n  addScanLine('→ POST /api/watchdog','muted'); activateTab('scanout');\n  setStatus('watchdog…','scanning');\n  try{\n    const d=await apiPost('/api/watchdog');\n    addScanLine(`Watchdog: ${d.online_count} online, ${d.offline_count} offline`,'ok');\n    d.offline?.forEach(o=>addScanLine(`  [OFFLINE] ${o.ip} ${o.hostname}`,'warn'));\n    setStatus('done','ready');\n    fetchIntelFeed();\n  }catch(e){ showActionError('watchdog',e); }\n};\n''',
)

replace_once(
    "ui/lanimals_live_map.html",
    '''$('btnDiff').onclick=async()=>{\n  addScanLine('→ GET /api/diff · last two explicit Discovery scans','muted'); activateTab('scanout');\n  diffData=await apiGet('/api/diff');\n  addScanLine(diffData.summary,'ok');\n  diffData.appeared?.forEach(h=>addScanLine(`  [NEW] ${h.ip} ${h.hostname}`,'ok'));\n  diffData.disappeared?.forEach(h=>addScanLine(`  [GONE] ${h.ip}`,'warn'));\n  diffData.changed?.forEach(h=>{ addScanLine(`  [CHANGED] ${h.ip}`,'warn'); h.changes?.forEach(c=>addScanLine(`    ${c}`,'muted')); });\n  setOverlay('diff');\n};\n''',
    '''$('btnDiff').onclick=async()=>{\n  addScanLine('→ GET /api/diff · last two explicit Discovery scans','muted'); activateTab('scanout');\n  setStatus('loading diff…','scanning');\n  try{\n    diffData=await apiGet('/api/diff');\n    addScanLine(diffData.summary||'Diff unavailable until two explicit Discovery scans exist',diffData.comparable?'ok':'muted');\n    diffData.appeared?.forEach(h=>addScanLine(`  [NEW] ${h.ip} ${h.hostname}`,'ok'));\n    diffData.disappeared?.forEach(h=>addScanLine(`  [GONE] ${h.ip}`,'warn'));\n    diffData.changed?.forEach(h=>{ addScanLine(`  [CHANGED] ${h.ip}`,'warn'); h.changes?.forEach(c=>addScanLine(`    ${c}`,'muted')); });\n    setStatus('done','ready');\n    setOverlay('diff');\n  }catch(e){ showActionError('network diff',e); }\n};\n''',
)

replace_once(
    "ui/lanimals_live_map.html",
    '''$('btnRescore').onclick=async()=>{\n  addScanLine('→ POST /api/scan/rescore','muted'); activateTab('scanout');\n  const d=await apiPost('/api/scan/rescore');\n  addScanLine(`Rescored ${d.rescored} hosts, ${d.flagged} flagged`,'ok');\n  d.results?.filter(r=>r.status!=='normal').forEach(r=>{ addScanLine(`  [${r.status.toUpperCase()}] ${r.ip} risk=${r.risk_score}`,'warn'); r.reasons?.slice(0,2).forEach(reason=>addScanLine(`    - ${reason}`,'muted')); });\n  fetchGraph(); fetchStats(); fetchIntelFeed();\n};\n''',
    '''$('btnRescore').onclick=async()=>{\n  addScanLine('→ POST /api/scan/rescore','muted'); activateTab('scanout');\n  setStatus('rescoring…','scanning');\n  try{\n    const d=await apiPost('/api/scan/rescore');\n    addScanLine(`Rescored ${d.rescored} hosts, ${d.flagged} flagged`,'ok');\n    d.results?.filter(r=>r.status!=='normal').forEach(r=>{ addScanLine(`  [${r.status.toUpperCase()}] ${r.ip} risk=${r.risk_score}`,'warn'); r.reasons?.slice(0,2).forEach(reason=>addScanLine(`    - ${reason}`,'muted')); });\n    setStatus('done','ready');\n    fetchGraph(); fetchStats(); fetchIntelFeed();\n  }catch(e){ showActionError('risk rescore',e); }\n};\n''',
)

# A browser contract test guards the visible control/API mapping and false-success paths.
(ROOT / "tests" / "test_browser_contract.py").write_text('''from pathlib import Path\n\n\nROOT = Path(__file__).resolve().parents[1]\nUI = (ROOT / "ui" / "lanimals_live_map.html").read_text(encoding="utf-8")\nAPI = (ROOT / "core" / "nexus_api.py").read_text(encoding="utf-8")\nTERMINAL = (ROOT / "core" / "nexus_terminal.py").read_text(encoding="utf-8")\n\n\ndef test_visible_browser_actions_map_to_supported_runtime_routes():\n    expected = [\n        "/api/scan/discovery",\n        "/api/scan/arp",\n        "/api/scan/hostmap",\n        "/api/scan/rogue",\n        "/api/scan/anomaly",\n        "/api/watchdog",\n        "/api/diff",\n        "/api/scan/rescore",\n        "/api/export/report",\n        "/api/traps",\n    ]\n    for route in expected:\n        assert route in UI, route\n        assert route in API, route\n\n    assert "'/api/scan/arp?cidr='+encodeURIComponent(cidr())" in UI\n    assert 'def scan_arp(cidr: Optional[str] = Query(default=None))' in API\n    assert 'scan arp [CIDR]' in TERMINAL\n\n\ndef test_browser_mutations_share_fail_closed_status_checking():\n    assert "async function apiMutate(method,path,body)" in UI\n    assert "async function apiPatch(path,body){ return apiMutate('PATCH',path,body); }" in UI\n    assert "async function apiDelete(path){ return apiMutate('DELETE',path); }" in UI\n    assert "await apiPatch('/api/hosts/'" in UI\n    assert "await apiDelete('/api/traps/'" in UI\n    assert "notesBtn.textContent='Saved';" in UI\n    assert "notesBtn.textContent='Save failed';" in UI\n    assert "await fetch('/api/hosts/'+encodeURIComponent(node.ip)+'/notes'" not in UI\n    assert "await fetch('/api/traps/'+encodeURIComponent(trapId)" not in UI\n\n\ndef test_page_open_is_read_only_with_respect_to_network_collection_and_mutation():\n    init = UI.split("// ── Init ─", 1)[1].split("</script>", 1)[0]\n    init_before_intervals = init.split("setInterval(fetchGraph", 1)[0]\n    assert "runOp(" not in init_before_intervals\n    assert "apiPost(" not in init_before_intervals\n    assert "apiPatch(" not in init_before_intervals\n    assert "apiDelete(" not in init_before_intervals\n    assert "fetchScope();" in init_before_intervals\n    assert "fetchGraph();" in init_before_intervals\n    assert "fetchStats();" in init_before_intervals\n\n\ndef test_major_inline_actions_surface_backend_errors():\n    for label in ["anomaly scan", "watchdog", "network diff", "risk rescore", "trap deployment", "stop all traps", "note save"]:\n        assert f"showActionError('{label}'" in UI\n''', encoding="utf-8")

# Extend the existing observation-scope contract through the API ARP worker.
with (ROOT / "tests" / "test_observation_scope.py").open("a", encoding="utf-8") as handle:
    handle.write('''\n\ndef test_arp_refresh_filters_passive_evidence_to_requested_cidr():\n    from core import nexus_api\n\n    arp = [\n        {"ip": "192.168.250.0", "mac": "AA:00:00:00:00:00", "source": "arp"},\n        {"ip": "192.168.250.2", "mac": "AA:00:00:00:00:02", "source": "arp"},\n        {"ip": "192.168.251.9", "mac": "AA:00:00:00:01:09", "source": "arp"},\n    ]\n    local = [\n        {"ip": "192.168.250.1", "source": "local"},\n        {"ip": "10.0.0.5", "source": "local"},\n    ]\n    saved = {}\n    persisted = []\n    completed = {}\n\n    with (\n        patch.object(nexus_collectors, "validate_scan_cidr", return_value="192.168.250.0/30"),\n        patch.object(nexus_api, "collect_arp_neighbors", return_value=arp),\n        patch.object(nexus_api, "collect_local_interfaces", return_value=local),\n        patch.object(nexus_api, "save_discovery_cache", side_effect=lambda data: saved.update(data)),\n        patch.object(nexus_api, "upsert_hosts", side_effect=lambda rows: persisted.extend(rows)),\n        patch.object(nexus_api, "_job_log"),\n        patch.object(nexus_api, "_job_done", side_effect=lambda jid, result, error=None: completed.update({"result": result, "error": error})),\n    ):\n        nexus_api._run_arp_refresh("job", "192.168.250.0/30")\n\n    assert [row["ip"] for row in saved["arp_neighbors"]] == ["192.168.250.2"]\n    assert [row["ip"] for row in saved["local_interfaces"]] == ["192.168.250.1"]\n    assert saved["cidr"] == "192.168.250.0/30"\n    assert {row["ip"] for row in persisted} == {"192.168.250.1", "192.168.250.2"}\n    assert completed["error"] is None\n    assert completed["result"]["cidr"] == "192.168.250.0/30"\n''')

print("browser/runtime contract correction staged")
