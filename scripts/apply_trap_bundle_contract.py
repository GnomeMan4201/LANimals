from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "core/nexus_api.py",
    '''@app.post("/api/traps/bundle/{bundle_name}")\ndef deploy_trap_bundle(bundle_name: str):\n    deployed = deploy_bundle(bundle_name)\n    active = [t for t in deployed if "error" not in t]\n    insert_events([{\n        "id": f"evt:bundle:{bundle_name}:{_now_iso()}",\n        "ts": _now_iso(),\n        "severity": "info",\n        "title": f"Trap bundle deployed: {bundle_name}",\n        "summary": f"{len(active)} traps active",\n    }])\n    return {"ok": True, "bundle": bundle_name, "deployed": deployed, "active_count": len(active)}\n''',
    '''@app.post("/api/traps/bundle/{bundle_name}")\ndef deploy_trap_bundle(bundle_name: str):\n    deployed = deploy_bundle(bundle_name)\n    active = [t for t in deployed if t.get("status") == "active"]\n    failed = [t for t in deployed if t.get("status") == "error" or t.get("error")]\n    insert_events([{\n        "id": f"evt:bundle:{bundle_name}:{_now_iso()}",\n        "ts": _now_iso(),\n        "severity": "warning" if failed else "info",\n        "title": f"Trap bundle deployed: {bundle_name}",\n        "summary": f"{len(active)} traps active, {len(failed)} failed",\n    }])\n    return {\n        "ok": not failed,\n        "bundle": bundle_name,\n        "deployed": deployed,\n        "active_count": len(active),\n        "failure_count": len(failed),\n    }\n''',
)

replace_once(
    "ui/lanimals_live_map.html",
    '''async function deployTrapBundle(){\n  addScanLine('→ Deploying trap bundle…','muted'); activateTab('scanout');\n  setStatus('deploying traps…','scanning');\n  try{\n    const d=await apiPost('/api/traps/bundle/default');\n    addScanLine(`${d.active_count} traps deployed`,'ok');\n    d.deployed?.forEach(t=>addScanLine(`  ◈ ${t.name} port=${t.port} ${t.status}`,'ok'));\n    setStatus('traps deployed','ready');\n    await fetchTraps(); await fetchGraph(); activateTab('traps');\n  }catch(e){\n    showActionError('trap deployment',e);\n  }\n}\n''',
    '''async function deployTrapBundle(){\n  addScanLine('→ Deploying trap bundle…','muted'); activateTab('scanout');\n  setStatus('deploying traps…','scanning');\n  try{\n    const d=await apiPost('/api/traps/bundle/default');\n    const failures=(d.deployed||[]).filter(t=>t.status==='error'||t.error);\n    addScanLine(`${d.active_count} traps active · ${d.failure_count??failures.length} failed`,failures.length?'warn':'ok');\n    d.deployed?.forEach(t=>{\n      const failed=t.status==='error'||t.error;\n      addScanLine(`  ◈ ${t.name||'trap'} port=${t.port??'?'} ${failed?'ERROR: '+(t.error||t.status):t.status}`,failed?'err':'ok');\n    });\n    if(failures.length){\n      setStatus('trap bundle partial','error');\n    }else{\n      setStatus('traps deployed','ready');\n    }\n    await fetchTraps(); await fetchGraph(); activateTab('traps');\n  }catch(e){\n    showActionError('trap deployment',e);\n  }\n}\n''',
)

with (ROOT / "tests" / "test_browser_contract.py").open("a", encoding="utf-8") as handle:
    handle.write('''\n\ndef test_trap_bundle_ui_distinguishes_partial_failure_from_success():\n    assert "const failures=(d.deployed||[]).filter(t=>t.status==='error'||t.error);" in UI\n    assert "setStatus('trap bundle partial','error');" in UI\n    assert "d.failure_count??failures.length" in UI\n''')

with (ROOT / "tests" / "test_operator_lifecycle.py").open("a", encoding="utf-8") as handle:
    handle.write('''\n\nclass TrapBundleResultContractTests(unittest.TestCase):\n    def test_bundle_counts_status_not_presence_of_error_key(self) -> None:\n        fake = [\n            {"id": "ok1", "name": "one", "port": 1, "status": "active", "error": None},\n            {"id": "ok2", "name": "two", "port": 2, "status": "active", "error": None},\n            {"id": "bad", "name": "three", "port": 3, "status": "error", "error": "busy"},\n        ]\n        client = TestClient(app)\n        with (\n            patch.object(nexus_api, "deploy_bundle", return_value=fake),\n            patch.object(nexus_api, "insert_events"),\n        ):\n            payload = client.post(\n                "/api/traps/bundle/default",\n                headers={"X-LANimals-Operator": "1"},\n            ).json()\n\n        self.assertFalse(payload["ok"])\n        self.assertEqual(payload["active_count"], 2)\n        self.assertEqual(payload["failure_count"], 1)\n''')

print("trap bundle result contract staged")
