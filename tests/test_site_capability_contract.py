from __future__ import annotations

import json
from pathlib import Path

from core.nexus_api import app
from core.version import VERSION


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "capabilities.json").read_text(encoding="utf-8"))
SITE = json.loads((ROOT / "site_capabilities.json").read_text(encoding="utf-8"))


def _route_supports(path: str, method: str | None) -> bool:
    for route in app.routes:
        if getattr(route, "path", None) != path:
            continue
        if method is None:
            return True
        methods = getattr(route, "methods", None) or set()
        if method in methods:
            return True
    return False


def test_site_contract_uses_canonical_product_and_authority():
    assert SITE["product"] == MANIFEST["product"] == "LANimals"
    assert SITE["product_version"] == MANIFEST["version"] == VERSION
    assert MANIFEST["site_contract"] == "site_capabilities.json"
    assert SITE["authority"]["capability_manifest"] == "capabilities.json"
    assert SITE["authority"]["browser_contract"] == "docs/BROWSER_RUNTIME_CONTRACT.md"


def test_hosted_and_local_surfaces_preserve_the_runtime_boundary():
    hosted = SITE["surfaces"]["hosted_site"]
    local = SITE["surfaces"]["self_hosted_web"]

    assert hosted["mode"] == MANIFEST["surfaces"]["hosted_site"]["mode"]
    assert hosted["network_access"] is False
    assert hosted["api_connection"] == "none"
    assert "NO LIVE LAN ACCESS" in hosted["required_badge"]

    assert local["mode"] == MANIFEST["surfaces"]["self_hosted_web"]["mode"]
    assert local["api_connection"] == "same_origin_local_runtime"
    assert local["system_shell"] is False
    assert MANIFEST["operator_bridge"]["system_shell"] is False


def test_every_site_operation_maps_to_a_declared_capability_and_real_route():
    capabilities = {item["id"]: item for item in MANIFEST["capabilities"]}
    operation_ids: list[str] = []

    for operation in SITE["operations"]:
        operation_ids.append(operation["id"])
        capability = capabilities[operation["capability_id"]]
        local = operation["local_runtime"]
        route = local["route"]

        assert route in capability["routes"], (operation["id"], route, capability["id"])
        assert _route_supports(route, local["method"]), (operation["id"], local["method"], route)
        assert operation["failure_contract"] == "surface_error_and_preserve_previous_state"

    assert len(operation_ids) == len(set(operation_ids))


def test_mutating_http_operations_require_operator_header():
    for operation in SITE["operations"]:
        local = operation["local_runtime"]
        if local["method"] in {"POST", "PATCH", "DELETE"}:
            assert local["operator_header_required"] is True, operation["id"]


def test_hosted_site_has_no_live_network_effect_or_silent_live_fallback():
    assert SITE["site_rules"]["page_load"] == "read_only"
    assert SITE["site_rules"]["active_collection"] == "explicit_operator_action_only"
    assert "never silently substitute fabricated live data" in SITE["site_rules"]["hosted_fallback"]

    for operation in SITE["operations"]:
        hosted = operation["hosted_site"]
        assert hosted["live_network_effect"] is False, operation["id"]
        assert not hosted["behavior"].startswith("live"), operation["id"]


def test_get_routes_with_known_side_effects_are_explicitly_declared():
    limitations = {item["id"]: item for item in SITE["known_limitations"]}
    assert limitations["report-export-get-side-effect"]["route"] == "/api/export/report"
    assert limitations["vt-enrichment-get-side-effect"]["route"] == "/api/enrich/vt/{ip}"

    operations = {item["id"]: item for item in SITE["operations"]}
    assert operations["report-export"]["local_runtime"]["persistence"] == "local_report_file"
    assert operations["vt-enrichment"]["local_runtime"]["external_network_dependency"] is True
