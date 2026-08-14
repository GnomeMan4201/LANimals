from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = (ROOT / "docs" / "SITES_BUILD_SPEC.md").read_text(encoding="utf-8")
PROMPT = (ROOT / "docs" / "SITES_BUILD_PROMPT.md").read_text(encoding="utf-8")
HANDOFF = (ROOT / "docs" / "SITES_HANDOFF.md").read_text(encoding="utf-8")


def test_sites_documents_preserve_authority_chain():
    for text in (SPEC, PROMPT):
        assert "capabilities.json" in text
        assert "site_capabilities.json" in text
        assert "docs/BROWSER_RUNTIME_CONTRACT.md" in text

    assert "docs/SITES_BUILD_SPEC.md" in HANDOFF
    assert "docs/SITES_BUILD_PROMPT.md" in HANDOFF


def test_hosted_surface_is_unambiguously_representative():
    for text in (SPEC, PROMPT):
        assert "REPRESENTATIVE / NO LIVE LAN ACCESS" in text
        assert "no direct" in text.lower()
        assert "visitor" in text.lower()
        assert "LAN" in text


def test_side_effecting_routes_remain_explicit_post_mutations():
    for text in (SPEC, PROMPT, HANDOFF):
        assert "POST /api/export/report" in text
        assert "POST /api/enrich/vt/{ip}" in text


def test_product_identity_and_operator_direction_are_locked():
    for text in (SPEC, PROMPT):
        assert "LANimals" in text
        assert "maroon" in text.lower()
        assert "marketing" in text.lower()
        assert "operator" in text.lower()
        assert "phone" in text.lower() or "mobile" in text.lower()


def test_terminal_boundary_and_no_dead_controls_are_explicit():
    for text in (SPEC, PROMPT):
        lowered = text.lower()
        assert "operating-system shell" in lowered or "system shell" in lowered
        assert "dead" in lowered
        assert "placeholder" in lowered
