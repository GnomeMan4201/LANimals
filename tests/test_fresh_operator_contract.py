from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ci_runs_fresh_operator_journey_after_base_smoke():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    base = "bash scripts/smoke_appliance.sh"
    journey = "bash scripts/smoke_operator_journey.sh"
    assert base in workflow
    assert journey in workflow
    assert workflow.index(base) < workflow.index(journey)


def test_fresh_journey_is_isolated_and_private():
    script = (ROOT / "scripts" / "smoke_operator_journey.sh").read_text(encoding="utf-8")
    assert "mktemp -d /tmp/lanimals-journey" in script
    assert 'export HOME="$JOURNEY_ROOT/home"' in script
    assert 'SCOPE="192.168.250.0/30"' in script
    assert 'NAMESPACE="lanimals-fixture"' in script
    assert "ip netns add" in script
    assert "./install.sh --scope" in script


def test_fresh_journey_covers_evidence_and_restart_boundaries():
    script = (ROOT / "scripts" / "smoke_operator_journey.sh").read_text(encoding="utf-8")
    required = [
        "/api/scan/discovery",
        "/api/baseline/accept",
        "/api/scan/services/",
        "/api/hosts/{TARGET}/notes",
        "/api/export/report",
        "/api/diff",
        "/api/traps",
        "/api/scan/rogue",
        "/api/baseline/defer",
        "lanimals stop",
        "lanimals start --no-browser",
    ]
    for marker in required:
        assert marker in script
