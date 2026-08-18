import json

import pytest

from core import nexus_state


def _redirect_state(monkeypatch, tmp_path):
    current = tmp_path / "network_snapshot.json"
    legacy = tmp_path / "nexus_state.json"
    monkeypatch.setattr(nexus_state, "SNAPSHOT_STATE_FILE", current)
    monkeypatch.setattr(nexus_state, "LEGACY_STATE_FILE", legacy)
    return current, legacy


def _snapshot(ip: str = "192.168.1.10", *, saved_at: str = "2026-08-18T00:00:00Z"):
    return {
        "hosts": {
            ip: {
                "ip": ip,
                "hostname": f"host-{ip.rsplit('.', 1)[-1]}",
                "mac": "AA:BB:CC:DD:EE:01",
                "status": "normal",
                "risk_score": 15,
            }
        },
        "saved_at": saved_at,
        "source": "discovery",
        "scope": "192.168.1.0/24",
    }


def test_missing_state_is_a_valid_first_run(monkeypatch, tmp_path):
    _redirect_state(monkeypatch, tmp_path)

    assert nexus_state.load_snapshot_pair() == {
        "schema_version": nexus_state.SNAPSHOT_SCHEMA_VERSION,
        "previous": None,
        "current": None,
    }


def test_malformed_state_fails_closed_and_is_not_replaced(monkeypatch, tmp_path):
    current, _ = _redirect_state(monkeypatch, tmp_path)
    original = b'{"schema_version": 2, "current": '
    current.write_bytes(original)

    with pytest.raises(nexus_state.SnapshotStateError, match="cannot read snapshot state"):
        nexus_state.load_snapshot_pair()

    with pytest.raises(nexus_state.SnapshotStateError, match="cannot read snapshot state"):
        nexus_state.advance_snapshot_state(_snapshot("192.168.1.20"))

    assert current.read_bytes() == original


def test_unsupported_schema_version_is_not_treated_as_empty(monkeypatch, tmp_path):
    current, _ = _redirect_state(monkeypatch, tmp_path)
    current.write_text(
        json.dumps({"schema_version": 999, "previous": None, "current": None}),
        encoding="utf-8",
    )

    with pytest.raises(nexus_state.SnapshotStateError, match="unsupported snapshot schema"):
        nexus_state.load_snapshot_pair()


def test_invalid_v2_snapshot_structure_fails_closed(monkeypatch, tmp_path):
    current, _ = _redirect_state(monkeypatch, tmp_path)
    current.write_text(
        json.dumps(
            {
                "schema_version": nexus_state.SNAPSHOT_SCHEMA_VERSION,
                "previous": None,
                "current": {"hosts": ["not", "a", "mapping"]},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(nexus_state.SnapshotStateError, match="invalid current snapshot structure"):
        nexus_state.load_snapshot_pair()


def test_valid_legacy_snapshot_advances_without_losing_history(monkeypatch, tmp_path):
    current, legacy = _redirect_state(monkeypatch, tmp_path)
    first = _snapshot("192.168.1.10", saved_at="2026-08-18T00:00:00Z")
    second = _snapshot("192.168.1.20", saved_at="2026-08-18T01:00:00Z")
    legacy.write_text(json.dumps(first), encoding="utf-8")

    pair = nexus_state.load_snapshot_pair()
    assert pair["previous"] is None
    assert set(pair["current"]["hosts"]) == {"192.168.1.10"}

    advanced = nexus_state.advance_snapshot_state(second)
    assert set(advanced["previous"]["hosts"]) == {"192.168.1.10"}
    assert set(advanced["current"]["hosts"]) == {"192.168.1.20"}

    persisted = json.loads(current.read_text(encoding="utf-8"))
    assert persisted["schema_version"] == nexus_state.SNAPSHOT_SCHEMA_VERSION
    assert set(persisted["previous"]["hosts"]) == {"192.168.1.10"}
    assert set(persisted["current"]["hosts"]) == {"192.168.1.20"}
