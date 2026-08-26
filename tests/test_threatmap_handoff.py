from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from core.threatmap_handoff import (
    ThreatmapHandoffError,
    ThreatmapHandoffRejected,
    build_threatmap_candidate,
    canonical_sha256,
    send_to_threatmap,
)


SOURCE_RECORD = {
    "host": "192.0.2.44",
    "port": 22,
    "service": "ssh",
    "scope": "192.0.2.0/24",
}
EXPECTED_HASH = "5c42d90124f84707773c59961429766c789d1f57b55173b447261dd16a28cf18"


def candidate():
    return build_threatmap_candidate(
        source_record_id="LAN-OBS-0001",
        observed_at="2026-08-26T02:00:00-05:00",
        observation_type="network_observation",
        source="approved_private_lan",
        source_locator="192.0.2.44",
        source_record=SOURCE_RECORD,
        collector_version="2.1.0-test",
    )


def test_threatmap_canonical_hash_vector():
    assert canonical_sha256(SOURCE_RECORD) == EXPECTED_HASH


def test_candidate_normalizes_timestamp_and_hashes_source_record():
    item = candidate()
    assert item["schema_version"] == 1
    assert item["observed_at"] == "2026-08-26T07:00:00Z"
    assert item["source_record_sha256"] == EXPECTED_HASH
    assert item["source_record"] == SOURCE_RECORD


def test_candidate_rejects_non_finite_source_data():
    with pytest.raises(ValueError, match="non-finite"):
        build_threatmap_candidate(
            source_record_id="LAN-OBS-BAD",
            observed_at="2026-08-26T07:00:00Z",
            observation_type="network_observation",
            source="approved_private_lan",
            source_record={"score": float("nan")},
            collector_version="2.1.0-test",
        )


def _serve_once(path: Path, response_factory, captured: dict):
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    os.chmod(path, 0o600)
    server.listen(1)
    try:
        conn, _ = server.accept()
        with conn:
            reader = conn.makefile("rb")
            request = json.loads(reader.readline())
            captured.update(request)
            response = response_factory(request)
            conn.sendall(json.dumps(response).encode("utf-8") + b"\n")
    finally:
        server.close()


def test_send_to_threatmap_uses_local_ipc_contract():
    with tempfile.TemporaryDirectory() as tmp:
        socket_path = Path(tmp) / "threatmapd.sock"
        captured = {}

        def response_factory(request):
            return {
                "id": request["id"],
                "ok": True,
                "result": {
                    "inserted": True,
                    "evidence": {"record_id": "EVID-LAN-test"},
                },
            }

        thread = threading.Thread(
            target=_serve_once,
            args=(socket_path, response_factory, captured),
            daemon=True,
        )
        thread.start()
        for _ in range(100):
            if socket_path.exists():
                break
            thread.join(0.01)

        result = send_to_threatmap(
            socket_path,
            "CASE-001",
            candidate(),
            request_id="req-fixed",
        )
        thread.join(timeout=1)

        assert result["inserted"] is True
        assert captured["id"] == "req-fixed"
        assert captured["op"] == "handoff.lanimals.accept"
        assert captured["params"]["case_id"] == "CASE-001"
        assert captured["params"]["candidate"]["source_record_sha256"] == EXPECTED_HASH


def test_send_surfaces_threatmap_rejection():
    with tempfile.TemporaryDirectory() as tmp:
        socket_path = Path(tmp) / "threatmapd.sock"
        captured = {}

        def response_factory(request):
            return {
                "id": request["id"],
                "ok": False,
                "error": {"code": "VALIDATION_ERROR", "message": "hash mismatch"},
            }

        thread = threading.Thread(
            target=_serve_once,
            args=(socket_path, response_factory, captured),
            daemon=True,
        )
        thread.start()
        for _ in range(100):
            if socket_path.exists():
                break
            thread.join(0.01)

        with pytest.raises(ThreatmapHandoffRejected) as exc:
            send_to_threatmap(socket_path, "CASE-001", candidate(), request_id="reject")
        thread.join(timeout=1)
        assert exc.value.code == "VALIDATION_ERROR"


def test_send_rejects_non_socket_path():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "not-a-socket"
        path.write_text("no", encoding="utf-8")
        with pytest.raises(ThreatmapHandoffError, match="not a direct Unix socket"):
            send_to_threatmap(path, "CASE-001", candidate())
