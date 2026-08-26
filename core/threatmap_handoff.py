from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HANDOFF_SCHEMA_VERSION = 1
MAX_RESPONSE_BYTES = 256 * 1024


class ThreatmapHandoffError(RuntimeError):
    pass


class ThreatmapHandoffRejected(ThreatmapHandoffError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def canonical_timestamp(value: str | datetime) -> str:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("observed_at is empty")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    elif isinstance(value, datetime):
        dt = value
    else:
        raise ValueError("observed_at must be str or datetime")
    if dt.tzinfo is None:
        raise ValueError("observed_at must include an explicit timezone")
    dt = dt.astimezone(timezone.utc)
    rendered = dt.isoformat(
        timespec="microseconds" if dt.microsecond else "seconds"
    )
    return rendered.replace("+00:00", "Z")


def _reject_non_json(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"non-finite float at {path}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_non_json(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"non-string key at {path}")
            _reject_non_json(item, f"{path}.{key}")
        return
    raise ValueError(f"unsupported value at {path}: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    _reject_non_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def lanimals_version() -> str:
    version_file = Path(__file__).resolve().parents[1] / "VERSION"
    return version_file.read_text(encoding="utf-8").strip()


def build_threatmap_candidate(
    *,
    source_record_id: str,
    observed_at: str | datetime,
    observation_type: str,
    source: str,
    source_record: dict[str, Any],
    source_locator: str | None = None,
    notes: str | None = None,
    collector_version: str | None = None,
) -> dict[str, Any]:
    """Build the transport candidate accepted by THREATMAP IPC v1.

    The candidate is not case evidence by itself. THREATMAP independently
    verifies the source-record hash and decides whether to accept it.
    """

    for name, value in {
        "source_record_id": source_record_id,
        "observation_type": observation_type,
        "source": source,
    }.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
    if not isinstance(source_record, dict):
        raise ValueError("source_record must be a JSON object")

    version = collector_version if collector_version is not None else lanimals_version()
    if not isinstance(version, str) or not version.strip():
        raise ValueError("collector_version must be a non-empty string")
    if source_locator is not None and (
        not isinstance(source_locator, str) or not source_locator.strip()
    ):
        raise ValueError("source_locator must be a non-empty string or null")
    if notes is not None and (not isinstance(notes, str) or not notes.strip()):
        raise ValueError("notes must be a non-empty string or null")

    source_hash = canonical_sha256(source_record)
    return {
        "schema_version": HANDOFF_SCHEMA_VERSION,
        "source_record_id": source_record_id.strip(),
        "source_record_sha256": source_hash,
        "observed_at": canonical_timestamp(observed_at),
        "observation_type": observation_type.strip(),
        "collector_version": version.strip(),
        "source": source.strip(),
        "source_locator": source_locator.strip() if source_locator is not None else None,
        "source_record": source_record,
        "notes": notes.strip() if notes is not None else None,
    }


def build_accept_request(
    case_id: str,
    candidate: dict[str, Any],
    *,
    request_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("case_id must be a non-empty string")
    if not isinstance(candidate, dict):
        raise ValueError("candidate must be a JSON object")
    return {
        "id": request_id or str(uuid.uuid4()),
        "op": "handoff.lanimals.accept",
        "params": {"case_id": case_id.strip(), "candidate": candidate},
    }


def send_to_threatmap(
    socket_path: str | Path,
    case_id: str,
    candidate: dict[str, Any],
    *,
    request_id: str | None = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Send one candidate to local threatmapd and return its result."""

    path = Path(socket_path)
    _validate_socket_path(path)
    request = build_accept_request(case_id, candidate, request_id=request_id)
    payload = canonical_json_bytes(request) + b"\n"

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(str(path))
        client.sendall(payload)
        reader = client.makefile("rb")
        line = reader.readline(MAX_RESPONSE_BYTES + 1)

    if not line or len(line) > MAX_RESPONSE_BYTES or not line.endswith(b"\n"):
        raise ThreatmapHandoffError("invalid or oversized threatmapd response")
    try:
        response = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ThreatmapHandoffError("threatmapd returned invalid JSON") from exc
    if response.get("id") != request["id"]:
        raise ThreatmapHandoffError("threatmapd response id mismatch")
    if response.get("ok") is not True:
        error = response.get("error") if isinstance(response.get("error"), dict) else {}
        raise ThreatmapHandoffRejected(
            str(error.get("code", "UNKNOWN")),
            str(error.get("message", "handoff rejected")),
        )
    result = response.get("result")
    if not isinstance(result, dict):
        raise ThreatmapHandoffError("threatmapd success response missing result object")
    return result


def _validate_socket_path(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise ThreatmapHandoffError(f"threatmapd socket does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
        raise ThreatmapHandoffError("threatmapd path is not a direct Unix socket")
    if info.st_uid != os.getuid():
        raise ThreatmapHandoffError("threatmapd socket is not owned by current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ThreatmapHandoffError("threatmapd socket permissions are broader than 0600")
