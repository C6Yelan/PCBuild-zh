# backend/tools/ops/chat/chat_artifact_helpers.py
"""Shared JSON and artifact payload helpers for chat ops CLIs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from backend.services.chat.snapshot_store import read_json_file

ArtifactSpec = tuple[str, str]


def read_json_artifact(path: Path) -> dict[str, Any]:
    return read_json_file(path)


def list_snapshot_artifacts(snapshot_dir: Path) -> list[str]:
    return sorted(path.name for path in snapshot_dir.iterdir() if path.is_file())


def add_optional_json_artifacts(
    payload: dict[str, object],
    *,
    snapshot_dir: Path,
    artifact_specs: Sequence[ArtifactSpec],
) -> None:
    for payload_key, filename in artifact_specs:
        artifact_path = snapshot_dir / filename
        if artifact_path.is_file():
            payload[payload_key] = read_json_artifact(artifact_path)


def build_request_snapshot_payload(
    *,
    request_id: str,
    snapshot_dir: Path,
    artifact_specs: Sequence[ArtifactSpec],
) -> dict[str, object]:
    payload: dict[str, object] = {
        "request_id": request_id,
        "snapshot_dir": str(snapshot_dir),
        "artifacts": list_snapshot_artifacts(snapshot_dir),
    }
    add_optional_json_artifacts(
        payload,
        snapshot_dir=snapshot_dir,
        artifact_specs=artifact_specs,
    )
    return payload


def emit_json_payload(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
