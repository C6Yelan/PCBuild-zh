# backend/services/chat/snapshot_artifacts.py
"""Artifact read/write helpers for chat snapshot persistence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.services.chat.snapshot_redaction import redact_snapshot_value


def write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def write_text_file(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")


def read_json_file(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def persist_snapshot_artifacts(
    *,
    snapshot_dir: Path,
    raw_request: dict[str, Any],
    raw_response: dict[str, Any],
    request_context: dict[str, Any],
    validation_report: dict[str, Any] | None,
    dq_report: dict[str, Any] | None,
    context_pack_text: str | None,
    compressed_candidates: dict[str, list[dict[str, object]]],
    drop_log: dict[str, dict[str, object]],
    lineage: dict[str, Any] | None,
    normalized_demand: dict[str, Any] | None,
    normalization_report: dict[str, Any] | None,
) -> list[str]:
    artifacts: list[str] = []

    write_json_file(snapshot_dir / "raw_request.json", raw_request)
    artifacts.append("raw_request.json")

    write_json_file(snapshot_dir / "raw_response.json", raw_response)
    artifacts.append("raw_response.json")

    write_json_file(snapshot_dir / "request_context.json", request_context)
    artifacts.append("request_context.json")

    if normalized_demand is not None:
        write_json_file(snapshot_dir / "normalized_demand.json", normalized_demand)
        artifacts.append("normalized_demand.json")

    if normalization_report is not None:
        write_json_file(snapshot_dir / "normalization_report.json", normalization_report)
        artifacts.append("normalization_report.json")

    if validation_report is not None:
        write_json_file(snapshot_dir / "validation_report.json", validation_report)
        artifacts.append("validation_report.json")

    if dq_report is not None:
        write_json_file(snapshot_dir / "dq_report.json", dq_report)
        artifacts.append("dq_report.json")

    if context_pack_text:
        write_text_file(snapshot_dir / "context_pack.txt", context_pack_text)
        artifacts.append("context_pack.txt")

    if compressed_candidates:
        write_json_file(
            snapshot_dir / "compressed_candidates.json",
            redact_snapshot_value(compressed_candidates),
        )
        artifacts.append("compressed_candidates.json")

        write_json_file(
            snapshot_dir / "drop_log.json",
            redact_snapshot_value(drop_log),
        )
        artifacts.append("drop_log.json")

        if lineage is not None:
            write_json_file(
                snapshot_dir / "lineage.json",
                redact_snapshot_value(lineage),
            )
            artifacts.append("lineage.json")

    return artifacts
