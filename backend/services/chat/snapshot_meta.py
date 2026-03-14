# backend/services/chat/snapshot_meta.py
"""Meta payload and updater helpers for chat snapshot artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.services.chat.config import AISettings
from backend.services.chat.dq import DQReport
from backend.services.chat.gate import TextValidationReport
from backend.services.chat.chat_payload_context import ChatPayloadContext
from backend.services.chat.snapshot_artifacts import read_json_file, write_json_file
from backend.services.chat.snapshot_paths import snapshot_dir


def build_snapshot_meta_payload(
    *,
    context: ChatPayloadContext,
    latency_ms: int,
    ok: bool,
    error_type: str | None,
    snapshot_id: str,
    upstream_request_id: str | None,
    status_code: int | None,
    request_mode: str,
    validation_report: TextValidationReport | None,
    dq_report: DQReport | None,
    provider_error: Any,
    artifacts: list[str],
) -> dict[str, Any]:
    return {
        "request_id": context.request_id,
        "provider": context.provider,
        "model": context.model,
        "context_pack_hash": context.context_pack_hash,
        "latency_ms": latency_ms,
        "ok": ok,
        "error_type": error_type or "-",
        "snapshot_id": snapshot_id,
        "upstream_request_id": upstream_request_id,
        "status_code": status_code,
        "request_mode": request_mode,
        "demand_source": context.demand_source,
        "triggered_retrieval": context.triggered_retrieval,
        "gate_status": (
            "pass"
            if validation_report is None or validation_report.passed
            else "fail"
        ),
        "gate_reasons": list(validation_report.reasons) if validation_report else [],
        "dq_status": (
            "skipped"
            if dq_report is None
            else "pass"
            if dq_report.passed
            else "fail"
        ),
        "dq_reasons": list(dq_report.reasons) if dq_report else [],
        "staging_status": "skipped",
        "quarantine_status": (
            "not_applicable" if provider_error is not None else "not_quarantined"
        ),
        "artifacts": [*artifacts, "meta.json"],
    }


def update_snapshot_meta(
    *,
    settings: AISettings,
    request_id: str,
    staging_status: str,
    quarantine_status: str,
    artifact_name: str | None = None,
) -> None:
    meta_path = snapshot_dir(settings, request_id) / "meta.json"
    if not meta_path.is_file():
        return

    meta = read_json_file(meta_path)
    meta["staging_status"] = staging_status
    meta["quarantine_status"] = quarantine_status

    artifacts = list(meta.get("artifacts", []))
    if artifact_name and artifact_name not in artifacts:
        if "meta.json" in artifacts:
            artifacts.insert(artifacts.index("meta.json"), artifact_name)
        else:
            artifacts.append(artifact_name)
    meta["artifacts"] = artifacts
    write_json_file(meta_path, meta)
