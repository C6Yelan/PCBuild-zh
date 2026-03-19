# backend/services/chat/staging/__init__.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.core.oplog import log_operation
from backend.services.chat.config import AISettings
from backend.services.chat.payloads.context import ChatPayloadContext
from backend.services.chat.snapshot_artifacts import write_json_file
from backend.services.chat.snapshot_meta import update_snapshot_meta
from backend.services.chat.snapshot_paths import snapshot_root
from .payloads import (
    ChatStagingRecord,
    build_chat_staging_record,
    build_quarantine_index_entry,
    build_staging_record_payload,
)


def persist_chat_staging_record(
    *,
    snapshot_root_dir: str | Path,
    snapshot_dir: str | Path,
    record: ChatStagingRecord,
) -> dict[str, object]:
    payload = build_staging_record_payload(record)
    root_dir = Path(snapshot_root_dir)
    request_snapshot_dir = Path(snapshot_dir)
    request_id = record.request_id

    write_json_file(root_dir / "_staging" / f"{request_id}.staging.json", payload)
    write_json_file(request_snapshot_dir / "staging_record.json", payload)
    return payload


def persist_chat_quarantine_entry(
    *,
    snapshot_root_dir: str | Path,
    snapshot_dir: str | Path,
    record: ChatStagingRecord,
) -> dict[str, object]:
    payload = build_staging_record_payload(record)
    root_dir = Path(snapshot_root_dir)
    request_snapshot_dir = Path(snapshot_dir)
    request_id = record.request_id
    quarantine_dir = root_dir / "_quarantine"

    write_json_file(quarantine_dir / f"{request_id}.quarantine.json", payload)
    write_json_file(request_snapshot_dir / "quarantine_entry.json", payload)

    index_entry = build_quarantine_index_entry(record)
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    with (quarantine_dir / "quarantine_index.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(index_entry, ensure_ascii=False, sort_keys=True))
        handle.write("\n")

    return payload


def persist_chat_stage_or_quarantine(
    *,
    settings: AISettings,
    warnings: list[str],
    context: ChatPayloadContext,
    snapshot_id: str,
    normalized_text: str,
    public_text: str,
    latency_ms: int,
    gate_status: str,
    dq_status: str,
    gate_reasons: list[str],
    dq_reasons: list[str],
    has_context_pack: bool,
    compressed_candidates: dict[str, list[dict[str, object]]],
    normalized_demand: dict[str, Any],
    normalization_report: dict[str, Any],
    publish_reason: str,
    error_type: str | None,
) -> None:
    if snapshot_id == "-":
        return

    root_dir = snapshot_root(settings)
    request_snapshot_dir = root_dir / context.request_id
    published = gate_status == "pass" and dq_status == "pass"
    record = build_chat_staging_record(
        context=context,
        snapshot_id=snapshot_id,
        normalized_text=normalized_text,
        public_text=public_text,
        latency_ms=latency_ms,
        gate_status=gate_status,
        dq_status=dq_status,
        gate_reasons=gate_reasons,
        dq_reasons=dq_reasons,
        warnings=warnings,
        has_context_pack=has_context_pack,
        compressed_candidates=compressed_candidates,
        snapshot_dir=str(request_snapshot_dir),
        published=published,
        publish_blocked=not published,
        publish_reason=publish_reason,
        error_type=error_type,
    )

    if published:
        try:
            persist_chat_staging_record(
                snapshot_root_dir=root_dir,
                snapshot_dir=request_snapshot_dir,
                record=record,
            )
            update_snapshot_meta(
                settings=settings,
                request_id=context.request_id,
                staging_status="staged",
                quarantine_status="not_quarantined",
                artifact_name="staging_record.json",
            )
        except Exception as exc:
            if "staging_write_failed" not in warnings:
                warnings.append("staging_write_failed")
            log_operation(
                "chat_staging_write_failed",
                request_id=context.request_id,
                provider=context.provider,
                model=context.model,
                error_type=type(exc).__name__,
            )
        return

    try:
        persist_chat_quarantine_entry(
            snapshot_root_dir=root_dir,
            snapshot_dir=request_snapshot_dir,
            record=record,
        )
        update_snapshot_meta(
            settings=settings,
            request_id=context.request_id,
            staging_status="skipped",
            quarantine_status="quarantined",
            artifact_name="quarantine_entry.json",
        )
    except Exception as exc:
        if "quarantine_write_failed" not in warnings:
            warnings.append("quarantine_write_failed")
        log_operation(
            "chat_quarantine_write_failed",
            request_id=context.request_id,
            provider=context.provider,
            model=context.model,
            error_type=type(exc).__name__,
        )


__all__ = [
    "ChatStagingRecord",
    "build_chat_staging_record",
    "build_quarantine_index_entry",
    "build_staging_record_payload",
    "persist_chat_quarantine_entry",
    "persist_chat_stage_or_quarantine",
    "persist_chat_staging_record",
]
