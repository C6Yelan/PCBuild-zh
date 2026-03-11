# backend/services/chat/staging.py
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from backend.core.oplog import log_operation
from backend.services.chat.config import AISettings
from backend.services.chat.snapshot_store import (
    build_candidate_lineage_categories,
    snapshot_root,
    update_snapshot_meta,
    write_json_file,
)


@dataclass(slots=True)
class ChatStagingRecord:
    request_id: str
    snapshot_id: str
    provider: str
    model: str
    context_pack_hash: str
    normalized_text: str
    public_text: str
    latency_ms: int
    gate_status: str
    dq_status: str
    gate_reasons: list[str]
    dq_reasons: list[str]
    warnings: list[str]
    demand_source: str
    triggered_retrieval: bool
    categories: list[str]
    top_k: int
    env: str
    has_context_pack: bool
    data_versions: dict[str, list[dict[str, str | None]]]
    snapshot_dir: str
    created_at: str
    published: bool
    publish_blocked: bool
    publish_reason: str
    error_type: str | None = None


def persist_chat_staging_record(
    *,
    snapshot_root_dir: str | Path,
    snapshot_dir: str | Path,
    record: ChatStagingRecord,
) -> dict[str, object]:
    payload = asdict(record)
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
    payload = asdict(record)
    root_dir = Path(snapshot_root_dir)
    request_snapshot_dir = Path(snapshot_dir)
    request_id = record.request_id
    quarantine_dir = root_dir / "_quarantine"

    write_json_file(quarantine_dir / f"{request_id}.quarantine.json", payload)
    write_json_file(request_snapshot_dir / "quarantine_entry.json", payload)

    reasons = list(dict.fromkeys([*record.gate_reasons, *record.dq_reasons]))
    index_entry = {
        "request_id": record.request_id,
        "snapshot_id": record.snapshot_id,
        "provider": record.provider,
        "model": record.model,
        "error_type": record.error_type or "-",
        "gate_status": record.gate_status,
        "dq_status": record.dq_status,
        "reasons": reasons,
        "publish_reason": record.publish_reason,
        "created_at": record.created_at,
    }
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    with (quarantine_dir / "quarantine_index.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(index_entry, ensure_ascii=False, sort_keys=True))
        handle.write("\n")

    return payload


def build_chat_staging_record(
    *,
    request_id: str,
    snapshot_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    normalized_text: str,
    public_text: str,
    latency_ms: int,
    gate_status: str,
    dq_status: str,
    gate_reasons: list[str],
    dq_reasons: list[str],
    warnings: list[str],
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    has_context_pack: bool,
    compressed_candidates: dict[str, list[dict[str, object]]],
    snapshot_dir: str,
    published: bool,
    publish_blocked: bool,
    publish_reason: str,
    error_type: str | None,
) -> ChatStagingRecord:
    return ChatStagingRecord(
        request_id=request_id,
        snapshot_id=snapshot_id,
        provider=provider,
        model=model,
        context_pack_hash=context_pack_hash,
        normalized_text=normalized_text,
        public_text=public_text,
        latency_ms=latency_ms,
        gate_status=gate_status,
        dq_status=dq_status,
        gate_reasons=list(gate_reasons),
        dq_reasons=list(dq_reasons),
        warnings=list(warnings),
        demand_source=demand_source,
        triggered_retrieval=triggered_retrieval,
        categories=list(categories),
        top_k=top_k,
        env=env,
        has_context_pack=has_context_pack,
        data_versions=build_candidate_lineage_categories(compressed_candidates),
        snapshot_dir=snapshot_dir,
        created_at=datetime.now(timezone.utc).isoformat(),
        published=published,
        publish_blocked=publish_blocked,
        publish_reason=publish_reason,
        error_type=error_type,
    )


def persist_chat_stage_or_quarantine(
    *,
    settings: AISettings,
    warnings: list[str],
    request_id: str,
    snapshot_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    normalized_text: str,
    public_text: str,
    latency_ms: int,
    gate_status: str,
    dq_status: str,
    gate_reasons: list[str],
    dq_reasons: list[str],
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    has_context_pack: bool,
    compressed_candidates: dict[str, list[dict[str, object]]],
    publish_reason: str,
    error_type: str | None,
) -> None:
    if snapshot_id == "-":
        return

    root_dir = snapshot_root(settings)
    request_snapshot_dir = root_dir / request_id
    published = gate_status == "pass" and dq_status == "pass"
    record = build_chat_staging_record(
        request_id=request_id,
        snapshot_id=snapshot_id,
        provider=provider,
        model=model,
        context_pack_hash=context_pack_hash,
        normalized_text=normalized_text,
        public_text=public_text,
        latency_ms=latency_ms,
        gate_status=gate_status,
        dq_status=dq_status,
        gate_reasons=gate_reasons,
        dq_reasons=dq_reasons,
        warnings=warnings,
        demand_source=demand_source,
        triggered_retrieval=triggered_retrieval,
        categories=categories,
        top_k=top_k,
        env=env,
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
                request_id=request_id,
                staging_status="staged",
                quarantine_status="not_quarantined",
                artifact_name="staging_record.json",
            )
        except Exception as exc:
            if "staging_write_failed" not in warnings:
                warnings.append("staging_write_failed")
            log_operation(
                "chat_staging_write_failed",
                request_id=request_id,
                provider=provider,
                model=model,
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
            request_id=request_id,
            staging_status="skipped",
            quarantine_status="quarantined",
            artifact_name="quarantine_entry.json",
        )
    except Exception as exc:
        if "quarantine_write_failed" not in warnings:
            warnings.append("quarantine_write_failed")
        log_operation(
            "chat_quarantine_write_failed",
            request_id=request_id,
            provider=provider,
            model=model,
            error_type=type(exc).__name__,
        )
