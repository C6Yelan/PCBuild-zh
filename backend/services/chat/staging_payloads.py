# backend/services/chat/staging_payloads.py
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from backend.services.chat.chat_payload_context import ChatPayloadContext
from backend.services.chat.snapshot_artifact_payloads import (
    build_candidate_lineage_categories,
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


def build_staging_record_payload(record: ChatStagingRecord) -> dict[str, object]:
    return asdict(record)


def build_quarantine_index_entry(record: ChatStagingRecord) -> dict[str, object]:
    reasons = list(dict.fromkeys([*record.gate_reasons, *record.dq_reasons]))
    return {
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


def build_chat_staging_record(
    *,
    context: ChatPayloadContext,
    snapshot_id: str,
    normalized_text: str,
    public_text: str,
    latency_ms: int,
    gate_status: str,
    dq_status: str,
    gate_reasons: list[str],
    dq_reasons: list[str],
    warnings: list[str],
    has_context_pack: bool,
    compressed_candidates: dict[str, list[dict[str, object]]],
    snapshot_dir: str,
    published: bool,
    publish_blocked: bool,
    publish_reason: str,
    error_type: str | None,
) -> ChatStagingRecord:
    return ChatStagingRecord(
        request_id=context.request_id,
        snapshot_id=snapshot_id,
        provider=context.provider,
        model=context.model,
        context_pack_hash=context.context_pack_hash,
        normalized_text=normalized_text,
        public_text=public_text,
        latency_ms=latency_ms,
        gate_status=gate_status,
        dq_status=dq_status,
        gate_reasons=list(gate_reasons),
        dq_reasons=list(dq_reasons),
        warnings=list(warnings),
        demand_source=context.demand_source,
        triggered_retrieval=context.triggered_retrieval,
        categories=list(context.categories),
        top_k=context.top_k,
        env=context.env,
        has_context_pack=has_context_pack,
        data_versions=build_candidate_lineage_categories(compressed_candidates),
        snapshot_dir=snapshot_dir,
        created_at=datetime.now(timezone.utc).isoformat(),
        published=published,
        publish_blocked=publish_blocked,
        publish_reason=publish_reason,
        error_type=error_type,
    )
