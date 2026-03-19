# backend/services/chat/staging/payloads.py
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from backend.services.chat.payloads.context import ChatPayloadContext
from backend.services.chat.payloads.snapshot_artifacts import (
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
    normalization_source: str
    normalization_confidence: float | None
    normalized_request_mode: str
    normalized_categories: list[str]
    normalized_budget_max: int | None
    normalized_budget_target: int | None
    normalized_cpu_vendor: str | None
    normalized_gpu_vendor: str | None
    normalized_size_preference: str | None
    normalization_missing_information: list[str]
    normalization_fallback_used: bool
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


@dataclass(slots=True)
class ChatStagingRequestContext:
    request_id: str
    snapshot_id: str
    provider: str
    model: str
    context_pack_hash: str
    demand_source: str
    normalization_summary: dict[str, object]
    triggered_retrieval: bool
    categories: list[str]
    top_k: int
    env: str


@dataclass(slots=True)
class ChatStagingOutcome:
    normalized_text: str
    public_text: str
    latency_ms: int
    gate_status: str
    dq_status: str
    gate_reasons: list[str]
    dq_reasons: list[str]
    warnings: list[str]
    has_context_pack: bool
    published: bool
    publish_blocked: bool
    publish_reason: str
    error_type: str | None


@dataclass(slots=True)
class ChatStagingStorage:
    data_versions: dict[str, list[dict[str, str | None]]]
    snapshot_dir: str
    created_at: str


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
    request_context = ChatStagingRequestContext(
        request_id=context.request_id,
        snapshot_id=snapshot_id,
        provider=context.provider,
        model=context.model,
        context_pack_hash=context.context_pack_hash,
        demand_source=context.demand_source,
        normalization_summary=dict(context.normalization_summary),
        triggered_retrieval=context.triggered_retrieval,
        categories=list(context.categories),
        top_k=context.top_k,
        env=context.env,
    )
    outcome = ChatStagingOutcome(
        normalized_text=normalized_text,
        public_text=public_text,
        latency_ms=latency_ms,
        gate_status=gate_status,
        dq_status=dq_status,
        gate_reasons=list(gate_reasons),
        dq_reasons=list(dq_reasons),
        warnings=list(warnings),
        has_context_pack=has_context_pack,
        published=published,
        publish_blocked=publish_blocked,
        publish_reason=publish_reason,
        error_type=error_type,
    )
    storage = ChatStagingStorage(
        data_versions=build_candidate_lineage_categories(compressed_candidates),
        snapshot_dir=snapshot_dir,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    return ChatStagingRecord(
        request_id=request_context.request_id,
        snapshot_id=request_context.snapshot_id,
        provider=request_context.provider,
        model=request_context.model,
        context_pack_hash=request_context.context_pack_hash,
        normalized_text=outcome.normalized_text,
        public_text=outcome.public_text,
        latency_ms=outcome.latency_ms,
        gate_status=outcome.gate_status,
        dq_status=outcome.dq_status,
        gate_reasons=outcome.gate_reasons,
        dq_reasons=outcome.dq_reasons,
        warnings=outcome.warnings,
        demand_source=request_context.demand_source,
        normalization_source=str(request_context.normalization_summary.get("normalization_source", "-")),
        normalization_confidence=request_context.normalization_summary.get("normalization_confidence"),
        normalized_request_mode=str(request_context.normalization_summary.get("normalized_request_mode", "unknown")),
        normalized_categories=list(request_context.normalization_summary.get("normalized_categories", []) or []),
        normalized_budget_max=request_context.normalization_summary.get("normalized_budget_max"),
        normalized_budget_target=request_context.normalization_summary.get("normalized_budget_target"),
        normalized_cpu_vendor=request_context.normalization_summary.get("normalized_cpu_vendor"),
        normalized_gpu_vendor=request_context.normalization_summary.get("normalized_gpu_vendor"),
        normalized_size_preference=request_context.normalization_summary.get("normalized_size_preference"),
        normalization_missing_information=list(
            request_context.normalization_summary.get("normalization_missing_information", []) or []
        ),
        normalization_fallback_used=bool(
            request_context.normalization_summary.get("normalization_fallback_used", False)
        ),
        triggered_retrieval=request_context.triggered_retrieval,
        categories=request_context.categories,
        top_k=request_context.top_k,
        env=request_context.env,
        has_context_pack=outcome.has_context_pack,
        data_versions=storage.data_versions,
        snapshot_dir=storage.snapshot_dir,
        created_at=storage.created_at,
        published=outcome.published,
        publish_blocked=outcome.publish_blocked,
        publish_reason=outcome.publish_reason,
        error_type=outcome.error_type,
    )


__all__ = [
    "ChatStagingRecord",
    "build_chat_staging_record",
    "build_quarantine_index_entry",
    "build_staging_record_payload",
]
