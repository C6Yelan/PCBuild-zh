# backend/services/chat/chat_payload_context.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.config import AISettings
from backend.services.chat.dq import DQReport
from backend.services.chat.gate import TextValidationReport
from backend.services.chat.provider_caller import (
    ProviderCallResult,
    ProviderDispatchError,
)


@dataclass(frozen=True)
class ChatPayloadContext:
    request_id: str
    provider: str
    model: str
    context_pack_hash: str
    demand_source: str
    triggered_retrieval: bool
    categories: list[str]
    top_k: int
    env: str


def build_snapshot_store_kwargs(
    *,
    settings: AISettings,
    warnings: list[str],
    context: ChatPayloadContext,
    messages: list[dict[str, str]],
    request_mode: str,
    message_chars: int,
    history_turns: int,
    context_pack_text: str | None,
    compressed_candidates: dict[str, list[dict[str, object]]],
    drop_log: dict[str, dict[str, object]],
    latency_ms: int,
    ok: bool,
    error_type: str,
    validation_report: TextValidationReport | None = None,
    dq_report: DQReport | None = None,
    provider_result: ProviderCallResult | None = None,
    provider_error: OpenAICompatError | ProviderDispatchError | None = None,
) -> dict[str, Any]:
    return {
        "settings": settings,
        "warnings": warnings,
        "context": context,
        "latency_ms": latency_ms,
        "ok": ok,
        "error_type": error_type,
        "messages": messages,
        "request_mode": request_mode,
        "message_chars": message_chars,
        "history_turns": history_turns,
        "context_pack_text": context_pack_text,
        "compressed_candidates": compressed_candidates,
        "drop_log": drop_log,
        "validation_report": validation_report,
        "dq_report": dq_report,
        "provider_result": provider_result,
        "provider_error": provider_error,
    }


def build_staging_persist_kwargs(
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
    publish_reason: str,
    error_type: str | None,
) -> dict[str, Any]:
    return {
        "settings": settings,
        "warnings": warnings,
        "context": context,
        "snapshot_id": snapshot_id,
        "normalized_text": normalized_text,
        "public_text": public_text,
        "latency_ms": latency_ms,
        "gate_status": gate_status,
        "dq_status": dq_status,
        "gate_reasons": gate_reasons,
        "dq_reasons": dq_reasons,
        "has_context_pack": has_context_pack,
        "compressed_candidates": compressed_candidates,
        "publish_reason": publish_reason,
        "error_type": error_type,
    }
