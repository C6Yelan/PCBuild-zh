# backend/services/chat/service/response.py
"""Response and logging helpers for chat orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from backend.services.chat.contracts import ChatResponse


@dataclass(slots=True)
class PublishedChatResult:
    text: str
    error_type: str | None
    ok: bool
    publish_reason: str


def truncate_output_text(text: str, *, max_chars: int, warnings: list[str]) -> str:
    if len(text) <= max_chars:
        return text
    warnings.append("output_truncated")
    return text[:max_chars]


def _with_request_id(message: str, request_id: str) -> str:
    return f"{message}request_id={request_id}"


def publish_chat_response(
    *,
    request_id: str,
    staged_public_text: str | None = None,
    error_type: str | None = None,
    provider_fallback_text: str | None = None,
) -> PublishedChatResult:
    if error_type is None:
        return PublishedChatResult(
            text=staged_public_text or "",
            error_type=None,
            ok=True,
            publish_reason="staged_pass",
        )

    if error_type == "validation_failed":
        return PublishedChatResult(
            text=_with_request_id("目前 AI 回覆格式異常，請稍後再試。", request_id),
            error_type=error_type,
            ok=False,
            publish_reason="validation_failed",
        )

    if error_type == "dq_failed":
        return PublishedChatResult(
            text=_with_request_id("目前資料不足，請補充需求後再試。", request_id),
            error_type=error_type,
            ok=False,
            publish_reason="dq_failed",
        )

    return PublishedChatResult(
        text=_with_request_id(
            provider_fallback_text or "目前 AI 服務暫時不可用，請稍後再試。",
            request_id,
        ),
        error_type=error_type,
        ok=False,
        publish_reason="provider_error",
    )


def provider_error_fallback_text(error_type: str) -> str:
    if error_type == "provider_not_ready":
        return "目前 AI 服務提供者尚未啟用，請稍後再試。"
    return "目前 AI 服務暫時不可用，請稍後再試。"


def log_ai_call(
    *,
    log_operation: Callable[..., Any],
    request_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    snapshot_id: str,
    latency_ms: int,
    ok: bool,
    error_type: str | None = None,
    gate_status: str,
    dq_status: str,
    staging_status: str,
    quarantine_status: str,
    warning_count: int,
    demand_source: str,
    triggered_retrieval: bool,
    normalization_summary: dict[str, Any] | None = None,
) -> None:
    summary = dict(normalization_summary or {})
    log_operation(
        "ai_call",
        request_id=request_id,
        provider=provider,
        model=model,
        context_pack_hash=context_pack_hash,
        snapshot_id=snapshot_id,
        latency_ms=latency_ms,
        ok=ok,
        error_type=error_type or "-",
        gate_status=gate_status,
        dq_status=dq_status,
        staging_status=staging_status,
        quarantine_status=quarantine_status,
        warning_count=warning_count,
        demand_source=demand_source,
        triggered_retrieval=triggered_retrieval,
        normalization_source=summary.get("normalization_source", "-"),
        normalization_confidence=summary.get("normalization_confidence"),
        normalized_request_mode=summary.get("normalized_request_mode", "unknown"),
        normalized_categories=",".join(summary.get("normalized_categories", []) or []) or "-",
        normalized_budget_max=summary.get("normalized_budget_max"),
        normalized_budget_target=summary.get("normalized_budget_target"),
        normalized_cpu_vendor=summary.get("normalized_cpu_vendor", "-") or "-",
        normalized_gpu_vendor=summary.get("normalized_gpu_vendor", "-") or "-",
        normalized_size_preference=summary.get("normalized_size_preference", "-") or "-",
        normalization_missing_information=",".join(summary.get("normalization_missing_information", []) or [])
        or "-",
        normalization_fallback_used=bool(summary.get("normalization_fallback_used", False)),
    )


def build_chat_response(
    *,
    request_id: str,
    provider: str,
    model: str,
    text: str,
    latency_ms: int,
    error_type: str | None,
    warnings: list[str],
    compressed_candidates: dict[str, list[dict[str, object]]],
    drop_log: dict[str, dict[str, object]],
) -> ChatResponse:
    return ChatResponse(
        request_id=request_id,
        provider=provider,
        model=model,
        text=text,
        latency_ms=latency_ms,
        error_type=error_type,
        warnings=warnings or None,
        compressed_candidates=compressed_candidates,
        drop_log=drop_log,
    )


__all__ = [
    "PublishedChatResult",
    "build_chat_response",
    "log_ai_call",
    "provider_error_fallback_text",
    "publish_chat_response",
    "truncate_output_text",
]
