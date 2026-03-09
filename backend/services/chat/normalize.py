# backend/services/chat/normalize.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.services.chat.config import OPENAI_COMPAT_PROVIDERS


@dataclass(slots=True)
class NormalizedAIResponse:
    request_id: str
    provider: str
    model: str
    text: str
    latency_ms: int
    warnings: list[str]
    upstream_request_id: str | None
    status_code: int | None
    finish_reason: str | None
    usage: dict[str, int] | None


def _append_warning(warnings: list[str], warning: str) -> None:
    if warning not in warnings:
        warnings.append(warning)


def _normalize_openai_compat_success(
    *,
    provider: str,
    model: str,
    request_id: str,
    latency_ms: int,
    provider_result: object,
    warnings: list[str],
) -> NormalizedAIResponse:
    usage = getattr(provider_result, "usage", None)
    if not isinstance(usage, dict) or not usage:
        usage = None
        _append_warning(warnings, "usage_unavailable")

    finish_reason = getattr(provider_result, "finish_reason", None)
    if finish_reason == "length":
        _append_warning(warnings, "provider_finish_reason_length")
    elif finish_reason == "content_filter":
        _append_warning(warnings, "provider_finish_reason_content_filter")

    return NormalizedAIResponse(
        request_id=request_id,
        provider=provider,
        model=model,
        text=str(getattr(provider_result, "text", "")),
        latency_ms=latency_ms,
        warnings=list(warnings),
        upstream_request_id=getattr(provider_result, "upstream_request_id", None),
        status_code=getattr(provider_result, "status_code", None),
        finish_reason=finish_reason if isinstance(finish_reason, str) else None,
        usage=usage,
    )


def normalize_provider_success(
    *,
    provider: str,
    model: str,
    request_id: str,
    latency_ms: int,
    provider_result: object,
    warnings: list[str],
) -> NormalizedAIResponse:
    if provider in OPENAI_COMPAT_PROVIDERS:
        return _normalize_openai_compat_success(
            provider=provider,
            model=model,
            request_id=request_id,
            latency_ms=latency_ms,
            provider_result=provider_result,
            warnings=warnings,
        )

    return NormalizedAIResponse(
        request_id=request_id,
        provider=provider,
        model=model,
        text=str(getattr(provider_result, "text", "")),
        latency_ms=latency_ms,
        warnings=list(warnings),
        upstream_request_id=getattr(provider_result, "upstream_request_id", None),
        status_code=getattr(provider_result, "status_code", None),
        finish_reason=None,
        usage=None,
    )
