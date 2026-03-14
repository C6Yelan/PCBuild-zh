# backend/services/chat/snapshot_payloads.py
"""Payload builders for chat snapshot request, lineage, validation, and DQ artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.services.chat.config import AISettings
from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.dq import DQReport
from backend.services.chat.gate import TextValidationReport
from backend.services.chat.provider_caller import (
    ProviderCallResult,
    ProviderDispatchError,
)

from backend.services.chat.snapshot_redaction import redact_snapshot_value


@dataclass(frozen=True)
class RawResponseArtifact:
    payload: dict[str, Any]
    upstream_request_id: str | None
    status_code: int | None


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


@dataclass(frozen=True)
class ProviderExchangePayload:
    endpoint: str
    request_headers: dict[str, Any]
    request_json: dict[str, Any]
    response_headers: dict[str, Any]
    response_json: dict[str, Any] | None
    raw_response_text: str
    upstream_request_id: str | None
    status_code: int | None


@dataclass(frozen=True)
class SnapshotArtifactPayloads:
    raw_request: dict[str, Any]
    raw_response: RawResponseArtifact
    request_context: dict[str, Any]
    lineage: dict[str, Any] | None


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


def build_request_context_payload(
    *,
    context: ChatPayloadContext,
    snapshot_id: str,
    request_mode: str,
    warnings: list[str],
    has_context_pack: bool,
    message_chars: int,
    history_turns: int,
) -> dict[str, Any]:
    return {
        "request_id": context.request_id,
        "provider": context.provider,
        "model": context.model,
        "snapshot_id": snapshot_id,
        "context_pack_hash": context.context_pack_hash,
        "request_mode": request_mode,
        "demand_source": context.demand_source,
        "triggered_retrieval": context.triggered_retrieval,
        "categories": list(context.categories),
        "top_k": context.top_k,
        "env": context.env,
        "warnings": list(warnings),
        "has_context_pack": has_context_pack,
        "message_chars": message_chars,
        "history_turns": history_turns,
    }


def build_snapshot_artifact_payloads(
    *,
    context: ChatPayloadContext,
    messages: list[dict[str, str]],
    client_request_id: str,
    request_mode: str,
    warnings: list[str],
    message_chars: int,
    history_turns: int,
    context_pack_text: str | None,
    compressed_candidates: dict[str, list[dict[str, object]]],
    provider_result: ProviderCallResult | None,
    provider_error: OpenAICompatError | ProviderDispatchError | None,
) -> SnapshotArtifactPayloads:
    return SnapshotArtifactPayloads(
        raw_request=build_raw_request_payload(
            context=context,
            messages=messages,
            client_request_id=client_request_id,
            provider_result=provider_result,
            provider_error=provider_error,
        ),
        raw_response=build_raw_response_payload(
            provider_result=provider_result,
            provider_error=provider_error,
        ),
        request_context=build_request_context_payload(
            context=context,
            snapshot_id=f"file:{context.request_id}",
            request_mode=request_mode,
            warnings=warnings,
            has_context_pack=bool(context_pack_text),
            message_chars=message_chars,
            history_turns=history_turns,
        ),
        lineage=(
            build_lineage_payload(
                context=context,
                compressed_candidates=compressed_candidates,
            )
            if compressed_candidates
            else None
        ),
    )


def build_candidate_lineage_categories(
    compressed_candidates: dict[str, list[dict[str, object]]],
) -> dict[str, list[dict[str, Any]]]:
    def _optional_str(value: object) -> str | None:
        if value is None:
            return None
        return str(value)

    categories: dict[str, list[dict[str, Any]]] = {}
    for category, items in compressed_candidates.items():
        category_items: list[dict[str, Any]] = []
        for item in items:
            category_items.append(
                {
                    "part_id": _optional_str(item.get("part_id")),
                    "category": _optional_str(item.get("category")) or category,
                    "display_name": _optional_str(item.get("display_name")),
                    "source": _optional_str(item.get("source")),
                    "source_url": _optional_str(item.get("source_url")),
                    "snapshot_id": _optional_str(item.get("snapshot_id")),
                    "run_id": _optional_str(item.get("run_id")),
                }
            )
        categories[category] = category_items
    return categories


def build_lineage_payload(
    *,
    context: ChatPayloadContext,
    compressed_candidates: dict[str, list[dict[str, object]]],
) -> dict[str, Any]:
    return {
        "request_id": context.request_id,
        "context_pack_hash": context.context_pack_hash,
        "categories": build_candidate_lineage_categories(compressed_candidates),
    }


def build_validation_payload(
    validation_report: TextValidationReport | None,
) -> dict[str, Any] | None:
    if validation_report is None:
        return None
    return {
        "passed": validation_report.passed,
        "reasons": list(validation_report.reasons),
        "warnings": list(validation_report.warnings),
        "removed_chars_count": validation_report.removed_chars_count,
        "max_chars": validation_report.max_chars,
        "original_length": validation_report.original_length,
        "sanitized_length": validation_report.sanitized_length,
    }


def build_dq_payload(dq_report: DQReport | None) -> dict[str, Any] | None:
    if dq_report is None:
        return None
    return {
        "passed": dq_report.passed,
        "reasons": list(dq_report.reasons),
        "warnings": list(dq_report.warnings),
        "metrics": dict(dq_report.metrics),
        "quarantine": dq_report.quarantine,
    }


def build_raw_request_payload(
    *,
    context: ChatPayloadContext,
    messages: list[dict[str, str]],
    client_request_id: str,
    provider_result: ProviderCallResult | None,
    provider_error: OpenAICompatError | ProviderDispatchError | None,
) -> dict[str, Any]:
    exchange = build_provider_exchange_payload(
        model=context.model,
        messages=messages,
        client_request_id=client_request_id,
        provider_result=provider_result,
        provider_error=provider_error,
    )
    endpoint = exchange.endpoint
    request_headers = exchange.request_headers
    request_json = exchange.request_json
    return {
        "provider": context.provider,
        "model": context.model,
        "messages": messages,
        "context_pack_hash": context.context_pack_hash,
        "endpoint": endpoint or "-",
        "client_request_id": client_request_id,
        "request_headers": redact_snapshot_value(request_headers),
        "request_json": redact_snapshot_value(request_json),
    }


def build_raw_response_payload(
    *,
    provider_result: ProviderCallResult | None,
    provider_error: OpenAICompatError | ProviderDispatchError | None,
) -> RawResponseArtifact:
    exchange = build_provider_exchange_payload(
        model="-",
        messages=[],
        client_request_id="-",
        provider_result=provider_result,
        provider_error=provider_error,
    )
    response_headers = exchange.response_headers
    response_json = exchange.response_json
    raw_response_text = exchange.raw_response_text
    upstream_request_id = exchange.upstream_request_id
    status_code = exchange.status_code
    return RawResponseArtifact(
        payload={
            "status_code": status_code,
            "response_headers": redact_snapshot_value(response_headers),
            "response_json": redact_snapshot_value(response_json),
            "raw_response_text": redact_snapshot_value(raw_response_text),
            "upstream_request_id": upstream_request_id,
        },
        upstream_request_id=upstream_request_id,
        status_code=status_code,
    )


def build_provider_exchange_payload(
    *,
    model: str,
    messages: list[dict[str, str]],
    client_request_id: str,
    provider_result: ProviderCallResult | None,
    provider_error: OpenAICompatError | ProviderDispatchError | None,
) -> ProviderExchangePayload:
    default_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Client-Request-Id": client_request_id,
    }
    if provider_result is not None:
        return ProviderExchangePayload(
            endpoint=provider_result.endpoint,
            request_headers=provider_result.request_headers,
            request_json=provider_result.request_json,
            response_headers=provider_result.response_headers,
            response_json=provider_result.response_json,
            raw_response_text=provider_result.raw_response_text,
            upstream_request_id=provider_result.upstream_request_id,
            status_code=provider_result.status_code,
        )
    if provider_error is not None:
        return ProviderExchangePayload(
            endpoint=provider_error.endpoint,
            request_headers=default_headers,
            request_json=provider_error.request_json or {"model": model, "messages": messages},
            response_headers=provider_error.response_headers,
            response_json=provider_error.response_json,
            raw_response_text=provider_error.raw_response_text,
            upstream_request_id=provider_error.upstream_request_id,
            status_code=provider_error.status_code,
        )
    return ProviderExchangePayload(
        endpoint="-",
        request_headers=default_headers,
        request_json={"model": model, "messages": messages},
        response_headers={},
        response_json=None,
        raw_response_text="",
        upstream_request_id=None,
        status_code=None,
    )
