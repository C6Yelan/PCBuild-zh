# backend/services/chat/snapshot_payloads.py
"""Payload builders for chat snapshot request, lineage, validation, and DQ artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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


def build_request_context_payload(
    *,
    request_id: str,
    provider: str,
    model: str,
    snapshot_id: str,
    context_pack_hash: str,
    request_mode: str,
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    warnings: list[str],
    has_context_pack: bool,
    message_chars: int,
    history_turns: int,
) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "provider": provider,
        "model": model,
        "snapshot_id": snapshot_id,
        "context_pack_hash": context_pack_hash,
        "request_mode": request_mode,
        "demand_source": demand_source,
        "triggered_retrieval": triggered_retrieval,
        "categories": categories,
        "top_k": top_k,
        "env": env,
        "warnings": list(warnings),
        "has_context_pack": has_context_pack,
        "message_chars": message_chars,
        "history_turns": history_turns,
    }


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
    request_id: str,
    context_pack_hash: str,
    compressed_candidates: dict[str, list[dict[str, object]]],
) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "context_pack_hash": context_pack_hash,
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
    provider: str,
    model: str,
    messages: list[dict[str, str]],
    context_pack_hash: str,
    client_request_id: str,
    provider_result: ProviderCallResult | None,
    provider_error: OpenAICompatError | ProviderDispatchError | None,
) -> dict[str, Any]:
    endpoint = provider_result.endpoint if provider_result else provider_error.endpoint if provider_error else "-"
    request_headers = (
        provider_result.request_headers
        if provider_result
        else {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Client-Request-Id": client_request_id,
        }
    )
    request_json = (
        provider_result.request_json
        if provider_result
        else provider_error.request_json if provider_error else {"model": model, "messages": messages}
    )
    return {
        "provider": provider,
        "model": model,
        "messages": messages,
        "context_pack_hash": context_pack_hash,
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
    response_headers = (
        provider_result.response_headers
        if provider_result
        else provider_error.response_headers if provider_error else {}
    )
    response_json = (
        provider_result.response_json
        if provider_result
        else provider_error.response_json if provider_error else None
    )
    raw_response_text = (
        provider_result.raw_response_text
        if provider_result
        else provider_error.raw_response_text if provider_error else ""
    )
    upstream_request_id = (
        provider_result.upstream_request_id
        if provider_result
        else provider_error.upstream_request_id if provider_error else None
    )
    status_code = (
        provider_result.status_code
        if provider_result
        else provider_error.status_code if provider_error else None
    )
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
