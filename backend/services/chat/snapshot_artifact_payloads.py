from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.services.chat.chat_payload_context import ChatPayloadContext
from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.dq import DQReport
from backend.services.chat.gate import TextValidationReport
from backend.services.chat.provider_caller import (
    ProviderCallResult,
    ProviderDispatchError,
)
from backend.services.chat.provider_exchange_payloads import (
    RawResponseArtifact,
    build_raw_request_payload,
    build_raw_response_payload,
)


@dataclass(frozen=True)
class SnapshotArtifactPayloads:
    raw_request: dict[str, Any]
    raw_response: RawResponseArtifact
    request_context: dict[str, Any]
    lineage: dict[str, Any] | None


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


def build_candidate_lineage_categories(
    compressed_candidates: dict[str, list[dict[str, object]]],
) -> dict[str, list[dict[str, Any]]]:
    def optional_str(value: object) -> str | None:
        if value is None:
            return None
        return str(value)

    categories: dict[str, list[dict[str, Any]]] = {}
    for category, items in compressed_candidates.items():
        category_items: list[dict[str, Any]] = []
        for item in items:
            category_items.append(
                {
                    "part_id": optional_str(item.get("part_id")),
                    "category": optional_str(item.get("category")) or category,
                    "display_name": optional_str(item.get("display_name")),
                    "source": optional_str(item.get("source")),
                    "source_url": optional_str(item.get("source_url")),
                    "snapshot_id": optional_str(item.get("snapshot_id")),
                    "run_id": optional_str(item.get("run_id")),
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
