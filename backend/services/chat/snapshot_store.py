"""Snapshot persistence seam for chat artifacts.

Round-1 scope:
- build request-context / lineage / validation / dq payloads
- write snapshot artifacts and meta.json without changing file names or shape
- expose minimal snapshot-root / JSON-loading helpers for inspect CLIs
- serve as the stable snapshot patch point for service-level tests
"""
# backend/services/chat/snapshot_store.py
from __future__ import annotations

from backend.core.oplog import log_operation
from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.config import AISettings
from backend.services.chat.dq import DQReport
from backend.services.chat.gate import TextValidationReport
from backend.services.chat.provider_caller import (
    ProviderCallResult,
    ProviderDispatchError,
)
from backend.services.chat.snapshot_artifacts import (
    persist_snapshot_artifacts,
    read_json_file,
    write_json_file,
)
from backend.services.chat.snapshot_meta import (
    build_snapshot_meta_payload,
    update_snapshot_meta,
)
from backend.services.chat.snapshot_paths import snapshot_dir, snapshot_root
from backend.services.chat.snapshot_payloads import (
    build_candidate_lineage_categories,
    build_dq_payload,
    build_lineage_payload,
    build_raw_request_payload,
    build_raw_response_payload,
    build_request_context_payload,
    build_validation_payload,
)


def _write_ai_snapshot(
    *,
    settings: AISettings,
    request_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    client_request_id: str,
    latency_ms: int,
    ok: bool,
    error_type: str | None,
    messages: list[dict[str, str]],
    request_mode: str,
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    warnings: list[str],
    message_chars: int,
    history_turns: int,
    context_pack_text: str | None,
    compressed_candidates: dict[str, list[dict[str, object]]],
    drop_log: dict[str, dict[str, object]],
    validation_report: TextValidationReport | None = None,
    dq_report: DQReport | None = None,
    provider_result: ProviderCallResult | None = None,
    provider_error: OpenAICompatError | ProviderDispatchError | None = None,
) -> str:
    # Keep this module as the stable import surface for chat service/tests/ops; detailed snapshot logic lives in sibling helpers.
    snapshot_id = f"file:{request_id}"
    request_snapshot_dir = snapshot_dir(settings, request_id)
    request_snapshot_dir.mkdir(parents=True, exist_ok=True)

    raw_request = build_raw_request_payload(
        provider=provider,
        model=model,
        messages=messages,
        context_pack_hash=context_pack_hash,
        client_request_id=client_request_id,
        provider_result=provider_result,
        provider_error=provider_error,
    )
    raw_response_artifact = build_raw_response_payload(
        provider_result=provider_result,
        provider_error=provider_error,
    )
    request_context = build_request_context_payload(
        request_id=request_id,
        provider=provider,
        model=model,
        snapshot_id=snapshot_id,
        context_pack_hash=context_pack_hash,
        request_mode=request_mode,
        demand_source=demand_source,
        triggered_retrieval=triggered_retrieval,
        categories=list(categories),
        top_k=top_k,
        env=env,
        warnings=warnings,
        has_context_pack=bool(context_pack_text),
        message_chars=message_chars,
        history_turns=history_turns,
    )
    lineage = (
        build_lineage_payload(
            request_id=request_id,
            context_pack_hash=context_pack_hash,
            compressed_candidates=compressed_candidates,
        )
        if compressed_candidates
        else None
    )

    artifacts = persist_snapshot_artifacts(
        snapshot_dir=request_snapshot_dir,
        raw_request=raw_request,
        raw_response=raw_response_artifact.payload,
        request_context=request_context,
        validation_report=build_validation_payload(validation_report),
        dq_report=build_dq_payload(dq_report),
        context_pack_text=context_pack_text,
        compressed_candidates=compressed_candidates,
        drop_log=drop_log,
        lineage=lineage,
    )

    meta = build_snapshot_meta_payload(
        request_id=request_id,
        provider=provider,
        model=model,
        context_pack_hash=context_pack_hash,
        latency_ms=latency_ms,
        ok=ok,
        error_type=error_type,
        snapshot_id=snapshot_id,
        upstream_request_id=raw_response_artifact.upstream_request_id,
        status_code=raw_response_artifact.status_code,
        request_mode=request_mode,
        demand_source=demand_source,
        triggered_retrieval=triggered_retrieval,
        validation_report=validation_report,
        dq_report=dq_report,
        provider_error=provider_error,
        artifacts=artifacts,
    )

    write_json_file(request_snapshot_dir / "meta.json", meta)
    return snapshot_id


def persist_ai_snapshot(
    *,
    settings: AISettings,
    warnings: list[str],
    request_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    latency_ms: int,
    ok: bool,
    error_type: str | None,
    messages: list[dict[str, str]],
    request_mode: str,
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    message_chars: int,
    history_turns: int,
    context_pack_text: str | None,
    compressed_candidates: dict[str, list[dict[str, object]]],
    drop_log: dict[str, dict[str, object]],
    validation_report: TextValidationReport | None = None,
    dq_report: DQReport | None = None,
    provider_result: ProviderCallResult | None = None,
    provider_error: OpenAICompatError | ProviderDispatchError | None = None,
) -> str:
    try:
        return _write_ai_snapshot(
            settings=settings,
            request_id=request_id,
            provider=provider,
            model=model,
            context_pack_hash=context_pack_hash,
            client_request_id=request_id,
            latency_ms=latency_ms,
            ok=ok,
            error_type=error_type,
            messages=messages,
            request_mode=request_mode,
            demand_source=demand_source,
            triggered_retrieval=triggered_retrieval,
            categories=categories,
            top_k=top_k,
            env=env,
            warnings=warnings,
            message_chars=message_chars,
            history_turns=history_turns,
            context_pack_text=context_pack_text,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
            validation_report=validation_report,
            dq_report=dq_report,
            provider_result=provider_result,
            provider_error=provider_error,
        )
    except Exception as exc:
        if "ai_snapshot_write_failed" not in warnings:
            warnings.append("ai_snapshot_write_failed")
        log_operation(
            "snapshot_write_failed",
            request_id=request_id,
            provider=provider,
            model=model,
            context_pack_hash=context_pack_hash,
            error_type=type(exc).__name__,
        )
        return "-"


__all__ = [
    "build_candidate_lineage_categories",
    "persist_ai_snapshot",
    "read_json_file",
    "snapshot_dir",
    "snapshot_root",
    "update_snapshot_meta",
    "write_json_file",
]
