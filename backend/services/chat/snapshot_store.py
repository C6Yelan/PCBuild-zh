# backend/services/chat/snapshot_store.py
"""Snapshot persistence seam for chat artifacts.

Round-1 scope:
- build request-context / lineage / validation / dq payloads
- write snapshot artifacts and meta.json without changing file names or shape
- expose minimal snapshot-root / JSON-loading helpers for inspect CLIs
- serve as the stable snapshot patch point for service-level tests
"""
from __future__ import annotations

from backend.core.oplog import log_operation
from backend.services.chat.chat_payload_context import ChatPayloadContext
from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.config import AISettings
from backend.services.chat.dq import DQReport
from backend.services.chat.gate import TextValidationReport
from backend.services.chat.provider_caller import (
    ProviderCallResult,
    ProviderDispatchError,
)
from backend.services.chat.snapshot_artifacts import read_json_file, write_json_file
from backend.services.chat.snapshot_meta import (
    update_snapshot_meta,
)
from backend.services.chat.snapshot_paths import snapshot_dir, snapshot_root
from backend.services.chat.snapshot_persistence import write_ai_snapshot_bundle


def persist_ai_snapshot(
    *,
    settings: AISettings,
    warnings: list[str],
    context: ChatPayloadContext,
    latency_ms: int,
    ok: bool,
    error_type: str | None,
    messages: list[dict[str, str]],
    request_mode: str,
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
        return write_ai_snapshot_bundle(
            settings=settings,
            context=context,
            latency_ms=latency_ms,
            ok=ok,
            error_type=error_type,
            messages=messages,
            request_mode=request_mode,
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
            request_id=context.request_id,
            provider=context.provider,
            model=context.model,
            context_pack_hash=context.context_pack_hash,
            error_type=type(exc).__name__,
        )
        return "-"


__all__ = [
    "persist_ai_snapshot",
    "read_json_file",
    "snapshot_dir",
    "snapshot_root",
    "update_snapshot_meta",
    "write_json_file",
]
