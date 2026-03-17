# backend/services/chat/snapshot_persistence.py
"""Snapshot write orchestration helpers.

Keep artifact payload building, artifact persistence, and meta writing bundled
here so ``snapshot_store`` can remain a thin stable facade for service/tests/ops.
"""

from __future__ import annotations

from backend.services.chat.chat_payload_context import ChatPayloadContext
from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.config import AISettings
from backend.services.chat.dq import DQReport
from backend.services.chat.gate import TextValidationReport
from backend.services.chat.provider_caller import (
    ProviderCallResult,
    ProviderDispatchError,
)
from backend.services.chat.snapshot_artifact_payloads import (
    build_dq_payload,
    build_snapshot_artifact_payloads,
    build_validation_payload,
)
from backend.services.chat.snapshot_artifacts import (
    persist_snapshot_artifacts,
    write_json_file,
)
from backend.services.chat.snapshot_meta import build_snapshot_meta_payload
from backend.services.chat.snapshot_paths import snapshot_dir


def write_ai_snapshot_bundle(
    *,
    settings: AISettings,
    context: ChatPayloadContext,
    latency_ms: int,
    ok: bool,
    error_type: str | None,
    messages: list[dict[str, str]],
    request_mode: str,
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
    snapshot_id = f"file:{context.request_id}"
    request_snapshot_dir = snapshot_dir(settings, context.request_id)
    request_snapshot_dir.mkdir(parents=True, exist_ok=True)

    artifact_payloads = build_snapshot_artifact_payloads(
        context=context,
        messages=messages,
        client_request_id=context.request_id,
        request_mode=request_mode,
        warnings=warnings,
        message_chars=message_chars,
        history_turns=history_turns,
        context_pack_text=context_pack_text,
        compressed_candidates=compressed_candidates,
        provider_result=provider_result,
        provider_error=provider_error,
    )

    artifacts = persist_snapshot_artifacts(
        snapshot_dir=request_snapshot_dir,
        raw_request=artifact_payloads.raw_request,
        raw_response=artifact_payloads.raw_response.payload,
        request_context=artifact_payloads.request_context,
        validation_report=build_validation_payload(validation_report),
        dq_report=build_dq_payload(dq_report),
        context_pack_text=context_pack_text,
        compressed_candidates=compressed_candidates,
        drop_log=drop_log,
        lineage=artifact_payloads.lineage,
    )

    meta = build_snapshot_meta_payload(
        context=context,
        latency_ms=latency_ms,
        ok=ok,
        error_type=error_type,
        snapshot_id=snapshot_id,
        upstream_request_id=artifact_payloads.raw_response.upstream_request_id,
        status_code=artifact_payloads.raw_response.status_code,
        request_mode=request_mode,
        validation_report=validation_report,
        dq_report=dq_report,
        provider_error=provider_error,
        artifacts=artifacts,
    )

    write_json_file(request_snapshot_dir / "meta.json", meta)
    return snapshot_id
