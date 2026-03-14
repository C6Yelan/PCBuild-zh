# backend/services/chat/service_state.py
"""Shared orchestration-state helpers for chat service side effects."""

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
from backend.services.chat.service_demand import DemandResolution
from backend.services.chat.service_retrieval import RetrievalArtifacts
from backend.services.chat.snapshot_payloads import (
    ChatPayloadContext,
    build_snapshot_store_kwargs,
    build_staging_persist_kwargs,
)


@dataclass(slots=True)
class ChatOrchestrationState:
    settings: Any
    request_id: str
    warnings: list[str]
    demand: DemandResolution
    retrieval: RetrievalArtifacts
    triggered_retrieval: bool
    provider_messages: list[dict[str, str]]

    def payload_context(self) -> ChatPayloadContext:
        return ChatPayloadContext(
            request_id=self.request_id,
            provider=self.settings.ai_provider,
            model=self.settings.ai_model,
            context_pack_hash=self.retrieval.context_pack_hash,
            demand_source=self.demand.source,
            triggered_retrieval=self.triggered_retrieval,
            categories=list(self.demand.categories),
            top_k=self.demand.top_k,
            env=self.demand.env,
        )

    def snapshot_kwargs(
        self,
        *,
        latency_ms: int,
        ok: bool,
        error_type: str,
        validation_report: TextValidationReport | None = None,
        dq_report: DQReport | None = None,
        provider_result: ProviderCallResult | None = None,
        provider_error: OpenAICompatError | ProviderDispatchError | None = None,
    ) -> dict[str, Any]:
        return build_snapshot_store_kwargs(
            settings=self.settings,
            warnings=self.warnings,
            context=self.payload_context(),
            messages=self.provider_messages,
            request_mode=self.demand.request_mode,
            message_chars=self.demand.message_chars,
            history_turns=self.demand.history_turns,
            context_pack_text=self.retrieval.context_pack_text,
            compressed_candidates=self.retrieval.compressed_candidates,
            drop_log=self.retrieval.drop_log,
            latency_ms=latency_ms,
            ok=ok,
            error_type=error_type,
            validation_report=validation_report,
            dq_report=dq_report,
            provider_result=provider_result,
            provider_error=provider_error,
        )

    def staging_kwargs(
        self,
        *,
        snapshot_id: str,
        normalized_text: str,
        public_text: str,
        latency_ms: int,
        gate_status: str,
        dq_status: str,
        gate_reasons: list[str],
        dq_reasons: list[str],
        publish_reason: str,
        error_type: str | None,
    ) -> dict[str, Any]:
        return build_staging_persist_kwargs(
            settings=self.settings,
            warnings=self.warnings,
            context=self.payload_context(),
            snapshot_id=snapshot_id,
            normalized_text=normalized_text,
            public_text=public_text,
            latency_ms=latency_ms,
            gate_status=gate_status,
            dq_status=dq_status,
            gate_reasons=gate_reasons,
            dq_reasons=dq_reasons,
            has_context_pack=bool(self.retrieval.context_pack_text),
            compressed_candidates=self.retrieval.compressed_candidates,
            publish_reason=publish_reason,
            error_type=error_type,
        )

    def ai_call_kwargs(
        self,
        *,
        snapshot_id: str,
        latency_ms: int,
        ok: bool,
        error_type: str,
        gate_status: str,
        dq_status: str,
        staging_status: str,
        quarantine_status: str,
    ) -> dict[str, Any]:
        context = self.payload_context()
        return {
            "request_id": context.request_id,
            "provider": context.provider,
            "model": context.model,
            "context_pack_hash": context.context_pack_hash,
            "snapshot_id": snapshot_id,
            "latency_ms": latency_ms,
            "ok": ok,
            "error_type": error_type,
            "gate_status": gate_status,
            "dq_status": dq_status,
            "staging_status": staging_status,
            "quarantine_status": quarantine_status,
            "warning_count": len(self.warnings),
            "demand_source": context.demand_source,
            "triggered_retrieval": context.triggered_retrieval,
        }
