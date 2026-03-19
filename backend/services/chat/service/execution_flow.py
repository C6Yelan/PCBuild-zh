# backend/services/chat/service/execution_flow.py
from __future__ import annotations

from time import perf_counter

from sqlalchemy.orm import Session

from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.contracts import ChatRequest, ChatResponse
from backend.services.chat.provider_caller import (
    ProviderCallResult,
    ProviderDispatchError,
)
from .retrieval import RetrievalArtifacts
from .seams import ChatServiceSeams
from .state import ChatOrchestrationState


def elapsed_latency_ms(started: float) -> int:
    return int((perf_counter() - started) * 1000)


def build_orchestration_state(
    *,
    chat_request: ChatRequest,
    db: Session | None,
    seams: ChatServiceSeams,
    request_id: str,
    settings: object,
    warnings: list[str],
) -> ChatOrchestrationState:
    demand = seams.policy.resolve_demand(
        chat_request,
        settings=settings,
        request_id=request_id,
        generate_provider_result=seams.provider.generate_provider_result,
        log_operation=seams.observability.log_operation,
    )
    triggered_retrieval = db is not None and bool(demand.categories)
    seams.policy.log_demand_resolution(
        log_operation=seams.observability.log_operation,
        request_id=request_id,
        demand=demand,
        triggered_retrieval=triggered_retrieval,
    )

    retrieval = RetrievalArtifacts.empty()
    if triggered_retrieval:
        retrieval = seams.policy.prepare_retrieval_artifacts(
            db=db,
            settings=settings,
            categories=demand.categories,
            top_k=demand.top_k,
            retrieval_demand=demand.retrieval_demand,
            build_profile=demand.build_profile,
            normalized_demand=demand.normalized_demand,
            env=demand.env,
            warnings=warnings,
        )

    provider_messages = seams.provider.build_provider_messages(
        chat_request,
        context_pack_text=retrieval.context_pack_text,
        context_pack_meta=retrieval.context_pack_meta,
        normalized_demand=demand.normalized_demand,
        build_profile=demand.build_profile,
    )
    return ChatOrchestrationState(
        settings=settings,
        request_id=request_id,
        warnings=warnings,
        demand=demand,
        retrieval=retrieval,
        triggered_retrieval=triggered_retrieval,
        provider_messages=provider_messages,
    )


def invoke_provider_result(
    *,
    state: ChatOrchestrationState,
    seams: ChatServiceSeams,
) -> ProviderCallResult:
    return seams.provider.generate_provider_result(
        settings=state.settings,
        messages=state.provider_messages,
        request_id=state.request_id,
    )


def finish_success_flow(
    *,
    state: ChatOrchestrationState,
    started: float,
    provider_result: ProviderCallResult,
    seams: ChatServiceSeams,
) -> ChatResponse:
    latency_ms = elapsed_latency_ms(started)
    normalized = seams.policy.normalize_provider_success(
        provider=state.settings.ai_provider,
        model=state.settings.ai_model,
        request_id=state.request_id,
        latency_ms=latency_ms,
        provider_result=provider_result,
        warnings=state.warnings,
    )
    outcome = seams.policy.evaluate_decision_outcome(
        request_id=state.request_id,
        text=normalized.text,
        max_output_chars=state.settings.ai_max_output_chars,
        warnings=state.warnings,
        categories=state.demand.categories,
        compressed_candidates=state.retrieval.compressed_candidates,
        context_pack_text=state.retrieval.context_pack_text,
        triggered_retrieval=state.triggered_retrieval,
    )
    snapshot_id = state.persist_snapshot(
        persist_ai_snapshot=seams.persistence.persist_ai_snapshot,
        latency_ms=latency_ms,
        ok=outcome.published.ok,
        error_type=outcome.published.error_type or "-",
        validation_report=outcome.validation,
        dq_report=outcome.dq_report,
        provider_result=provider_result,
    )
    state.persist_staging(
        persist_chat_stage_or_quarantine=seams.persistence.persist_chat_stage_or_quarantine,
        snapshot_id=snapshot_id,
        normalized_text=outcome.response_text,
        public_text=outcome.published.text,
        latency_ms=latency_ms,
        gate_status=outcome.gate_status,
        dq_status=outcome.dq_status,
        gate_reasons=list(outcome.validation.reasons),
        dq_reasons=list(outcome.dq_report.reasons) if outcome.dq_report else [],
        publish_reason=outcome.published.publish_reason,
        error_type=outcome.published.error_type,
    )
    state.emit_ai_call_log(
        log_ai_call=seams.observability.log_ai_call,
        log_operation=seams.observability.log_operation,
        snapshot_id=snapshot_id,
        latency_ms=latency_ms,
        ok=outcome.published.ok,
        error_type=outcome.published.error_type or "-",
        gate_status=outcome.gate_status,
        dq_status=outcome.dq_status,
        staging_status=outcome.staging_status,
        quarantine_status=outcome.quarantine_status,
    )
    return seams.policy.build_chat_response(
        request_id=normalized.request_id,
        provider=normalized.provider,
        model=normalized.model,
        text=outcome.published.text,
        latency_ms=normalized.latency_ms,
        error_type=outcome.published.error_type,
        warnings=state.warnings,
        compressed_candidates=state.retrieval.compressed_candidates,
        drop_log=state.retrieval.drop_log,
    )


def finish_provider_error_flow(
    *,
    state: ChatOrchestrationState,
    started: float,
    error: OpenAICompatError | ProviderDispatchError,
    seams: ChatServiceSeams,
) -> ChatResponse:
    latency_ms = elapsed_latency_ms(started)
    snapshot_id = state.persist_snapshot(
        persist_ai_snapshot=seams.persistence.persist_ai_snapshot,
        latency_ms=latency_ms,
        ok=False,
        error_type=error.error_type,
        provider_error=error,
    )
    published = seams.policy.publish_chat_response(
        request_id=state.request_id,
        error_type=error.error_type,
        provider_fallback_text=seams.policy.provider_error_fallback_text(error.error_type),
    )
    state.emit_ai_call_log(
        log_ai_call=seams.observability.log_ai_call,
        log_operation=seams.observability.log_operation,
        snapshot_id=snapshot_id,
        latency_ms=latency_ms,
        ok=False,
        error_type=error.error_type,
        gate_status="skipped",
        dq_status="skipped",
        staging_status="skipped",
        quarantine_status="not_applicable",
    )
    return seams.policy.build_chat_response(
        request_id=state.request_id,
        provider=state.settings.ai_provider,
        model=state.settings.ai_model,
        text=published.text,
        latency_ms=latency_ms,
        error_type=error.error_type,
        warnings=state.warnings,
        compressed_candidates=state.retrieval.compressed_candidates,
        drop_log=state.retrieval.drop_log,
    )
