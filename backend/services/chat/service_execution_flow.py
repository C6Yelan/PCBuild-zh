from __future__ import annotations

from time import perf_counter

from sqlalchemy.orm import Session

from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.contracts import ChatRequest, ChatResponse
from backend.services.chat.provider_caller import (
    ProviderCallResult,
    ProviderDispatchError,
)
from backend.services.chat.service_seams import ChatServiceSeams
from backend.services.chat.service_state import ChatOrchestrationState


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
    demand = seams.resolve_demand(
        chat_request,
        infer_chat_demand=seams.infer_chat_demand,
    )
    triggered_retrieval = db is not None and bool(demand.categories)
    seams.log_demand_resolution(
        log_operation=seams.log_operation,
        request_id=request_id,
        demand=demand,
        triggered_retrieval=triggered_retrieval,
    )

    retrieval = seams.empty_retrieval_artifacts()
    if triggered_retrieval:
        retrieval = seams.prepare_retrieval_artifacts(
            db=db,
            settings=settings,
            categories=demand.categories,
            top_k=demand.top_k,
            p1_demand=demand.p1_demand,
            env=demand.env,
            warnings=warnings,
            retrieve_topk_candidates=seams.retrieve_topk_candidates,
            compress_candidates=seams.compress_candidates,
            build_context_pack=seams.build_context_pack,
            log_operation=seams.log_operation,
        )

    provider_messages = seams.build_provider_messages(
        chat_request,
        context_pack_text=retrieval.context_pack_text,
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
    return seams.generate_provider_result(
        settings=state.settings,
        messages=state.provider_messages,
        request_id=state.request_id,
        text_generator=seams.text_generator,
        completion_generator=seams.completion_generator,
        original_text_generator=seams.original_text_generator,
    )


def finish_success_flow(
    *,
    state: ChatOrchestrationState,
    started: float,
    provider_result: ProviderCallResult,
    seams: ChatServiceSeams,
) -> ChatResponse:
    latency_ms = elapsed_latency_ms(started)
    normalized = seams.normalize_provider_success(
        provider=state.settings.ai_provider,
        model=state.settings.ai_model,
        request_id=state.request_id,
        latency_ms=latency_ms,
        provider_result=provider_result,
        warnings=state.warnings,
    )
    outcome = seams.evaluate_decision_outcome(
        request_id=state.request_id,
        text=normalized.text,
        max_output_chars=state.settings.ai_max_output_chars,
        warnings=state.warnings,
        categories=state.demand.categories,
        compressed_candidates=state.retrieval.compressed_candidates,
        context_pack_text=state.retrieval.context_pack_text,
        triggered_retrieval=state.triggered_retrieval,
        validate_text_response=seams.validate_text_response,
        evaluate_text_dq=seams.evaluate_text_dq,
    )
    snapshot_id = seams.persist_ai_snapshot(
        **state.snapshot_kwargs(
            latency_ms=latency_ms,
            ok=outcome.published.ok,
            error_type=outcome.published.error_type or "-",
            validation_report=outcome.validation,
            dq_report=outcome.dq_report,
            provider_result=provider_result,
        )
    )
    seams.persist_chat_stage_or_quarantine(
        **state.staging_kwargs(
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
    )
    seams.log_ai_call(
        log_operation=seams.log_operation,
        **state.ai_call_kwargs(
            snapshot_id=snapshot_id,
            latency_ms=latency_ms,
            ok=outcome.published.ok,
            error_type=outcome.published.error_type or "-",
            gate_status=outcome.gate_status,
            dq_status=outcome.dq_status,
            staging_status=outcome.staging_status,
            quarantine_status=outcome.quarantine_status,
        ),
    )
    return seams.build_chat_response(
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
    snapshot_id = seams.persist_ai_snapshot(
        **state.snapshot_kwargs(
            latency_ms=latency_ms,
            ok=False,
            error_type=error.error_type,
            provider_error=error,
        )
    )
    published = seams.publish_chat_response(
        request_id=state.request_id,
        error_type=error.error_type,
        provider_fallback_text=seams.provider_error_fallback_text(error.error_type),
    )
    seams.log_ai_call(
        log_operation=seams.log_operation,
        **state.ai_call_kwargs(
            snapshot_id=snapshot_id,
            latency_ms=latency_ms,
            ok=False,
            error_type=error.error_type,
            gate_status="skipped",
            dq_status="skipped",
            staging_status="skipped",
            quarantine_status="not_applicable",
        ),
    )
    return seams.build_chat_response(
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
