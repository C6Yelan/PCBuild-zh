"""Chat orchestration entrypoint.

Round-2 public boundary:
- keep ``generate_chat_reply`` importable from this module and from
  ``backend.services.chat``.
- keep this module as the stable patch point for tests and ops, while
  detailed orchestration helpers live in sibling modules.
"""

# backend/services/chat/service.py
from __future__ import annotations

from time import perf_counter
from uuid import uuid4

from sqlalchemy.orm import Session

from backend.core.oplog import log_operation
from backend.services.chat.clients.openai_compat_client import (
    OpenAICompatError,
    generate_openai_compat_completion,
    generate_openai_compat_text,
)
from backend.services.chat.config import (
    get_ai_settings,
)
from backend.services.chat.context_pack import (
    build_context_pack,
    compress_candidates,
    retrieve_topk_candidates,
)
from backend.services.chat.contracts import ChatRequest, ChatResponse
from backend.services.chat.demand_inference import infer_chat_demand
from backend.services.chat.dq import evaluate_text_dq
from backend.services.chat.gate import validate_text_response
from backend.services.chat.normalize import normalize_provider_success
from backend.services.chat.provider_caller import (
    ProviderDispatchError,
)
from backend.services.chat.service_decisions import evaluate_decision_outcome
from backend.services.chat.service_demand import (
    log_demand_resolution,
    resolve_demand,
)
from backend.services.chat.service_response import (
    build_chat_response,
    log_ai_call,
    provider_error_fallback_text,
    publish_chat_response,
)
from backend.services.chat.service_retrieval import (
    empty_retrieval_artifacts,
    prepare_retrieval_artifacts,
)
from backend.services.chat.service_state import ChatOrchestrationState
import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.snapshot_store as chat_snapshot_store
from backend.services.chat.staging import (
    persist_chat_stage_or_quarantine as persist_chat_stage_or_quarantine_seam,
)

_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT = generate_openai_compat_text


def _elapsed_latency_ms(started: float) -> int:
    return int((perf_counter() - started) * 1000)


def _finish_success_flow(
    *,
    state: ChatOrchestrationState,
    started: float,
    provider_result: chat_provider_caller.ProviderCallResult,
) -> ChatResponse:
    latency_ms = _elapsed_latency_ms(started)
    normalized = normalize_provider_success(
        provider=state.settings.ai_provider,
        model=state.settings.ai_model,
        request_id=state.request_id,
        latency_ms=latency_ms,
        provider_result=provider_result,
        warnings=state.warnings,
    )
    outcome = evaluate_decision_outcome(
        request_id=state.request_id,
        text=normalized.text,
        max_output_chars=state.settings.ai_max_output_chars,
        warnings=state.warnings,
        categories=state.demand.categories,
        compressed_candidates=state.retrieval.compressed_candidates,
        context_pack_text=state.retrieval.context_pack_text,
        triggered_retrieval=state.triggered_retrieval,
        validate_text_response=validate_text_response,
        evaluate_text_dq=evaluate_text_dq,
    )
    snapshot_id = chat_snapshot_store.persist_ai_snapshot(
        **state.snapshot_kwargs(
            latency_ms=latency_ms,
            ok=outcome.published.ok,
            error_type=outcome.published.error_type or "-",
            validation_report=outcome.validation,
            dq_report=outcome.dq_report,
            provider_result=provider_result,
        )
    )
    persist_chat_stage_or_quarantine_seam(
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
    log_ai_call(
        log_operation=log_operation,
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
    return build_chat_response(
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


def _finish_provider_error_flow(
    *,
    state: ChatOrchestrationState,
    started: float,
    error: OpenAICompatError | ProviderDispatchError,
) -> ChatResponse:
    latency_ms = _elapsed_latency_ms(started)
    snapshot_id = chat_snapshot_store.persist_ai_snapshot(
        **state.snapshot_kwargs(
            latency_ms=latency_ms,
            ok=False,
            error_type=error.error_type,
            provider_error=error,
        )
    )
    published = publish_chat_response(
        request_id=state.request_id,
        error_type=error.error_type,
        provider_fallback_text=provider_error_fallback_text(error.error_type),
    )
    log_ai_call(
        log_operation=log_operation,
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
    return build_chat_response(
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


def generate_chat_reply(chat_request: ChatRequest, *, db: Session | None = None) -> ChatResponse:
    # Keep this module as the stable generate_chat_reply patch/import surface for
    # backend.services.chat, tests, and ops CLIs.
    settings = get_ai_settings()
    request_id = uuid4().hex
    started = perf_counter()
    warnings: list[str] = []
    demand = resolve_demand(
        chat_request,
        infer_chat_demand=infer_chat_demand,
    )
    triggered_retrieval = db is not None and bool(demand.categories)
    log_demand_resolution(
        log_operation=log_operation,
        request_id=request_id,
        demand=demand,
        triggered_retrieval=triggered_retrieval,
    )

    retrieval = empty_retrieval_artifacts()
    if triggered_retrieval:
        retrieval = prepare_retrieval_artifacts(
            db=db,
            settings=settings,
            categories=demand.categories,
            top_k=demand.top_k,
            p1_demand=demand.p1_demand,
            env=demand.env,
            warnings=warnings,
            retrieve_topk_candidates=retrieve_topk_candidates,
            compress_candidates=compress_candidates,
            build_context_pack=build_context_pack,
            log_operation=log_operation,
        )

    provider_messages = chat_provider_caller.build_provider_messages(
        chat_request,
        context_pack_text=retrieval.context_pack_text,
    )
    state = ChatOrchestrationState(
        settings=settings,
        request_id=request_id,
        warnings=warnings,
        demand=demand,
        retrieval=retrieval,
        triggered_retrieval=triggered_retrieval,
        provider_messages=provider_messages,
    )

    try:
        provider_result = chat_provider_caller.generate_provider_result(
            settings=settings,
            messages=provider_messages,
            request_id=request_id,
            text_generator=generate_openai_compat_text,
            completion_generator=generate_openai_compat_completion,
            original_text_generator=_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT,
        )
    except (OpenAICompatError, ProviderDispatchError) as exc:
        return _finish_provider_error_flow(
            state=state,
            started=started,
            error=exc,
        )
    return _finish_success_flow(
        state=state,
        started=started,
        provider_result=provider_result,
    )
