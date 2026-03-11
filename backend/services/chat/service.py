"""Chat orchestration entrypoint.

Round-1 public boundary:
- keep ``generate_chat_reply`` importable from this module and from
  ``backend.services.chat``.
- treat all ``_`` helpers in this file as internal-only; do not add new
  cross-module dependencies on them.
"""

# backend/services/chat/service.py
from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy.orm import Session

from backend.core.oplog import log_operation
from backend.services.chat.clients.openai_compat_client import (
    OpenAICompatError,
    generate_openai_compat_completion,
    generate_openai_compat_text,
)
from backend.services.chat.config import (
    AISettings,
    get_ai_settings,
)
from backend.services.chat.context_pack import (
    P1Demand,
    build_context_pack,
    compress_candidates,
    retrieve_topk_candidates,
)
from backend.services.chat.contracts import ChatRequest, ChatResponse
from backend.services.chat.demand_inference import infer_chat_demand
from backend.services.chat.dq import DQReport, evaluate_text_dq
from backend.services.chat.gate import TextValidationReport, validate_text_response
from backend.services.chat.normalize import normalize_provider_success
from backend.services.chat.provider_caller import (
    ProviderCallResult as _ProviderCallResult,
    ProviderDispatchError as _ProviderDispatchError,
)
import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.snapshot_store as chat_snapshot_store
from backend.services.chat.staging import (
    persist_chat_stage_or_quarantine as persist_chat_stage_or_quarantine_seam,
)

_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT = generate_openai_compat_text
_build_provider_messages = chat_provider_caller.build_provider_messages


@dataclass(slots=True)
class _ResolvedDemand:
    raw_demand: dict[str, Any] | None
    source: str


@dataclass(slots=True)
class _PublishedChatResult:
    text: str
    error_type: str | None
    ok: bool
    publish_reason: str


def _truncate_text(text: str, max_chars: int, warnings: list[str]) -> str:
    if len(text) <= max_chars:
        return text
    warnings.append("output_truncated")
    return text[:max_chars]


def _with_request_id(message: str, request_id: str) -> str:
    return f"{message}request_id={request_id}"


def _publish_chat_response(
    *,
    request_id: str,
    staged_public_text: str | None = None,
    error_type: str | None = None,
    provider_fallback_text: str | None = None,
) -> _PublishedChatResult:
    if error_type is None:
        return _PublishedChatResult(
            text=staged_public_text or "",
            error_type=None,
            ok=True,
            publish_reason="staged_pass",
        )

    if error_type == "validation_failed":
        return _PublishedChatResult(
            text=_with_request_id("目前 AI 回覆格式異常，請稍後再試。", request_id),
            error_type=error_type,
            ok=False,
            publish_reason="validation_failed",
        )

    if error_type == "dq_failed":
        return _PublishedChatResult(
            text=_with_request_id("目前資料不足，請補充需求後再試。", request_id),
            error_type=error_type,
            ok=False,
            publish_reason="dq_failed",
        )

    return _PublishedChatResult(
        text=_with_request_id(
            provider_fallback_text or "目前 AI 服務暫時不可用，請稍後再試。",
            request_id,
        ),
        error_type=error_type,
        ok=False,
        publish_reason="provider_error",
    )


def _inference_inputs(chat_request: ChatRequest) -> tuple[str, list[Any]]:
    if chat_request.user_text:
        return chat_request.user_text, list(chat_request.history)

    if not chat_request.messages:
        return "", []

    last_user_index: int | None = None
    for index in range(len(chat_request.messages) - 1, -1, -1):
        if chat_request.messages[index].role == "user":
            last_user_index = index
            break

    if last_user_index is None:
        return "", list(chat_request.messages)

    return (
        chat_request.messages[last_user_index].content,
        list(chat_request.messages[:last_user_index]),
    )


def _resolve_effective_demand(chat_request: ChatRequest) -> _ResolvedDemand:
    if isinstance(chat_request.demand, dict):
        return _ResolvedDemand(raw_demand=chat_request.demand, source="explicit")

    message, history = _inference_inputs(chat_request)
    inferred = infer_chat_demand(message=message, history=history)
    if inferred is None:
        return _ResolvedDemand(raw_demand=None, source="none")
    return _ResolvedDemand(raw_demand=inferred, source="inferred")


def _extract_p1_inputs_from_demand(
    raw: dict[str, Any] | None,
) -> tuple[list[str], int, P1Demand | None, str]:
    if not isinstance(raw, dict):
        return [], 5, None, "prod"

    categories: list[str] = []
    raw_categories = raw.get("categories")
    if isinstance(raw_categories, list):
        for value in raw_categories:
            normalized = str(value).strip()
            if normalized:
                categories.append(normalized)

    raw_top_k = raw.get("top_k", 5)
    try:
        top_k = int(raw_top_k)
    except (TypeError, ValueError):
        top_k = 5

    raw_env = raw.get("env")
    env = raw_env.strip() if isinstance(raw_env, str) and raw_env.strip() else "prod"

    p1_demand: P1Demand | None = None
    raw_filters = raw.get("filters")
    if isinstance(raw_filters, dict):
        try:
            p1_demand = P1Demand.model_validate(raw_filters)
        except ValidationError:
            p1_demand = None

    return categories, top_k, p1_demand, env


def _request_mode(chat_request: ChatRequest) -> str:
    return "messages" if chat_request.messages else "user_text"


def _generate_provider_result(
    *,
    settings: AISettings,
    messages: list[dict[str, str]],
    request_id: str,
) -> _ProviderCallResult:
    # Compat wrapper: keep the service-local patch point available while the
    # main orchestration path moves to backend.services.chat.provider_caller.
    return chat_provider_caller.generate_provider_result(
        settings=settings,
        messages=messages,
        request_id=request_id,
        text_generator=generate_openai_compat_text,
        completion_generator=generate_openai_compat_completion,
        original_text_generator=_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT,
    )


def _persist_ai_snapshot(
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
    provider_result: _ProviderCallResult | None = None,
    provider_error: OpenAICompatError | _ProviderDispatchError | None = None,
) -> str:
    # Compat wrapper: keep the service-local patch point while snapshot
    # persistence lives in backend.services.chat.snapshot_store.
    return chat_snapshot_store.persist_ai_snapshot(
        settings=settings,
        warnings=warnings,
        request_id=request_id,
        provider=provider,
        model=model,
        context_pack_hash=context_pack_hash,
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


def _persist_chat_stage_or_quarantine(
    *,
    settings: AISettings,
    warnings: list[str],
    request_id: str,
    snapshot_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    normalized_text: str,
    public_text: str,
    latency_ms: int,
    gate_status: str,
    dq_status: str,
    gate_reasons: list[str],
    dq_reasons: list[str],
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    has_context_pack: bool,
    compressed_candidates: dict[str, list[dict[str, object]]],
    publish_reason: str,
    error_type: str | None,
) -> None:
    # Compat wrapper: keep the orchestration call site stable while stage /
    # quarantine persistence lives in backend.services.chat.staging.
    persist_chat_stage_or_quarantine_seam(
        settings=settings,
        warnings=warnings,
        request_id=request_id,
        snapshot_id=snapshot_id,
        provider=provider,
        model=model,
        context_pack_hash=context_pack_hash,
        normalized_text=normalized_text,
        public_text=public_text,
        latency_ms=latency_ms,
        gate_status=gate_status,
        dq_status=dq_status,
        gate_reasons=gate_reasons,
        dq_reasons=dq_reasons,
        demand_source=demand_source,
        triggered_retrieval=triggered_retrieval,
        categories=categories,
        top_k=top_k,
        env=env,
        has_context_pack=has_context_pack,
        compressed_candidates=compressed_candidates,
        publish_reason=publish_reason,
        error_type=error_type,
    )


def _log_ai_call(
    *,
    request_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    snapshot_id: str,
    latency_ms: int,
    ok: bool,
    error_type: str | None = None,
    gate_status: str,
    dq_status: str,
    staging_status: str,
    quarantine_status: str,
    warning_count: int,
    demand_source: str,
    triggered_retrieval: bool,
) -> None:
    log_operation(
        "ai_call",
        request_id=request_id,
        provider=provider,
        model=model,
        context_pack_hash=context_pack_hash,
        snapshot_id=snapshot_id,
        latency_ms=latency_ms,
        ok=ok,
        error_type=error_type or "-",
        gate_status=gate_status,
        dq_status=dq_status,
        staging_status=staging_status,
        quarantine_status=quarantine_status,
        warning_count=warning_count,
        demand_source=demand_source,
        triggered_retrieval=triggered_retrieval,
    )


def generate_chat_reply(chat_request: ChatRequest, *, db: Session | None = None) -> ChatResponse:
    settings = get_ai_settings()
    request_id = uuid4().hex
    started = perf_counter()
    warnings: list[str] = []
    compressed_candidates: dict[str, list[dict[str, object]]] = {}
    drop_log: dict[str, dict[str, object]] = {}
    context_pack_text: str | None = None
    context_pack_hash = "-"
    resolved_demand = _resolve_effective_demand(chat_request)
    categories, p1_top_k, p1_demand, p1_env = _extract_p1_inputs_from_demand(resolved_demand.raw_demand)
    message_for_inference, history_for_inference = _inference_inputs(chat_request)
    request_mode = _request_mode(chat_request)
    message_chars = len(message_for_inference)
    history_turns = len(history_for_inference)
    triggered_retrieval = db is not None and bool(categories)

    log_operation(
        "demand_resolution",
        request_id=request_id,
        source=resolved_demand.source,
        categories=",".join(categories) if categories else "-",
        top_k=p1_top_k,
        env=p1_env,
        message_chars=message_chars,
        history_turns=history_turns,
        triggered_retrieval=triggered_retrieval,
    )

    if triggered_retrieval:
        try:
            p1_result = retrieve_topk_candidates(
                db,
                categories=categories,
                top_k=p1_top_k,
                demand=p1_demand,
                env=p1_env,
            )
            compressed_candidates, drop_log = compress_candidates(
                p1_result,
                spec_whitelist_by_category=settings.p2_spec_whitelist_by_category,
                max_value_len=settings.p2_max_value_len,
                max_specs_per_part=settings.p2_max_specs_per_part,
            )
            drop_entries = list(drop_log.values())
            fallback_count = sum(
                1
                for entry in drop_entries
                if isinstance(entry, dict)
                and isinstance(entry.get("reason"), list)
                and "fallback_used" in entry["reason"]
            )
            dropped_specs_count = sum(
                len(entry["dropped_specs"])
                for entry in drop_entries
                if isinstance(entry, dict) and isinstance(entry.get("dropped_specs"), list)
            )
            truncated_specs_count = sum(
                len(entry["truncated_specs"])
                for entry in drop_entries
                if isinstance(entry, dict) and isinstance(entry.get("truncated_specs"), dict)
            )
            log_operation(
                "p2_compress",
                env=p1_env,
                top_k=p1_top_k,
                requested_categories=",".join(categories),
                returned_categories=",".join(sorted(compressed_candidates.keys())),
                returned_count=sum(len(items) for items in compressed_candidates.values()),
                drop_log_count=len(drop_entries),
                fallback_count=fallback_count,
                dropped_specs_count=dropped_specs_count,
                truncated_specs_count=truncated_specs_count,
                max_value_len=settings.p2_max_value_len,
                max_specs_per_part=settings.p2_max_specs_per_part,
            )

            context_pack = build_context_pack(
                compressed_by_category=compressed_candidates,
                category_order=categories,
                enable_rerank=True,
                demand=p1_demand,
            )
            context_pack_text = context_pack.text
            context_pack_hash = context_pack.hash
            category_counts = ",".join(
                f"{category}:{len(compressed_candidates.get(category, []))}"
                for category in sorted(compressed_candidates.keys())
            )
            log_operation(
                "p3_context_pack",
                env=p1_env,
                context_pack_hash=context_pack_hash,
                context_pack_chars=len(context_pack.text),
                category_counts=category_counts,
            )
        except Exception as exc:
            warnings.append("p1_retrieval_failed")
            log_operation(
                "p1_retrieval_failed",
                error_type=type(exc).__name__,
                env=p1_env,
                categories=",".join(categories),
                top_k=p1_top_k,
            )
            compressed_candidates = {}
            drop_log = {}

    provider_messages = chat_provider_caller.build_provider_messages(
        chat_request,
        context_pack_text=context_pack_text,
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
        latency_ms = int((perf_counter() - started) * 1000)
        normalized = normalize_provider_success(
            provider=settings.ai_provider,
            model=settings.ai_model,
            request_id=request_id,
            latency_ms=latency_ms,
            provider_result=provider_result,
            warnings=warnings,
        )
        response_text = _truncate_text(
            normalized.text,
            max_chars=settings.ai_max_output_chars,
            warnings=warnings,
        )
        validation = validate_text_response(
            response_text,
            max_chars=settings.ai_max_output_chars,
        )
        for warning in validation.warnings:
            if warning not in warnings:
                warnings.append(warning)
        response_text = validation.sanitized_text
        dq_report: DQReport | None = None
        response_error_type: str | None = None
        if not validation.passed:
            response_error_type = "validation_failed"
        else:
            dq_report = evaluate_text_dq(
                text=response_text,
                request_categories=categories,
                compressed_candidates=compressed_candidates,
                context_pack_text=context_pack_text,
                triggered_retrieval=triggered_retrieval,
            )
            for warning in dq_report.warnings:
                if warning not in warnings:
                    warnings.append(warning)
            if not dq_report.passed:
                response_error_type = "dq_failed"
        published = _publish_chat_response(
            request_id=request_id,
            staged_public_text=response_text,
            error_type=response_error_type,
        )
        gate_status = "pass" if validation.passed else "fail"
        dq_status = (
            "skipped"
            if dq_report is None
            else "pass"
            if dq_report.passed
            else "fail"
        )
        snapshot_id = _persist_ai_snapshot(
            settings=settings,
            warnings=warnings,
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            latency_ms=latency_ms,
            ok=published.ok,
            error_type=published.error_type or "-",
            messages=provider_messages,
            request_mode=request_mode,
            demand_source=resolved_demand.source,
            triggered_retrieval=triggered_retrieval,
            categories=categories,
            top_k=p1_top_k,
            env=p1_env,
            message_chars=message_chars,
            history_turns=history_turns,
            context_pack_text=context_pack_text,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
            validation_report=validation,
            dq_report=dq_report,
            provider_result=provider_result,
        )
        _persist_chat_stage_or_quarantine(
            settings=settings,
            warnings=warnings,
            request_id=request_id,
            snapshot_id=snapshot_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            normalized_text=response_text,
            public_text=published.text,
            latency_ms=latency_ms,
            gate_status=gate_status,
            dq_status=dq_status,
            gate_reasons=list(validation.reasons),
            dq_reasons=list(dq_report.reasons) if dq_report else [],
            demand_source=resolved_demand.source,
            triggered_retrieval=triggered_retrieval,
            categories=categories,
            top_k=p1_top_k,
            env=p1_env,
            has_context_pack=bool(context_pack_text),
            compressed_candidates=compressed_candidates,
            publish_reason=published.publish_reason,
            error_type=published.error_type,
        )
        staging_status = "staged" if gate_status == "pass" and dq_status == "pass" else "skipped"
        quarantine_status = (
            "not_quarantined" if staging_status == "staged" else "quarantined"
        )
        _log_ai_call(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            snapshot_id=snapshot_id,
            latency_ms=latency_ms,
            ok=published.ok,
            error_type=published.error_type or "-",
            gate_status=gate_status,
            dq_status=dq_status,
            staging_status=staging_status,
            quarantine_status=quarantine_status,
            warning_count=len(warnings),
            demand_source=resolved_demand.source,
            triggered_retrieval=triggered_retrieval,
        )
        return ChatResponse(
            request_id=normalized.request_id,
            provider=normalized.provider,
            model=normalized.model,
            text=published.text,
            latency_ms=normalized.latency_ms,
            error_type=published.error_type,
            warnings=warnings or None,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
        )
    except OpenAICompatError as exc:
        latency_ms = int((perf_counter() - started) * 1000)
        snapshot_id = _persist_ai_snapshot(
            settings=settings,
            warnings=warnings,
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            latency_ms=latency_ms,
            ok=False,
            error_type=exc.error_type,
            messages=provider_messages,
            request_mode=request_mode,
            demand_source=resolved_demand.source,
            triggered_retrieval=triggered_retrieval,
            categories=categories,
            top_k=p1_top_k,
            env=p1_env,
            message_chars=message_chars,
            history_turns=history_turns,
            context_pack_text=context_pack_text,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
            provider_error=exc,
        )
        published = _publish_chat_response(
            request_id=request_id,
            error_type=exc.error_type,
            provider_fallback_text="目前 AI 服務暫時不可用，請稍後再試。",
        )
        _log_ai_call(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            snapshot_id=snapshot_id,
            latency_ms=latency_ms,
            ok=False,
            error_type=exc.error_type,
            gate_status="skipped",
            dq_status="skipped",
            staging_status="skipped",
            quarantine_status="not_applicable",
            warning_count=len(warnings),
            demand_source=resolved_demand.source,
            triggered_retrieval=triggered_retrieval,
        )
        return ChatResponse(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            text=published.text,
            latency_ms=latency_ms,
            error_type=exc.error_type,
            warnings=warnings or None,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
        )
    except _ProviderDispatchError as exc:
        latency_ms = int((perf_counter() - started) * 1000)
        snapshot_id = _persist_ai_snapshot(
            settings=settings,
            warnings=warnings,
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            latency_ms=latency_ms,
            ok=False,
            error_type=exc.error_type,
            messages=provider_messages,
            request_mode=request_mode,
            demand_source=resolved_demand.source,
            triggered_retrieval=triggered_retrieval,
            categories=categories,
            top_k=p1_top_k,
            env=p1_env,
            message_chars=message_chars,
            history_turns=history_turns,
            context_pack_text=context_pack_text,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
            provider_error=exc,
        )
        published = _publish_chat_response(
            request_id=request_id,
            error_type=exc.error_type,
            provider_fallback_text=(
                "目前 AI 服務提供者尚未啟用，請稍後再試。"
                if exc.error_type == "provider_not_ready"
                else "目前 AI 服務暫時不可用，請稍後再試。"
            ),
        )
        _log_ai_call(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            snapshot_id=snapshot_id,
            latency_ms=latency_ms,
            ok=False,
            error_type=exc.error_type,
            gate_status="skipped",
            dq_status="skipped",
            staging_status="skipped",
            quarantine_status="not_applicable",
            warning_count=len(warnings),
            demand_source=resolved_demand.source,
            triggered_retrieval=triggered_retrieval,
        )
        return ChatResponse(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            text=published.text,
            latency_ms=latency_ms,
            error_type=exc.error_type,
            warnings=warnings or None,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
        )
