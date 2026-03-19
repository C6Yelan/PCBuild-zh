# backend/services/chat/service/demand.py
"""Demand and request-shape helpers for chat orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from pydantic import ValidationError

from backend.services.chat.build_policy import BuildRequestProfile, build_request_profile
from backend.services.chat.context_pack import P1Demand
from backend.services.chat.contracts import ChatRequest, NormalizedDemand
from backend.services.chat.provider import ProviderCallResult
from backend.services.chat.retrieval_defaults import DEFAULT_RETRIEVAL_TOP_K
from .normalization import (
    merge_normalized_demands,
    normalize_explicit_demand,
    run_normalization_pass,
)


@dataclass(slots=True)
class DemandResolution:
    raw_demand: dict[str, Any] | None
    source: str
    categories: list[str]
    top_k: int
    retrieval_demand: P1Demand | None
    env: str
    message_for_inference: str
    history_for_inference: list[Any]
    request_mode: str
    message_chars: int
    history_turns: int
    build_profile: BuildRequestProfile
    normalized_demand: NormalizedDemand
    normalization_fallback_used: bool
    normalization_report: dict[str, Any]

    def normalization_summary(self) -> dict[str, Any]:
        return {
            "normalization_source": self.normalized_demand.normalization_source,
            "normalization_confidence": self.normalized_demand.normalization_confidence,
            "normalized_request_mode": self.normalized_demand.request_mode,
            "normalized_categories": list(self.normalized_demand.categories),
            "normalized_budget_max": self.normalized_demand.budget_max,
            "normalized_budget_target": self.normalized_demand.budget_target,
            "normalized_cpu_vendor": self.normalized_demand.preferred_cpu_vendor,
            "normalized_gpu_vendor": self.normalized_demand.preferred_gpu_vendor,
            "normalized_size_preference": self.normalized_demand.size_preference,
            "normalization_missing_information": list(self.normalized_demand.missing_information),
            "normalization_fallback_used": self.normalization_fallback_used,
        }


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


def _normalize_query_text(
    message_text: str,
    *,
    query_focus: list[str],
) -> str | None:
    parts: list[str] = []
    if message_text.strip():
        parts.append(message_text.strip())
    for focus in query_focus:
        normalized = str(focus).strip()
        if normalized and normalized not in parts:
            parts.append(normalized)
    if not parts:
        return None
    return "\n".join(parts)


def _parse_top_k(raw_demand: Mapping[str, Any] | None) -> int:
    if not raw_demand:
        return DEFAULT_RETRIEVAL_TOP_K
    raw_top_k = raw_demand.get("top_k", DEFAULT_RETRIEVAL_TOP_K)
    try:
        return int(raw_top_k)
    except (TypeError, ValueError):
        return DEFAULT_RETRIEVAL_TOP_K


def _parse_env(raw_demand: Mapping[str, Any] | None) -> str:
    if not raw_demand:
        return "prod"
    raw_env = raw_demand.get("env")
    if isinstance(raw_env, str) and raw_env.strip():
        return raw_env.strip()
    return "prod"


def _apply_explicit_filter_overrides(
    retrieval_demand: P1Demand,
    raw_demand: Mapping[str, Any] | None,
) -> P1Demand:
    if not raw_demand:
        return retrieval_demand

    raw_filters = raw_demand.get("filters")
    if not isinstance(raw_filters, dict):
        return retrieval_demand

    overrides: dict[str, Any] = {}
    for field_name in ("budget", "target_price", "min_price", "max_price"):
        if field_name in raw_filters:
            overrides[field_name] = raw_filters[field_name]

    if not overrides:
        return retrieval_demand

    try:
        explicit_filters = P1Demand.model_validate(overrides)
    except ValidationError:
        return retrieval_demand

    merged = retrieval_demand.model_dump()
    if explicit_filters.budget is not None:
        merged["budget"] = explicit_filters.budget
    if explicit_filters.target_price is not None:
        merged["target_price"] = explicit_filters.target_price
    if explicit_filters.min_price is not None:
        current_min = merged.get("min_price")
        merged["min_price"] = (
            explicit_filters.min_price
            if current_min is None
            else max(int(current_min), explicit_filters.min_price)
        )
    if explicit_filters.max_price is not None:
        current_max = merged.get("max_price")
        merged["max_price"] = (
            explicit_filters.max_price
            if current_max is None
            else min(int(current_max), explicit_filters.max_price)
        )
    try:
        return P1Demand.model_validate(merged)
    except ValidationError:
        return retrieval_demand


def _build_retrieval_demand(
    *,
    normalized_demand: NormalizedDemand,
    raw_demand: Mapping[str, Any] | None,
    query_text: str,
) -> P1Demand | None:
    target_price = normalized_demand.budget_target
    budget_max = normalized_demand.budget_max
    min_price: int | None = None
    max_price = budget_max
    if target_price is not None and normalized_demand.budget_flex_pct is not None:
        delta = max(1, int(round(target_price * normalized_demand.budget_flex_pct)))
        min_price = max(0, target_price - delta)
        max_price = target_price + delta if budget_max is None else min(budget_max, target_price + delta)

    payload = {
        "query_text": query_text or None,
        "budget": budget_max,
        "target_price": target_price,
        "min_price": min_price,
        "max_price": max_price,
    }
    retrieval_demand = P1Demand.model_validate(payload)
    retrieval_demand = _apply_explicit_filter_overrides(retrieval_demand, raw_demand)
    if retrieval_demand.query_text or any(
        getattr(retrieval_demand, name) is not None
        for name in ("budget", "target_price", "min_price", "max_price")
    ):
        return retrieval_demand
    return None


def _determine_resolution_source(
    *,
    raw_demand: Mapping[str, Any] | None,
    normalized_demand: NormalizedDemand,
) -> str:
    if raw_demand:
        return "explicit"
    if normalized_demand.request_mode != "unknown" or normalized_demand.categories:
        return "inferred"
    return "none"


def _apply_legacy_inference(
    *,
    normalized_demand: NormalizedDemand,
    infer_chat_demand: Callable[..., dict[str, Any] | None] | None,
    message_text: str,
    history: list[Any],
    explicit_raw_demand: Mapping[str, Any] | None,
) -> NormalizedDemand:
    if infer_chat_demand is None:
        return normalized_demand
    if explicit_raw_demand:
        return normalized_demand

    legacy = infer_chat_demand(message=message_text, history=history)
    if not isinstance(legacy, dict):
        return normalized_demand
    categories = legacy.get("categories")
    if not isinstance(categories, list) or not categories:
        return normalized_demand

    request_mode = normalized_demand.request_mode
    if request_mode == "unknown":
        request_mode = "build" if len(categories) >= 3 else "single_part"
    return normalized_demand.model_copy(
        update={
            "request_mode": request_mode,
            "categories": categories,
            "normalization_source": normalized_demand.normalization_source,
        }
    )


def resolve_demand(
    chat_request: ChatRequest,
    *,
    settings: object | None = None,
    request_id: str = "local-demand",
    generate_provider_result: Callable[..., ProviderCallResult] | None = None,
    log_operation: Callable[..., Any] | None = None,
    infer_chat_demand: Callable[..., dict[str, Any] | None] | None = None,
) -> DemandResolution:
    resolved_settings = settings or SimpleNamespace(ai_provider="openai_compat", ai_model="-")
    resolved_generate_provider_result = generate_provider_result or (
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("normalization_provider_unavailable"))
    )
    resolved_log_operation = log_operation or (lambda *args, **kwargs: None)
    raw_demand = chat_request.demand if isinstance(chat_request.demand, dict) else None
    message_for_inference, history_for_inference = _inference_inputs(chat_request)
    explicit_normalized, explicit_fields = normalize_explicit_demand(raw_demand)

    resolved_log_operation(
        "normalization_started",
        request_id=request_id,
        provider=str(getattr(resolved_settings, "ai_provider", "")),
        model=str(getattr(resolved_settings, "ai_model", "")),
        has_explicit_demand=bool(raw_demand),
        request_mode="messages" if chat_request.messages else "user_text",
    )
    ai_result = run_normalization_pass(
        message_text=message_for_inference,
        history=history_for_inference,
        explicit_demand=raw_demand,
        settings=resolved_settings,
        request_id=request_id,
        generate_provider_result=resolved_generate_provider_result,
        log_operation=resolved_log_operation,
    )
    normalized_demand, merge_trace = merge_normalized_demands(
        explicit_demand=explicit_normalized,
        explicit_fields=explicit_fields,
        ai_demand=ai_result.normalized_demand,
    )
    normalized_demand = _apply_legacy_inference(
        normalized_demand=normalized_demand,
        infer_chat_demand=infer_chat_demand,
        message_text=message_for_inference,
        history=history_for_inference,
        explicit_raw_demand=raw_demand,
    )
    normalization_report = dict(ai_result.report)
    normalization_report["source"] = normalized_demand.normalization_source
    normalization_report["confidence"] = normalized_demand.normalization_confidence
    normalization_report["missing_information"] = list(normalized_demand.missing_information)
    normalization_report["fallback_used"] = ai_result.fallback_used
    normalization_report["merge_trace"] = merge_trace

    query_text = _normalize_query_text(
        message_for_inference,
        query_focus=normalized_demand.query_focus,
    )
    retrieval_demand = _build_retrieval_demand(
        normalized_demand=normalized_demand,
        raw_demand=raw_demand,
        query_text=query_text or "",
    )
    categories = list(normalized_demand.categories)
    top_k = _parse_top_k(raw_demand)
    env = _parse_env(raw_demand)
    build_profile = build_request_profile(
        normalized_demand=normalized_demand,
        retrieval_demand=retrieval_demand,
    )
    source = _determine_resolution_source(raw_demand=raw_demand, normalized_demand=normalized_demand)

    summary = DemandResolution(
        raw_demand=raw_demand,
        source=source,
        categories=categories,
        top_k=top_k,
        retrieval_demand=retrieval_demand,
        env=env,
        message_for_inference=message_for_inference,
        history_for_inference=history_for_inference,
        request_mode="messages" if chat_request.messages else "user_text",
        message_chars=len(message_for_inference),
        history_turns=len(history_for_inference),
        build_profile=build_profile,
        normalized_demand=normalized_demand,
        normalization_fallback_used=ai_result.fallback_used,
        normalization_report=normalization_report,
    )
    resolved_log_operation(
        "normalization_finished",
        request_id=request_id,
        provider=str(getattr(resolved_settings, "ai_provider", "")),
        model=str(getattr(resolved_settings, "ai_model", "")),
        normalization_source=normalized_demand.normalization_source,
        normalization_confidence=normalized_demand.normalization_confidence,
        normalized_request_mode=normalized_demand.request_mode,
        normalized_categories=",".join(normalized_demand.categories) if normalized_demand.categories else "-",
        normalized_budget_max=normalized_demand.budget_max,
        normalized_budget_target=normalized_demand.budget_target,
        normalized_cpu_vendor=normalized_demand.preferred_cpu_vendor or "-",
        normalized_gpu_vendor=normalized_demand.preferred_gpu_vendor or "-",
        normalized_size_preference=normalized_demand.size_preference or "-",
        normalization_missing_information=",".join(normalized_demand.missing_information)
        if normalized_demand.missing_information
        else "-",
        normalization_fallback_used=ai_result.fallback_used,
    )
    return summary


def log_demand_resolution(
    *,
    log_operation: Callable[..., Any],
    request_id: str,
    demand: DemandResolution,
    triggered_retrieval: bool,
) -> None:
    log_operation(
        "demand_resolution",
        request_id=request_id,
        source=demand.source,
        categories=",".join(demand.categories) if demand.categories else "-",
        top_k=demand.top_k,
        env=demand.env,
        message_chars=demand.message_chars,
        history_turns=demand.history_turns,
        triggered_retrieval=triggered_retrieval,
        build_mode=demand.build_profile.enabled,
        normalization_source=demand.normalized_demand.normalization_source,
        normalization_confidence=demand.normalized_demand.normalization_confidence,
        normalization_fallback_used=demand.normalization_fallback_used,
    )


__all__ = [
    "DemandResolution",
    "log_demand_resolution",
    "resolve_demand",
]
