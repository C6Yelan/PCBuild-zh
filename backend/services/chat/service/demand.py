# backend/services/chat/service/demand.py
"""Demand and request-shape helpers for chat orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from pydantic import ValidationError

from backend.services.chat.build_policy import BuildRequestProfile, build_request_profile
from backend.services.chat.context_pack import P1Demand
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.retrieval_defaults import DEFAULT_RETRIEVAL_TOP_K


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


def _extract_retrieval_inputs(
    raw_demand: dict[str, Any] | None,
) -> tuple[list[str], int, P1Demand | None, str]:
    if not isinstance(raw_demand, dict):
        return [], DEFAULT_RETRIEVAL_TOP_K, None, "prod"

    categories: list[str] = []
    raw_categories = raw_demand.get("categories")
    if isinstance(raw_categories, list):
        for value in raw_categories:
            normalized = str(value).strip()
            if normalized:
                categories.append(normalized)

    raw_top_k = raw_demand.get("top_k", DEFAULT_RETRIEVAL_TOP_K)
    try:
        top_k = int(raw_top_k)
    except (TypeError, ValueError):
        top_k = DEFAULT_RETRIEVAL_TOP_K

    raw_env = raw_demand.get("env")
    env = raw_env.strip() if isinstance(raw_env, str) and raw_env.strip() else "prod"

    retrieval_demand: P1Demand | None = None
    raw_filters = raw_demand.get("filters")
    if isinstance(raw_filters, dict):
        try:
            retrieval_demand = P1Demand.model_validate(raw_filters)
        except ValidationError:
            retrieval_demand = None

    return categories, top_k, retrieval_demand, env


def _with_query_text(
    retrieval_demand: P1Demand | None,
    *,
    query_text: str,
) -> P1Demand | None:
    normalized_query_text = query_text.strip()
    if not normalized_query_text:
        return retrieval_demand
    if retrieval_demand is None:
        return P1Demand(query_text=normalized_query_text)
    return retrieval_demand.model_copy(update={"query_text": normalized_query_text})


def _resolve_raw_demand(
    chat_request: ChatRequest,
    *,
    infer_chat_demand: Callable[..., dict[str, Any] | None],
) -> tuple[dict[str, Any] | None, str]:
    if isinstance(chat_request.demand, dict):
        return chat_request.demand, "explicit"

    message, history = _inference_inputs(chat_request)
    inferred = infer_chat_demand(message=message, history=history)
    if inferred is None:
        return None, "none"
    return inferred, "inferred"


def resolve_demand(
    chat_request: ChatRequest,
    *,
    infer_chat_demand: Callable[..., dict[str, Any] | None],
) -> DemandResolution:
    raw_demand, source = _resolve_raw_demand(
        chat_request,
        infer_chat_demand=infer_chat_demand,
    )
    message_for_inference, history_for_inference = _inference_inputs(chat_request)
    categories, top_k, retrieval_demand, env = _extract_retrieval_inputs(raw_demand)
    retrieval_demand = _with_query_text(
        retrieval_demand,
        query_text=message_for_inference,
    )
    build_profile = build_request_profile(
        message_text=message_for_inference,
        categories=categories,
        retrieval_demand=retrieval_demand,
    )
    request_mode = "messages" if chat_request.messages else "user_text"
    return DemandResolution(
        raw_demand=raw_demand,
        source=source,
        categories=categories,
        top_k=top_k,
        retrieval_demand=retrieval_demand,
        env=env,
        message_for_inference=message_for_inference,
        history_for_inference=history_for_inference,
        request_mode=request_mode,
        message_chars=len(message_for_inference),
        history_turns=len(history_for_inference),
        build_profile=build_profile,
    )


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
    )


__all__ = [
    "DemandResolution",
    "log_demand_resolution",
    "resolve_demand",
]
