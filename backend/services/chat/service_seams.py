# backend/services/chat/service_seams.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from backend.services.chat.contracts import ChatResponse
from backend.services.chat.provider_caller import ProviderCallResult


@dataclass(slots=True)
class ChatServiceSeams:
    get_ai_settings: Callable[[], Any]
    resolve_demand: Callable[..., Any]
    infer_chat_demand: Callable[..., dict[str, Any] | None]
    log_demand_resolution: Callable[..., None]
    empty_retrieval_artifacts: Callable[..., Any]
    prepare_retrieval_artifacts: Callable[..., Any]
    retrieve_topk_candidates: Callable[..., Any]
    compress_candidates: Callable[..., Any]
    build_context_pack: Callable[..., Any]
    build_provider_messages: Callable[..., list[dict[str, str]]]
    generate_provider_result: Callable[..., ProviderCallResult]
    text_generator: Callable[..., str]
    completion_generator: Callable[..., Any]
    original_text_generator: Callable[..., str]
    normalize_provider_success: Callable[..., Any]
    evaluate_decision_outcome: Callable[..., Any]
    validate_text_response: Callable[..., Any]
    evaluate_text_dq: Callable[..., Any]
    persist_ai_snapshot: Callable[..., str]
    persist_chat_stage_or_quarantine: Callable[..., Any]
    publish_chat_response: Callable[..., Any]
    provider_error_fallback_text: Callable[..., str]
    log_ai_call: Callable[..., None]
    build_chat_response: Callable[..., ChatResponse]
    log_operation: Callable[..., Any]
