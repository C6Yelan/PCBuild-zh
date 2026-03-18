# backend/services/chat/service/seams.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from backend.services.chat.contracts import ChatResponse
from backend.services.chat.provider import ProviderCallResult


@dataclass(slots=True)
class ChatProviderSeams:
    build_provider_messages: Callable[..., list[dict[str, str]]]
    generate_provider_result: Callable[..., ProviderCallResult]


@dataclass(slots=True)
class ChatPolicySeams:
    resolve_demand: Callable[..., Any]
    log_demand_resolution: Callable[..., None]
    prepare_retrieval_artifacts: Callable[..., Any]
    normalize_provider_success: Callable[..., Any]
    evaluate_decision_outcome: Callable[..., Any]
    publish_chat_response: Callable[..., Any]
    provider_error_fallback_text: Callable[..., str]
    build_chat_response: Callable[..., ChatResponse]


@dataclass(slots=True)
class ChatPersistenceSeams:
    persist_ai_snapshot: Callable[..., str]
    persist_chat_stage_or_quarantine: Callable[..., Any]


@dataclass(slots=True)
class ChatObservabilitySeams:
    log_operation: Callable[..., Any]
    log_ai_call: Callable[..., None]


@dataclass(slots=True)
class ChatServiceSeams:
    get_ai_settings: Callable[[], Any]
    provider: ChatProviderSeams
    policy: ChatPolicySeams
    persistence: ChatPersistenceSeams
    observability: ChatObservabilitySeams


__all__ = [
    "ChatObservabilitySeams",
    "ChatPersistenceSeams",
    "ChatPolicySeams",
    "ChatProviderSeams",
    "ChatServiceSeams",
]
