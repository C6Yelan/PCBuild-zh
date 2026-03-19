# backend/services/chat/service/__init__.py
"""Chat orchestration entrypoint.

Round-3 public boundary:
- keep ``generate_chat_reply`` importable from this module and from
  ``backend.services.chat``.
- keep this package as the stable patch point for tests and ops, while
  detailed orchestration helpers live in package-local modules.
"""

from __future__ import annotations

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
from backend.services.chat.provider_caller import ProviderDispatchError
from .decisions import evaluate_decision_outcome
from .demand import (
    log_demand_resolution,
    resolve_demand,
)
from .response import (
    build_chat_response,
    log_ai_call,
    provider_error_fallback_text,
    publish_chat_response,
)
from .retrieval import prepare_retrieval_artifacts
import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.snapshot_store as chat_snapshot_store
from .orchestration import (
    ChatServiceSeams,
    generate_chat_reply_with_seams,
)
from .seams import (
    ChatObservabilitySeams,
    ChatPersistenceSeams,
    ChatPolicySeams,
    ChatProviderSeams,
)
from backend.services.chat.staging import (
    persist_chat_stage_or_quarantine as persist_chat_stage_or_quarantine_seam,
)

_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT = generate_openai_compat_text


def _resolve_chat_demand(
    chat_request: ChatRequest,
    *,
    settings: object,
    request_id: str,
    generate_provider_result: object,
    log_operation: object,
) -> object:
    return resolve_demand(
        chat_request,
        settings=settings,
        request_id=request_id,
        generate_provider_result=generate_provider_result,
        log_operation=log_operation,
        infer_chat_demand=infer_chat_demand,
    )


def _prepare_chat_retrieval_artifacts(
    *,
    db: object,
    settings: object,
    categories: list[str],
    top_k: int,
    retrieval_demand: object,
    build_profile: object,
    normalized_demand: object,
    env: str,
    warnings: list[str],
) -> object:
    return prepare_retrieval_artifacts(
        db=db,
        settings=settings,
        categories=categories,
        top_k=top_k,
        retrieval_demand=retrieval_demand,
        build_profile=build_profile,
        normalized_demand=normalized_demand,
        env=env,
        warnings=warnings,
        retrieve_topk_candidates=retrieve_topk_candidates,
        compress_candidates=compress_candidates,
        build_context_pack=build_context_pack,
        log_operation=log_operation,
    )


def _generate_chat_provider_result(
    *,
    settings: object,
    messages: list[dict[str, str]],
    request_id: str,
    extra_payload: dict[str, object] | None = None,
) -> object:
    return chat_provider_caller.generate_provider_result(
        settings=settings,
        messages=messages,
        request_id=request_id,
        extra_payload=extra_payload,
        text_generator=generate_openai_compat_text,
        completion_generator=generate_openai_compat_completion,
        original_text_generator=_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT,
    )


def _evaluate_chat_decision_outcome(**kwargs: object) -> object:
    return evaluate_decision_outcome(
        validate_text_response=validate_text_response,
        evaluate_text_dq=evaluate_text_dq,
        **kwargs,
    )


def build_chat_service_seams() -> ChatServiceSeams:
    return ChatServiceSeams(
        get_ai_settings=get_ai_settings,
        provider=ChatProviderSeams(
            build_provider_messages=chat_provider_caller.build_provider_messages,
            generate_provider_result=_generate_chat_provider_result,
        ),
        policy=ChatPolicySeams(
            resolve_demand=_resolve_chat_demand,
            log_demand_resolution=log_demand_resolution,
            prepare_retrieval_artifacts=_prepare_chat_retrieval_artifacts,
            normalize_provider_success=normalize_provider_success,
            evaluate_decision_outcome=_evaluate_chat_decision_outcome,
            publish_chat_response=publish_chat_response,
            provider_error_fallback_text=provider_error_fallback_text,
            build_chat_response=build_chat_response,
        ),
        persistence=ChatPersistenceSeams(
            persist_ai_snapshot=chat_snapshot_store.persist_ai_snapshot,
            persist_chat_stage_or_quarantine=persist_chat_stage_or_quarantine_seam,
        ),
        observability=ChatObservabilitySeams(
            log_operation=log_operation,
            log_ai_call=log_ai_call,
        ),
    )


def generate_chat_reply(chat_request: ChatRequest, *, db: Session | None = None) -> ChatResponse:
    # Keep this module as the stable generate_chat_reply patch/import surface for
    # backend.services.chat, tests, and ops CLIs.
    return generate_chat_reply_with_seams(
        chat_request,
        db=db,
        seams=build_chat_service_seams(),
    )


__all__ = [
    "ChatServiceSeams",
    "build_chat_service_seams",
    "generate_chat_reply",
]
