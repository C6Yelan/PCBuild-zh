# backend/services/chat/service.py
"""Chat orchestration entrypoint.

Round-3 public boundary:
- keep ``generate_chat_reply`` importable from this module and from
  ``backend.services.chat``.
- keep this module as the stable patch point for tests and ops, while
  detailed orchestration helpers live in sibling modules.
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
import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.snapshot_store as chat_snapshot_store
from backend.services.chat.service_orchestration import (
    ChatServiceSeams,
    generate_chat_reply_with_seams,
)
from backend.services.chat.staging import (
    persist_chat_stage_or_quarantine as persist_chat_stage_or_quarantine_seam,
)

_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT = generate_openai_compat_text


def build_chat_service_seams() -> ChatServiceSeams:
    return ChatServiceSeams(
        get_ai_settings=get_ai_settings,
        resolve_demand=resolve_demand,
        infer_chat_demand=infer_chat_demand,
        log_demand_resolution=log_demand_resolution,
        empty_retrieval_artifacts=empty_retrieval_artifacts,
        prepare_retrieval_artifacts=prepare_retrieval_artifacts,
        retrieve_topk_candidates=retrieve_topk_candidates,
        compress_candidates=compress_candidates,
        build_context_pack=build_context_pack,
        build_provider_messages=chat_provider_caller.build_provider_messages,
        generate_provider_result=chat_provider_caller.generate_provider_result,
        text_generator=generate_openai_compat_text,
        completion_generator=generate_openai_compat_completion,
        original_text_generator=_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT,
        normalize_provider_success=normalize_provider_success,
        evaluate_decision_outcome=evaluate_decision_outcome,
        validate_text_response=validate_text_response,
        evaluate_text_dq=evaluate_text_dq,
        persist_ai_snapshot=chat_snapshot_store.persist_ai_snapshot,
        persist_chat_stage_or_quarantine=persist_chat_stage_or_quarantine_seam,
        publish_chat_response=publish_chat_response,
        provider_error_fallback_text=provider_error_fallback_text,
        log_ai_call=log_ai_call,
        build_chat_response=build_chat_response,
        log_operation=log_operation,
    )


def generate_chat_reply(chat_request: ChatRequest, *, db: Session | None = None) -> ChatResponse:
    # Keep this module as the stable generate_chat_reply patch/import surface for
    # backend.services.chat, tests, and ops CLIs.
    return generate_chat_reply_with_seams(
        chat_request,
        db=db,
        seams=build_chat_service_seams(),
    )
