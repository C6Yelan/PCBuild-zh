# backend/services/chat/service/orchestration.py
"""Focused orchestration helpers for the chat service entrypoint."""

from __future__ import annotations

from time import perf_counter
from uuid import uuid4

from sqlalchemy.orm import Session

from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.contracts import ChatRequest, ChatResponse
from backend.services.chat.provider_caller import ProviderDispatchError
from .execution_flow import (
    build_orchestration_state,
    finish_provider_error_flow,
    finish_success_flow,
    invoke_provider_result,
)
from .seams import ChatServiceSeams


def generate_chat_reply_with_seams(
    chat_request: ChatRequest,
    *,
    db: Session | None = None,
    seams: ChatServiceSeams,
) -> ChatResponse:
    settings = seams.get_ai_settings()
    request_id = uuid4().hex
    started = perf_counter()
    warnings: list[str] = []
    state = build_orchestration_state(
        chat_request=chat_request,
        db=db,
        seams=seams,
        request_id=request_id,
        settings=settings,
        warnings=warnings,
    )

    try:
        provider_result = invoke_provider_result(state=state, seams=seams)
    except (OpenAICompatError, ProviderDispatchError) as exc:
        return finish_provider_error_flow(
            state=state,
            started=started,
            error=exc,
            seams=seams,
        )
    return finish_success_flow(
        state=state,
        started=started,
        provider_result=provider_result,
        seams=seams,
    )


__all__ = ["ChatServiceSeams", "generate_chat_reply_with_seams"]
