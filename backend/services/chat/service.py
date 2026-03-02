# backend/services/chat/service.py
from __future__ import annotations

from time import perf_counter
from uuid import uuid4

from backend.services.chat.clients import OpenAICompatError, generate_openai_compat_text
from backend.services.chat.config import get_ai_settings
from backend.services.chat.contracts import ChatRequest, ChatResponse
from backend.services.chat.prompt import build_prompt


def _normalize_role(role: str) -> str:
    if role == "ai":
        return "assistant"
    return role


def _build_provider_messages(chat_request: ChatRequest) -> list[dict[str, str]]:
    if chat_request.messages:
        return [
            {"role": _normalize_role(m.role), "content": m.content}
            for m in chat_request.messages
        ]

    prompt = build_prompt(
        message=chat_request.user_text or "",
        history=chat_request.history,
    )
    if chat_request.demand:
        prompt = f"{prompt}\n\n需求補充：{chat_request.demand}"
    return [{"role": "user", "content": prompt}]


def _truncate_text(text: str, max_chars: int, warnings: list[str]) -> str:
    if len(text) <= max_chars:
        return text
    warnings.append("output_truncated")
    return text[:max_chars]


def generate_chat_reply(chat_request: ChatRequest) -> ChatResponse:
    settings = get_ai_settings()
    request_id = uuid4().hex
    started = perf_counter()
    warnings: list[str] = []

    try:
        response_text = generate_openai_compat_text(
            base_url=settings.ai_oai_base_url,
            api_key=(
                settings.ai_oai_api_key.get_secret_value()
                if settings.ai_oai_api_key
                else None
            ),
            model=settings.ai_model,
            messages=_build_provider_messages(chat_request),
            timeout_seconds=settings.ai_timeout_seconds,
        )
        response_text = _truncate_text(
            response_text,
            max_chars=settings.ai_max_output_chars,
            warnings=warnings,
        )
        return ChatResponse(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            text=response_text,
            latency_ms=int((perf_counter() - started) * 1000),
            warnings=warnings or None,
        )
    except OpenAICompatError as exc:
        return ChatResponse(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            text="目前 AI 服務暫時不可用，請稍後再試。",
            latency_ms=int((perf_counter() - started) * 1000),
            error_type=exc.error_type,
            warnings=warnings or None,
        )
