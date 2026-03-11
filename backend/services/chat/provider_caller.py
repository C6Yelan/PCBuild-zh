"""Provider caller seam for chat orchestration.

Round-1 stable seam:
- provider message construction for upstream calls
- provider dispatch and provider-result contract
- keep service-level wrappers thin so tests/harness can stop patching
  ``backend.services.chat.service`` internals directly
"""
# backend/services/chat/provider_caller.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from pydantic import SecretBytes, SecretStr

from backend.services.chat.clients.openai_compat_client import (
    OpenAICompatResult,
    generate_openai_compat_completion,
    generate_openai_compat_text,
)
from backend.services.chat.config import (
    OPENAI_COMPAT_PROVIDERS,
    AISettings,
    SYSTEM_PROMPT,
)
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.prompt import build_prompt

_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT = generate_openai_compat_text


@dataclass(slots=True)
class ProviderCallResult:
    text: str
    endpoint: str
    status_code: int
    request_headers: dict[str, str]
    request_json: dict[str, object]
    response_headers: dict[str, str]
    response_json: dict[str, object] | None
    raw_response_text: str
    upstream_request_id: str | None
    response_id: str | None = None
    finish_reason: str | None = None
    usage: dict[str, int] | None = None


class ProviderDispatchError(RuntimeError):
    def __init__(
        self,
        error_type: str,
        message: str,
        *,
        endpoint: str = "",
        request_json: dict[str, object] | None = None,
        response_headers: dict[str, str] | None = None,
        response_json: dict[str, object] | None = None,
        raw_response_text: str = "",
        status_code: int | None = None,
        upstream_request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.endpoint = endpoint
        self.request_json = request_json or {}
        self.response_headers = response_headers or {}
        self.response_json = response_json
        self.raw_response_text = raw_response_text
        self.status_code = status_code
        self.upstream_request_id = upstream_request_id


def _normalize_role(role: str) -> str:
    if role == "ai":
        return "assistant"
    return role


def _strip_internal_system_prompt(prompt: str) -> str:
    prefixed = f"{SYSTEM_PROMPT}\n\n"
    if prompt.startswith(prefixed):
        return prompt[len(prefixed) :]
    if prompt.startswith(SYSTEM_PROMPT):
        return prompt[len(SYSTEM_PROMPT) :].lstrip()
    return prompt


def build_provider_messages(
    chat_request: ChatRequest,
    *,
    context_pack_text: str | None = None,
) -> list[dict[str, str]]:
    if chat_request.messages:
        provider_messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        provider_messages.extend(
            {"role": _normalize_role(message.role), "content": message.content}
            for message in chat_request.messages
        )
        if context_pack_text:
            provider_messages.append(
                {
                    "role": "user",
                    "content": f"## CONTEXT_PACK\n{context_pack_text}",
                }
            )
        return provider_messages

    prompt = build_prompt(
        message=chat_request.user_text or "",
        history=chat_request.history,
    )
    prompt = _strip_internal_system_prompt(prompt)
    if chat_request.demand and not isinstance(chat_request.demand, dict):
        prompt = f"{prompt}\n\n需求補充：{chat_request.demand}"
    if context_pack_text:
        prompt = f"{prompt}\n\n## CONTEXT_PACK\n{context_pack_text}"
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]


def _resolve_api_key(api_key: SecretStr | SecretBytes | str | None) -> str | None:
    if isinstance(api_key, SecretStr):
        return api_key.get_secret_value()
    if isinstance(api_key, SecretBytes):
        value = api_key.get_secret_value()
        return value.decode("utf-8", errors="ignore")
    if isinstance(api_key, str):
        return api_key
    return None


def _coerce_provider_result(result: OpenAICompatResult) -> ProviderCallResult:
    return ProviderCallResult(
        text=result.text,
        endpoint=result.endpoint,
        status_code=result.status_code,
        request_headers=result.request_headers,
        request_json=result.request_json,
        response_headers=result.response_headers,
        response_json=result.response_json,
        raw_response_text=result.raw_response_text,
        upstream_request_id=result.upstream_request_id,
        response_id=result.response_id,
        finish_reason=result.finish_reason,
        usage=result.usage,
    )


def _fallback_text_result(
    *,
    settings: AISettings,
    messages: list[dict[str, str]],
    request_id: str,
    text: str,
) -> ProviderCallResult:
    request_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Client-Request-Id": request_id,
    }
    return ProviderCallResult(
        text=text,
        endpoint=settings.ai_oai_base_url or "-",
        status_code=200,
        request_headers=request_headers,
        request_json={"model": settings.ai_model, "messages": messages},
        response_headers={},
        response_json=None,
        raw_response_text=text,
        upstream_request_id=None,
    )


def generate_provider_result(
    *,
    settings: AISettings,
    messages: list[dict[str, str]],
    request_id: str,
    text_generator: Callable[..., str] | None = None,
    completion_generator: Callable[..., OpenAICompatResult] | None = None,
    original_text_generator: Callable[..., str] | None = None,
) -> ProviderCallResult:
    provider = settings.ai_provider
    resolved_text_generator = text_generator or generate_openai_compat_text
    resolved_completion_generator = (
        completion_generator or generate_openai_compat_completion
    )
    resolved_original_text_generator = (
        original_text_generator or _ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT
    )

    if provider in OPENAI_COMPAT_PROVIDERS:
        if not settings.ai_oai_base_url:
            raise ProviderDispatchError(
                "config_error",
                "AI_OAI_BASE_URL is required for openai-compatible providers.",
                request_json={"model": settings.ai_model, "messages": messages},
            )

        if resolved_text_generator is not resolved_original_text_generator:
            text = resolved_text_generator(
                base_url=settings.ai_oai_base_url,
                api_key=_resolve_api_key(settings.ai_oai_api_key),
                model=settings.ai_model,
                messages=messages,
                timeout_seconds=settings.ai_timeout_seconds,
                client_request_id=request_id,
                provider=provider,
            )
            return _fallback_text_result(
                settings=settings,
                messages=messages,
                request_id=request_id,
                text=text,
            )

        result = resolved_completion_generator(
            base_url=settings.ai_oai_base_url,
            api_key=_resolve_api_key(settings.ai_oai_api_key),
            model=settings.ai_model,
            messages=messages,
            timeout_seconds=settings.ai_timeout_seconds,
            client_request_id=request_id,
            provider=provider,
        )
        return _coerce_provider_result(result)

    if provider == "gemini":
        raise ProviderDispatchError(
            "provider_not_ready",
            "Gemini provider dispatch is reserved for A5 implementation.",
            request_json={"model": settings.ai_model, "messages": messages},
        )
    raise ProviderDispatchError(
        "config_error",
        f"Unsupported AI provider: {provider}",
        request_json={"model": settings.ai_model, "messages": messages},
    )


__all__ = [
    "ProviderCallResult",
    "ProviderDispatchError",
    "build_provider_messages",
    "generate_provider_result",
]
