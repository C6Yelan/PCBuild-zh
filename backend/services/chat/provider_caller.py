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

from backend.services.chat.clients.openai_compat_client import (
    OpenAICompatResult,
    generate_openai_compat_completion,
    generate_openai_compat_text,
)
from backend.services.chat.config import (
    AISettings,
    GeminiRuntimeConfig,
    OpenAICompatRuntimeConfig,
    SYSTEM_PROMPT,
    build_provider_runtime_config,
    resolve_secret_text,
)
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.prompt import build_prompt

_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT = generate_openai_compat_text

ProviderTextGenerator = Callable[..., str]
ProviderCompletionGenerator = Callable[..., OpenAICompatResult]


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
    runtime: OpenAICompatRuntimeConfig,
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
        endpoint=runtime.base_url or "-",
        status_code=200,
        request_headers=request_headers,
        request_json={"model": runtime.model, "messages": messages},
        response_headers={},
        response_json=None,
        raw_response_text=text,
        upstream_request_id=None,
    )


def _dispatch_openai_compat_runtime(
    *,
    runtime: OpenAICompatRuntimeConfig,
    messages: list[dict[str, str]],
    request_id: str,
    text_generator: ProviderTextGenerator,
    completion_generator: ProviderCompletionGenerator,
    original_text_generator: ProviderTextGenerator,
) -> ProviderCallResult:
    if not runtime.base_url:
        raise ProviderDispatchError(
            "config_error",
            "AI_OAI_BASE_URL is required for openai-compatible providers.",
            request_json={"model": runtime.model, "messages": messages},
        )

    resolved_api_key = resolve_secret_text(runtime.api_key)
    if text_generator is not original_text_generator:
        text = text_generator(
            base_url=runtime.base_url,
            api_key=resolved_api_key,
            model=runtime.model,
            messages=messages,
            timeout_seconds=runtime.timeout_seconds,
            client_request_id=request_id,
            provider=runtime.provider,
        )
        return _fallback_text_result(
            runtime=runtime,
            messages=messages,
            request_id=request_id,
            text=text,
        )

    result = completion_generator(
        base_url=runtime.base_url,
        api_key=resolved_api_key,
        model=runtime.model,
        messages=messages,
        timeout_seconds=runtime.timeout_seconds,
        client_request_id=request_id,
        provider=runtime.provider,
    )
    return _coerce_provider_result(result)


def _dispatch_gemini_runtime(
    *,
    runtime: GeminiRuntimeConfig,
    messages: list[dict[str, str]],
) -> ProviderCallResult:
    raise ProviderDispatchError(
        "provider_not_ready",
        "Gemini provider dispatch is reserved for A5 implementation.",
        request_json={"model": runtime.model, "messages": messages},
    )


def generate_provider_result(
    *,
    settings: AISettings,
    messages: list[dict[str, str]],
    request_id: str,
    text_generator: ProviderTextGenerator | None = None,
    completion_generator: ProviderCompletionGenerator | None = None,
    original_text_generator: ProviderTextGenerator | None = None,
) -> ProviderCallResult:
    resolved_text_generator = text_generator or generate_openai_compat_text
    resolved_completion_generator = (
        completion_generator or generate_openai_compat_completion
    )
    resolved_original_text_generator = (
        original_text_generator or _ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT
    )

    try:
        runtime = build_provider_runtime_config(settings)
    except ValueError as exc:
        raise ProviderDispatchError(
            "config_error",
            str(exc),
            request_json={"model": getattr(settings, "ai_model", ""), "messages": messages},
        ) from exc

    if isinstance(runtime, OpenAICompatRuntimeConfig):
        return _dispatch_openai_compat_runtime(
            runtime=runtime,
            messages=messages,
            request_id=request_id,
            text_generator=resolved_text_generator,
            completion_generator=resolved_completion_generator,
            original_text_generator=resolved_original_text_generator,
        )
    if isinstance(runtime, GeminiRuntimeConfig):
        return _dispatch_gemini_runtime(
            runtime=runtime,
            messages=messages,
        )
    raise ProviderDispatchError(
        "config_error",
        f"Unsupported AI provider: {getattr(settings, 'ai_provider', '')}",
        request_json={"model": getattr(settings, "ai_model", ""), "messages": messages},
    )


__all__ = [
    "ProviderCallResult",
    "ProviderDispatchError",
    "build_provider_messages",
    "generate_provider_result",
]
