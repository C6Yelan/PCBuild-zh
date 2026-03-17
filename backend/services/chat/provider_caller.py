# backend/services/chat/provider_caller.py
"""Provider caller seam for chat orchestration.

Round-1 stable seam:
- provider message construction for upstream calls
- provider dispatch and provider-result contract
- keep service-level wrappers thin so tests/harness can stop patching
  ``backend.services.chat.service`` internals directly
"""

from __future__ import annotations

from backend.services.chat.clients.openai_compat_client import (
    generate_openai_compat_completion,
    generate_openai_compat_text,
)
from backend.services.chat.config import (
    AISettings,
    SYSTEM_PROMPT,
    build_provider_runtime_config,
)
from backend.services.chat.provider_call_models import (
    ProviderCallResult,
    ProviderCompletionGenerator,
    ProviderDispatchError,
    ProviderTextGenerator,
)
from backend.services.chat.provider_runtime_dispatch import (
    build_provider_config_error,
    dispatch_provider_runtime,
)
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.prompt import build_prompt

_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT = generate_openai_compat_text


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
        raise build_provider_config_error(
            settings=settings,
            messages=messages,
            error=exc,
        ) from exc

    return dispatch_provider_runtime(
        runtime=runtime,
        settings=settings,
        messages=messages,
        request_id=request_id,
        text_generator=resolved_text_generator,
        completion_generator=resolved_completion_generator,
        original_text_generator=resolved_original_text_generator,
    )


__all__ = [
    "ProviderCallResult",
    "ProviderDispatchError",
    "build_provider_messages",
    "generate_provider_result",
]
