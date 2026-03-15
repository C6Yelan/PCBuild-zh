from __future__ import annotations

from backend.services.chat.clients.openai_compat_models import OpenAICompatResult
from backend.services.chat.config import (
    GeminiRuntimeConfig,
    OpenAICompatRuntimeConfig,
    ProviderRuntimeConfig,
    resolve_secret_text,
)
from backend.services.chat.provider_call_models import (
    ProviderCallResult,
    ProviderCompletionGenerator,
    ProviderDispatchError,
    ProviderTextGenerator,
)


def coerce_provider_result(result: OpenAICompatResult) -> ProviderCallResult:
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


def fallback_text_result(
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


def build_provider_config_error(
    *,
    settings: object,
    messages: list[dict[str, str]],
    error: Exception,
) -> ProviderDispatchError:
    return ProviderDispatchError(
        "config_error",
        str(error),
        request_json={"model": getattr(settings, "ai_model", ""), "messages": messages},
    )


def build_unsupported_provider_error(
    *,
    settings: object,
    messages: list[dict[str, str]],
) -> ProviderDispatchError:
    return ProviderDispatchError(
        "config_error",
        f"Unsupported AI provider: {getattr(settings, 'ai_provider', '')}",
        request_json={"model": getattr(settings, "ai_model", ""), "messages": messages},
    )


def dispatch_provider_runtime(
    *,
    runtime: ProviderRuntimeConfig | object,
    settings: object,
    messages: list[dict[str, str]],
    request_id: str,
    text_generator: ProviderTextGenerator,
    completion_generator: ProviderCompletionGenerator,
    original_text_generator: ProviderTextGenerator,
) -> ProviderCallResult:
    if isinstance(runtime, OpenAICompatRuntimeConfig):
        return _dispatch_openai_compat_runtime(
            runtime=runtime,
            messages=messages,
            request_id=request_id,
            text_generator=text_generator,
            completion_generator=completion_generator,
            original_text_generator=original_text_generator,
        )
    if isinstance(runtime, GeminiRuntimeConfig):
        raise _dispatch_gemini_runtime(
            runtime=runtime,
            messages=messages,
        )
    raise build_unsupported_provider_error(settings=settings, messages=messages)


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
        return fallback_text_result(
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
    return coerce_provider_result(result)


def _dispatch_gemini_runtime(
    *,
    runtime: GeminiRuntimeConfig,
    messages: list[dict[str, str]],
) -> ProviderDispatchError:
    return ProviderDispatchError(
        "provider_not_ready",
        "Gemini provider dispatch is reserved for A5 implementation.",
        request_json={"model": runtime.model, "messages": messages},
    )
