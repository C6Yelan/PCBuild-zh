# backend/services/chat/clients/openai_compat_client.py
from __future__ import annotations

from time import sleep

import httpx
from pydantic import SecretStr

from backend.core.oplog import log_operation
from backend.services.chat.clients.openai_compat_models import (
    OpenAICompatError,
    OpenAICompatResult,
)
from backend.services.chat.clients.openai_compat_response import (
    parse_openai_compat_result,
)
from backend.services.chat.clients.openai_compat_transport import (
    build_openai_compat_request,
    send_openai_compat_request,
)
from backend.services.chat.retry_policy import (
    RETRY_BACKOFF_SECONDS,
    should_retry_chat_error,
)


def generate_openai_compat_completion(
    *,
    base_url: str,
    api_key: SecretStr | str | None,
    model: str,
    messages: list[dict[str, str]],
    timeout_seconds: float,
    client_request_id: str | None = None,
    provider: str = "openai_compat",
) -> OpenAICompatResult:
    request = build_openai_compat_request(
        base_url=base_url,
        api_key=api_key,
        model=model,
        messages=messages,
        timeout_seconds=timeout_seconds,
        client_request_id=client_request_id,
    )

    attempt = 1
    while True:
        try:
            response = send_openai_compat_request(request, http_post=httpx.post)
            return parse_openai_compat_result(response)
        except OpenAICompatError as exc:
            if not should_retry_chat_error(exc.error_type, attempt=attempt):
                raise

            attempt += 1
            log_operation(
                "ai_retry",
                request_id=client_request_id or "-",
                provider=provider,
                model=model,
                attempt=attempt,
                error_type=exc.error_type,
            )
            sleep(RETRY_BACKOFF_SECONDS)


def generate_openai_compat_text(
    *,
    base_url: str,
    api_key: SecretStr | str | None,
    model: str,
    messages: list[dict[str, str]],
    timeout_seconds: float,
    client_request_id: str | None = None,
    provider: str = "openai_compat",
) -> str:
    result = generate_openai_compat_completion(
        base_url=base_url,
        api_key=api_key,
        model=model,
        messages=messages,
        timeout_seconds=timeout_seconds,
        client_request_id=client_request_id,
        provider=provider,
    )
    return result.text
