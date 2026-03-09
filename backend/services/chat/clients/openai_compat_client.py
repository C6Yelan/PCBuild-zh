# backend/services/chat/clients/openai_compat_client.py
from __future__ import annotations

from dataclasses import dataclass
from time import sleep
from urllib.parse import urlparse, urlunparse

import httpx
from pydantic import SecretStr

from backend.core.oplog import log_operation
from backend.services.chat.retry_policy import (
    RETRY_BACKOFF_SECONDS,
    should_retry_chat_error,
)


@dataclass(slots=True)
class OpenAICompatResult:
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


class OpenAICompatError(RuntimeError):
    def __init__(
        self,
        error_type: str,
        message: str = "",
        *,
        status_code: int | None = None,
        upstream_request_id: str | None = None,
        raw_response_text: str = "",
        response_json: dict[str, object] | None = None,
        response_headers: dict[str, str] | None = None,
        endpoint: str = "",
        request_json: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message or error_type)
        self.error_type = error_type
        self.status_code = status_code
        self.upstream_request_id = upstream_request_id
        self.raw_response_text = raw_response_text
        self.response_json = response_json
        self.response_headers = response_headers or {}
        self.endpoint = endpoint
        self.request_json = request_json or {}


def _normalize_base_url(base_url: str) -> str:
    return base_url.strip().rstrip("/")


def _build_chat_completions_endpoint(base_url: str) -> str:
    parsed = urlparse(_normalize_base_url(base_url))
    path = parsed.path.rstrip("/")
    if not path:
        path = "/v1"
    endpoint_path = f"{path}/chat/completions"
    return urlunparse((parsed.scheme, parsed.netloc, endpoint_path, "", "", ""))


def _extract_upstream_request_id(headers: httpx.Headers) -> str | None:
    for key in ("x-request-id", "request-id"):
        value = headers.get(key)
        if value:
            return value
    return None


def _extract_usage(payload: object) -> dict[str, int] | None:
    if not isinstance(payload, dict):
        return None

    normalized: dict[str, int] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            return None
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            normalized[key] = value
            continue
        if isinstance(value, float) and value.is_integer():
            normalized[key] = int(value)

    return normalized or None


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
    endpoint = _build_chat_completions_endpoint(base_url)
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if client_request_id:
        headers["X-Client-Request-Id"] = client_request_id

    resolved_api_key = (
        api_key.get_secret_value() if isinstance(api_key, SecretStr) else api_key
    )
    if resolved_api_key:
        headers["Authorization"] = f"Bearer {resolved_api_key}"

    payload: dict[str, object] = {
        "model": model,
        "messages": messages,
    }

    def _attempt_once() -> OpenAICompatResult:
        try:
            response = httpx.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise OpenAICompatError(
                "timeout",
                endpoint=endpoint,
                request_json=payload,
            ) from exc
        except httpx.RequestError as exc:
            raise OpenAICompatError(
                "network_error",
                endpoint=endpoint,
                request_json=payload,
            ) from exc

        raw_response_text = getattr(response, "text", "")
        response_headers_obj = getattr(response, "headers", {})
        if isinstance(response_headers_obj, httpx.Headers):
            upstream_request_id = _extract_upstream_request_id(response_headers_obj)
            response_headers = dict(response_headers_obj.items())
        else:
            response_headers = dict(response_headers_obj or {})
            upstream_request_id = None
        response_json: dict[str, object] | None = None

        try:
            parsed_json = response.json()
            if isinstance(parsed_json, dict):
                response_json = parsed_json
        except ValueError:
            parsed_json = None

        if response.status_code == 429:
            raise OpenAICompatError(
                "429",
                status_code=response.status_code,
                upstream_request_id=upstream_request_id,
                raw_response_text=raw_response_text,
                response_json=response_json,
                response_headers=response_headers,
                endpoint=endpoint,
                request_json=payload,
            )
        if response.status_code >= 500:
            raise OpenAICompatError(
                "5xx",
                status_code=response.status_code,
                upstream_request_id=upstream_request_id,
                raw_response_text=raw_response_text,
                response_json=response_json,
                response_headers=response_headers,
                endpoint=endpoint,
                request_json=payload,
            )
        if response.status_code >= 400:
            raise OpenAICompatError(
                "network_error",
                status_code=response.status_code,
                upstream_request_id=upstream_request_id,
                raw_response_text=raw_response_text,
                response_json=response_json,
                response_headers=response_headers,
                endpoint=endpoint,
                request_json=payload,
            )

        if response_json is None:
            raise OpenAICompatError(
                "parse_error",
                status_code=response.status_code,
                upstream_request_id=upstream_request_id,
                raw_response_text=raw_response_text,
                response_json=None,
                response_headers=response_headers,
                endpoint=endpoint,
                request_json=payload,
            )

        try:
            choice = response_json["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise OpenAICompatError(
                "parse_error",
                status_code=response.status_code,
                upstream_request_id=upstream_request_id,
                raw_response_text=raw_response_text,
                response_json=response_json,
                response_headers=response_headers,
                endpoint=endpoint,
                request_json=payload,
            ) from exc

        if not isinstance(choice, str):
            raise OpenAICompatError(
                "parse_error",
                status_code=response.status_code,
                upstream_request_id=upstream_request_id,
                raw_response_text=raw_response_text,
                response_json=response_json,
                response_headers=response_headers,
                endpoint=endpoint,
                request_json=payload,
            )

        response_id = response_json.get("id")
        if not isinstance(response_id, str):
            response_id = None

        finish_reason: str | None = None
        choices = response_json.get("choices")
        if isinstance(choices, list) and choices:
            first_choice = choices[0]
            if isinstance(first_choice, dict):
                raw_finish_reason = first_choice.get("finish_reason")
                if isinstance(raw_finish_reason, str):
                    finish_reason = raw_finish_reason

        usage = _extract_usage(response_json.get("usage"))

        return OpenAICompatResult(
            text=choice.strip(),
            endpoint=endpoint,
            status_code=response.status_code,
            request_headers=headers,
            request_json=payload,
            response_headers=response_headers,
            response_json=response_json,
            raw_response_text=raw_response_text,
            upstream_request_id=upstream_request_id,
            response_id=response_id,
            finish_reason=finish_reason,
            usage=usage,
        )

    attempt = 1
    while True:
        try:
            return _attempt_once()
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
