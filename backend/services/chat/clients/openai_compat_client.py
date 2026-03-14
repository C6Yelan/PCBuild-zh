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


@dataclass(slots=True)
class _OpenAICompatRequest:
    endpoint: str
    headers: dict[str, str]
    payload: dict[str, object]
    timeout_seconds: float


@dataclass(slots=True)
class _OpenAICompatResponse:
    request: _OpenAICompatRequest
    status_code: int
    raw_response_text: str
    response_headers: dict[str, str]
    response_json: dict[str, object] | None
    upstream_request_id: str | None


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


def _resolve_api_key(api_key: SecretStr | str | None) -> str | None:
    if isinstance(api_key, SecretStr):
        return api_key.get_secret_value()
    return api_key


def _build_request_headers(
    *,
    api_key: SecretStr | str | None,
    client_request_id: str | None,
) -> dict[str, str]:
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if client_request_id:
        headers["X-Client-Request-Id"] = client_request_id

    resolved_api_key = _resolve_api_key(api_key)
    if resolved_api_key:
        headers["Authorization"] = f"Bearer {resolved_api_key}"
    return headers


def _build_request_payload(
    *,
    model: str,
    messages: list[dict[str, str]],
) -> dict[str, object]:
    return {
        "model": model,
        "messages": messages,
    }


def _build_openai_compat_request(
    *,
    base_url: str,
    api_key: SecretStr | str | None,
    model: str,
    messages: list[dict[str, str]],
    timeout_seconds: float,
    client_request_id: str | None,
) -> _OpenAICompatRequest:
    return _OpenAICompatRequest(
        endpoint=_build_chat_completions_endpoint(base_url),
        headers=_build_request_headers(
            api_key=api_key,
            client_request_id=client_request_id,
        ),
        payload=_build_request_payload(model=model, messages=messages),
        timeout_seconds=timeout_seconds,
    )


def _build_openai_compat_error(
    error_type: str,
    *,
    request: _OpenAICompatRequest,
    response: _OpenAICompatResponse | None = None,
) -> OpenAICompatError:
    return OpenAICompatError(
        error_type,
        status_code=response.status_code if response is not None else None,
        upstream_request_id=(
            response.upstream_request_id if response is not None else None
        ),
        raw_response_text=response.raw_response_text if response is not None else "",
        response_json=response.response_json if response is not None else None,
        response_headers=response.response_headers if response is not None else None,
        endpoint=request.endpoint,
        request_json=request.payload,
    )


def _extract_response_metadata(
    headers_obj: object,
) -> tuple[dict[str, str], str | None]:
    if isinstance(headers_obj, httpx.Headers):
        return dict(headers_obj.items()), _extract_upstream_request_id(headers_obj)
    return dict(headers_obj or {}), None


def _parse_response_json(response: object) -> dict[str, object] | None:
    try:
        parsed_json = response.json()
    except ValueError:
        return None
    if isinstance(parsed_json, dict):
        return parsed_json
    return None


def _send_openai_compat_request(
    request: _OpenAICompatRequest,
) -> _OpenAICompatResponse:
    try:
        response = httpx.post(
            request.endpoint,
            headers=request.headers,
            json=request.payload,
            timeout=request.timeout_seconds,
        )
    except httpx.TimeoutException as exc:
        raise _build_openai_compat_error("timeout", request=request) from exc
    except httpx.RequestError as exc:
        raise _build_openai_compat_error("network_error", request=request) from exc

    response_headers, upstream_request_id = _extract_response_metadata(
        getattr(response, "headers", {})
    )
    return _OpenAICompatResponse(
        request=request,
        status_code=response.status_code,
        raw_response_text=getattr(response, "text", ""),
        response_headers=response_headers,
        response_json=_parse_response_json(response),
        upstream_request_id=upstream_request_id,
    )


def _map_status_error_type(status_code: int) -> str | None:
    if status_code == 429:
        return "429"
    if status_code >= 500:
        return "5xx"
    if status_code >= 400:
        return "network_error"
    return None


def _raise_for_error_status(response: _OpenAICompatResponse) -> None:
    error_type = _map_status_error_type(response.status_code)
    if error_type is not None:
        raise _build_openai_compat_error(
            error_type,
            request=response.request,
            response=response,
        )


def _extract_choice_text(response: _OpenAICompatResponse) -> str:
    response_json = response.response_json
    if response_json is None:
        raise _build_openai_compat_error(
            "parse_error",
            request=response.request,
            response=response,
        )

    try:
        choice = response_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise _build_openai_compat_error(
            "parse_error",
            request=response.request,
            response=response,
        ) from exc

    if not isinstance(choice, str):
        raise _build_openai_compat_error(
            "parse_error",
            request=response.request,
            response=response,
        )
    return choice


def _extract_response_id(response_json: dict[str, object]) -> str | None:
    response_id = response_json.get("id")
    if isinstance(response_id, str):
        return response_id
    return None


def _extract_finish_reason(response_json: dict[str, object]) -> str | None:
    choices = response_json.get("choices")
    if isinstance(choices, list) and choices:
        first_choice = choices[0]
        if isinstance(first_choice, dict):
            raw_finish_reason = first_choice.get("finish_reason")
            if isinstance(raw_finish_reason, str):
                return raw_finish_reason
    return None


def _parse_openai_compat_result(
    response: _OpenAICompatResponse,
) -> OpenAICompatResult:
    _raise_for_error_status(response)
    choice = _extract_choice_text(response)
    response_json = response.response_json
    if response_json is None:
        raise _build_openai_compat_error(
            "parse_error",
            request=response.request,
            response=response,
        )

    return OpenAICompatResult(
        text=choice.strip(),
        endpoint=response.request.endpoint,
        status_code=response.status_code,
        request_headers=response.request.headers,
        request_json=response.request.payload,
        response_headers=response.response_headers,
        response_json=response_json,
        raw_response_text=response.raw_response_text,
        upstream_request_id=response.upstream_request_id,
        response_id=_extract_response_id(response_json),
        finish_reason=_extract_finish_reason(response_json),
        usage=_extract_usage(response_json.get("usage")),
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
    request = _build_openai_compat_request(
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
            response = _send_openai_compat_request(request)
            return _parse_openai_compat_result(response)
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
