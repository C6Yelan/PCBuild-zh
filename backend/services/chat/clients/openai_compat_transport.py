# backend/services/chat/clients/openai_compat_transport.py
from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlparse, urlunparse

import httpx
from pydantic import SecretStr

from .openai_compat_models import (
    OpenAICompatError,
    OpenAICompatRequest,
    OpenAICompatResponse,
)


def normalize_openai_compat_base_url(base_url: str) -> str:
    return base_url.strip().rstrip("/")


def build_chat_completions_endpoint(base_url: str) -> str:
    parsed = urlparse(normalize_openai_compat_base_url(base_url))
    path = parsed.path.rstrip("/")
    if not path:
        path = "/v1"
    endpoint_path = f"{path}/chat/completions"
    return urlunparse((parsed.scheme, parsed.netloc, endpoint_path, "", "", ""))


def extract_upstream_request_id(headers: httpx.Headers) -> str | None:
    for key in ("x-request-id", "request-id"):
        value = headers.get(key)
        if value:
            return value
    return None


def resolve_openai_compat_api_key(api_key: SecretStr | str | None) -> str | None:
    if isinstance(api_key, SecretStr):
        return api_key.get_secret_value()
    return api_key


def build_openai_compat_request(
    *,
    base_url: str,
    api_key: SecretStr | str | None,
    model: str,
    messages: list[dict[str, str]],
    timeout_seconds: float,
    client_request_id: str | None,
    extra_payload: dict[str, object] | None = None,
) -> OpenAICompatRequest:
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if client_request_id:
        headers["X-Client-Request-Id"] = client_request_id

    resolved_api_key = resolve_openai_compat_api_key(api_key)
    if resolved_api_key:
        headers["Authorization"] = f"Bearer {resolved_api_key}"

    payload: dict[str, object] = {
        "model": model,
        "messages": messages,
    }
    if extra_payload:
        payload.update(extra_payload)

    return OpenAICompatRequest(
        endpoint=build_chat_completions_endpoint(base_url),
        headers=headers,
        payload=payload,
        timeout_seconds=timeout_seconds,
    )


def build_openai_compat_error(
    error_type: str,
    *,
    request: OpenAICompatRequest,
    response: OpenAICompatResponse | None = None,
) -> OpenAICompatError:
    return OpenAICompatError(
        error_type,
        status_code=response.status_code if response is not None else None,
        upstream_request_id=response.upstream_request_id if response is not None else None,
        raw_response_text=response.raw_response_text if response is not None else "",
        response_json=response.response_json if response is not None else None,
        response_headers=response.response_headers if response is not None else None,
        endpoint=request.endpoint,
        request_json=request.payload,
    )


def _extract_response_metadata(headers_obj: object) -> tuple[dict[str, str], str | None]:
    if isinstance(headers_obj, httpx.Headers):
        return dict(headers_obj.items()), extract_upstream_request_id(headers_obj)
    return dict(headers_obj or {}), None


def _parse_response_json(response: object) -> dict[str, object] | None:
    try:
        parsed_json = response.json()
    except ValueError:
        return None
    if isinstance(parsed_json, dict):
        return parsed_json
    return None


def send_openai_compat_request(
    request: OpenAICompatRequest,
    *,
    http_post: Callable[..., object],
) -> OpenAICompatResponse:
    try:
        response = http_post(
            request.endpoint,
            headers=request.headers,
            json=request.payload,
            timeout=request.timeout_seconds,
        )
    except httpx.TimeoutException as exc:
        raise build_openai_compat_error("timeout", request=request) from exc
    except httpx.RequestError as exc:
        raise build_openai_compat_error("network_error", request=request) from exc

    response_headers, upstream_request_id = _extract_response_metadata(
        getattr(response, "headers", {})
    )
    return OpenAICompatResponse(
        request=request,
        status_code=response.status_code,
        raw_response_text=getattr(response, "text", ""),
        response_headers=response_headers,
        response_json=_parse_response_json(response),
        upstream_request_id=upstream_request_id,
    )


def map_openai_compat_status_error_type(status_code: int) -> str | None:
    if status_code == 429:
        return "429"
    if status_code >= 500:
        return "5xx"
    if status_code >= 400:
        return "network_error"
    return None


def raise_openai_compat_error_for_status(response: OpenAICompatResponse) -> None:
    error_type = map_openai_compat_status_error_type(response.status_code)
    if error_type is not None:
        raise build_openai_compat_error(
            error_type,
            request=response.request,
            response=response,
        )
