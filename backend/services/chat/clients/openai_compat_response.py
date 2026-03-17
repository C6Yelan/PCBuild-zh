# backend/services/chat/clients/openai_compat_response.py
from __future__ import annotations

from .openai_compat_models import (
    OpenAICompatRequest,
    OpenAICompatResponse,
    OpenAICompatResult,
)
from .openai_compat_transport import (
    build_openai_compat_error,
    raise_openai_compat_error_for_status,
)


def extract_openai_compat_usage(payload: object) -> dict[str, int] | None:
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


def _raise_parse_error(
    *,
    request: OpenAICompatRequest,
    response: OpenAICompatResponse,
    cause: Exception | None = None,
) -> None:
    if cause is None:
        raise build_openai_compat_error(
            "parse_error",
            request=request,
            response=response,
        )
    raise build_openai_compat_error(
        "parse_error",
        request=request,
        response=response,
    ) from cause


def _extract_choice_text(response: OpenAICompatResponse) -> str:
    response_json = response.response_json
    if response_json is None:
        _raise_parse_error(request=response.request, response=response)

    try:
        choice = response_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        _raise_parse_error(request=response.request, response=response, cause=exc)

    if not isinstance(choice, str):
        _raise_parse_error(request=response.request, response=response)
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


def parse_openai_compat_result(response: OpenAICompatResponse) -> OpenAICompatResult:
    raise_openai_compat_error_for_status(response)
    choice = _extract_choice_text(response)
    response_json = response.response_json
    if response_json is None:
        _raise_parse_error(request=response.request, response=response)

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
        usage=extract_openai_compat_usage(response_json.get("usage")),
    )
