# backend/services/chat/clients/openai_compat_models.py
from __future__ import annotations

from dataclasses import dataclass


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
class OpenAICompatRequest:
    endpoint: str
    headers: dict[str, str]
    payload: dict[str, object]
    timeout_seconds: float


@dataclass(slots=True)
class OpenAICompatResponse:
    request: OpenAICompatRequest
    status_code: int
    raw_response_text: str
    response_headers: dict[str, str]
    response_json: dict[str, object] | None
    upstream_request_id: str | None
