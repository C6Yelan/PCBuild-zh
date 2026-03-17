# backend/services/chat/provider_call_models.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from backend.services.chat.clients.openai_compat_models import OpenAICompatResult


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
