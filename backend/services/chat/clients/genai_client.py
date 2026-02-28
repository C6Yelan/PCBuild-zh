# backend/services/chat/clients/genai_client.py
from __future__ import annotations

import logging
from functools import lru_cache
from time import perf_counter
from typing import Any
from uuid import UUID, uuid4

import httpx

from backend.services.chat.config import ChatSettings, get_chat_settings
from backend.services.chat.contracts import ChatResponse

_FALLBACK_ERROR_TEXT = "目前 AI 服務暫時不可用，請稍後再試。"
logger = logging.getLogger(__name__)


class OpenAICompatChatClient:
    def __init__(self, settings: ChatSettings) -> None:
        self._settings = settings
        self._base_url = str(settings.ai_oai_base_url).rstrip("/")
        self._api_key = settings.ai_oai_api_key

    def generate_text(self, *, prompt: str, request_id: UUID | None = None) -> ChatResponse:
        rid = request_id or uuid4()
        started = perf_counter()

        model_name = self._settings.ai_model
        if not model_name:
            return self._error_response(rid=rid, latency_ms=0, error_type="config_error")

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
        }

        try:
            response = httpx.post(
                f"{self._base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=self._settings.ai_timeout_seconds,
            )
            latency_ms = _latency_ms(started)
            response.raise_for_status()

            text = _extract_response_text(response.json())
            text = text[: self._settings.ai_max_output_chars]

            chat_response = ChatResponse(
                request_id=rid,
                provider=self._settings.ai_provider.value,
                model=model_name,
                text=text,
                latency_ms=latency_ms,
                error_type=None,
            )
            _log_call(chat_response, ok=True, status_code=None)
            return chat_response
        except httpx.TimeoutException:
            chat_response = self._error_response(
                rid=rid,
                latency_ms=_latency_ms(started),
                error_type="timeout",
            )
            _log_call(chat_response, ok=False, status_code=None)
            return chat_response
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            chat_response = self._error_response(
                rid=rid,
                latency_ms=_latency_ms(started),
                error_type=_classify_http_status(status_code),
            )
            _log_call(chat_response, ok=False, status_code=status_code)
            return chat_response
        except httpx.RequestError:
            chat_response = self._error_response(
                rid=rid,
                latency_ms=_latency_ms(started),
                error_type="network_error",
            )
            _log_call(chat_response, ok=False, status_code=None)
            return chat_response
        except (TypeError, ValueError, KeyError):
            chat_response = self._error_response(
                rid=rid,
                latency_ms=_latency_ms(started),
                error_type="invalid_response",
            )
            _log_call(chat_response, ok=False, status_code=None)
            return chat_response

    def _error_response(self, *, rid: UUID, latency_ms: int, error_type: str) -> ChatResponse:
        # ChatResponse.text 依 Contract 不可空，失敗情境回傳安全降級訊息。
        return ChatResponse(
            request_id=rid,
            provider=self._settings.ai_provider.value,
            model=self._settings.ai_model or "unknown",
            text=_FALLBACK_ERROR_TEXT,
            latency_ms=latency_ms,
            error_type=error_type,
        )


@lru_cache(maxsize=1)
def get_genai_client() -> OpenAICompatChatClient:
    return OpenAICompatChatClient(settings=get_chat_settings())


def _classify_http_status(status_code: int) -> str:
    if status_code == 400:
        return "invalid_request"
    if status_code == 401:
        return "authentication_error"
    if status_code == 403:
        return "permission_error"
    if status_code == 404:
        return "not_found"
    if status_code == 408:
        return "timeout"
    if status_code == 409:
        return "conflict"
    if status_code == 422:
        return "validation_error"
    if status_code == 429:
        return "rate_limited"
    if 500 <= status_code <= 599:
        return "upstream_error"
    if 400 <= status_code <= 499:
        return "client_error"
    return "http_error"


def _latency_ms(started: float) -> int:
    return int((perf_counter() - started) * 1000)


def _extract_response_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("missing choices")

    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        raise ValueError("invalid choice payload")

    message = first_choice.get("message")
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str):
            cleaned = content.strip()
            if cleaned:
                return cleaned

    raw_text = first_choice.get("text")
    if isinstance(raw_text, str):
        cleaned = raw_text.strip()
        if cleaned:
            return cleaned

    raise ValueError("empty response text")


def _log_call(chat_response: ChatResponse, *, ok: bool, status_code: int | None) -> None:
    logger.info(
        "request_id=%s provider=%s model=%s ok=%s latency_ms=%s error_type=%s status_code=%s",
        chat_response.request_id,
        chat_response.provider,
        chat_response.model,
        ok,
        chat_response.latency_ms,
        chat_response.error_type or "",
        status_code,
    )
