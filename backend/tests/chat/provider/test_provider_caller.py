from __future__ import annotations

import pytest

from backend.services.chat.clients.openai_compat_models import OpenAICompatResult
from backend.services.chat.provider_caller import (
    ProviderDispatchError,
    generate_provider_result,
)


class _OpenAISettings:
    ai_provider = "openai_compat"
    ai_model = "gpt-4o-mini"
    ai_timeout_seconds = 10.0
    ai_oai_base_url = "https://example.invalid/v1"
    ai_oai_api_key = None


class _GeminiSettings:
    ai_provider = "gemini"
    ai_model = "gemini-2.0-flash"
    ai_timeout_seconds = 10.0
    ai_oai_base_url = None
    ai_oai_api_key = None
    gemini_api_key = "gemini-key"
    google_api_key = None


def test_generate_provider_result_openai_completion_path() -> None:
    def fake_completion(**kwargs) -> OpenAICompatResult:
        assert kwargs["base_url"] == "https://example.invalid/v1"
        assert kwargs["model"] == "gpt-4o-mini"
        assert kwargs["provider"] == "openai_compat"
        return OpenAICompatResult(
            text="ok",
            endpoint="https://example.invalid/v1/chat/completions",
            status_code=200,
            request_headers={"X-Client-Request-Id": kwargs["client_request_id"]},
            request_json={"model": kwargs["model"], "messages": kwargs["messages"]},
            response_headers={"x-request-id": "up-1"},
            response_json={"choices": [{"message": {"content": "ok"}}]},
            raw_response_text='{"choices":[{"message":{"content":"ok"}}]}',
            upstream_request_id="up-1",
            response_id="resp-1",
            finish_reason="stop",
            usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        )

    result = generate_provider_result(
        settings=_OpenAISettings(),
        messages=[{"role": "user", "content": "hi"}],
        request_id="req-1",
        completion_generator=fake_completion,
    )

    assert result.text == "ok"
    assert result.endpoint == "https://example.invalid/v1/chat/completions"
    assert result.request_json["model"] == "gpt-4o-mini"
    assert result.upstream_request_id == "up-1"
    assert result.finish_reason == "stop"


def test_generate_provider_result_openai_fallback_text_path() -> None:
    def fake_text(**kwargs) -> str:
        assert kwargs["base_url"] == "https://example.invalid/v1"
        assert kwargs["model"] == "gpt-4o-mini"
        assert kwargs["provider"] == "openai_compat"
        return "fallback-ok"

    def original_text(**kwargs) -> str:
        raise AssertionError("should not use original text generator")

    result = generate_provider_result(
        settings=_OpenAISettings(),
        messages=[{"role": "user", "content": "hi"}],
        request_id="req-2",
        text_generator=fake_text,
        original_text_generator=original_text,
    )

    assert result.text == "fallback-ok"
    assert result.status_code == 200
    assert result.endpoint == "https://example.invalid/v1"
    assert result.request_headers["X-Client-Request-Id"] == "req-2"
    assert result.request_json["model"] == "gpt-4o-mini"


def test_generate_provider_result_gemini_not_ready() -> None:
    with pytest.raises(ProviderDispatchError) as exc_info:
        generate_provider_result(
            settings=_GeminiSettings(),
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-3",
        )

    assert exc_info.value.error_type == "provider_not_ready"
    assert exc_info.value.request_json["model"] == "gemini-2.0-flash"
