# backend/tests/test_chat_service_p6_normalize.py
from __future__ import annotations

import json
from pathlib import Path

import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.normalize import normalize_provider_success


class _FakeSettings:
    def __init__(self, raw_snapshot_dir: str) -> None:
        self.ai_oai_base_url = "https://example.invalid/v1"
        self.ai_oai_api_key = None
        self.ai_model = "gpt-4o-mini"
        self.ai_timeout_seconds = 10.0
        self.ai_max_output_chars = 4000
        self.ai_provider = "openai_compat"
        self.ai_raw_snapshot_dir = raw_snapshot_dir
        self.p2_max_value_len = 120
        self.p2_max_specs_per_part = 12
        self.p2_spec_whitelist_by_category = {}


def _provider_result(
    *,
    text: str = "ok",
    finish_reason: str | None = "stop",
    usage: dict[str, int] | None = None,
    upstream_request_id: str | None = "up-1",
) -> chat_provider_caller.ProviderCallResult:
    return chat_provider_caller.ProviderCallResult(
        text=text,
        endpoint="https://example.invalid/v1/chat/completions",
        status_code=200,
        request_headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Client-Request-Id": "req-1",
        },
        request_json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        response_headers={"x-request-id": upstream_request_id or ""},
        response_json={"choices": [{"message": {"content": text}}]},
        raw_response_text='{"choices":[{"message":{"content":"ok"}}]}',
        upstream_request_id=upstream_request_id,
        finish_reason=finish_reason,
        usage=usage,
    )


def test_normalize_provider_success_keeps_usage_and_stop_finish_reason() -> None:
    warnings: list[str] = []

    normalized = normalize_provider_success(
        provider="openai_compat",
        model="gpt-4o-mini",
        request_id="req-1",
        latency_ms=123,
        provider_result=_provider_result(
            usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        ),
        warnings=warnings,
    )

    assert normalized.text == "ok"
    assert normalized.usage == {
        "prompt_tokens": 1,
        "completion_tokens": 2,
        "total_tokens": 3,
    }
    assert normalized.finish_reason == "stop"
    assert warnings == []


def test_normalize_provider_success_warns_when_usage_missing() -> None:
    warnings: list[str] = []

    normalized = normalize_provider_success(
        provider="openai_compat",
        model="gpt-4o-mini",
        request_id="req-1",
        latency_ms=123,
        provider_result=_provider_result(usage=None),
        warnings=warnings,
    )

    assert normalized.text == "ok"
    assert normalized.usage is None
    assert "usage_unavailable" in warnings


def test_normalize_provider_success_warns_on_length_finish_reason() -> None:
    warnings: list[str] = []

    normalize_provider_success(
        provider="openai_compat",
        model="gpt-4o-mini",
        request_id="req-1",
        latency_ms=123,
        provider_result=_provider_result(
            finish_reason="length",
            usage={"prompt_tokens": 1},
        ),
        warnings=warnings,
    )

    assert "provider_finish_reason_length" in warnings


def test_normalize_provider_success_warns_on_content_filter_finish_reason() -> None:
    warnings: list[str] = []

    normalize_provider_success(
        provider="openai_compat",
        model="gpt-4o-mini",
        request_id="req-1",
        latency_ms=123,
        provider_result=_provider_result(
            finish_reason="content_filter",
            usage={"prompt_tokens": 1},
        ),
        warnings=warnings,
    )

    assert "provider_finish_reason_content_filter" in warnings


def test_generate_chat_reply_snapshot_keeps_normalize_warnings(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: _provider_result(finish_reason="length", usage=None),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(
        ChatRequest(user_text="請回答我"),
        db=None,
    )

    assert response.warnings is not None
    assert "usage_unavailable" in response.warnings
    assert "provider_finish_reason_length" in response.warnings

    snapshot_dir = tmp_path / response.request_id
    assert (snapshot_dir / "raw_request.json").exists()
    assert (snapshot_dir / "raw_response.json").exists()
    assert (snapshot_dir / "meta.json").exists()
    assert (snapshot_dir / "request_context.json").exists()

    request_context = json.loads(
        (snapshot_dir / "request_context.json").read_text(encoding="utf-8")
    )
    assert "usage_unavailable" in request_context["warnings"]
    assert "provider_finish_reason_length" in request_context["warnings"]


def test_generate_chat_reply_fallback_text_path_still_works(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "generate_openai_compat_text", lambda **kwargs: "fallback-ok")
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="hi"), db=None)

    assert response.text == "fallback-ok"
    assert response.provider == "openai_compat"
    assert response.model == "gpt-4o-mini"
    assert response.error_type is None
