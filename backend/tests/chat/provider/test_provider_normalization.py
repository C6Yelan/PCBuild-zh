# backend/tests/chat/provider/test_provider_normalization.py
from __future__ import annotations

import json
from pathlib import Path

import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.normalize import normalize_provider_success


def test_normalize_provider_success_keeps_usage_and_stop_finish_reason(
    provider_result_factory,
) -> None:
    warnings: list[str] = []

    normalized = normalize_provider_success(
        provider="openai_compat",
        model="gpt-4o-mini",
        request_id="req-1",
        latency_ms=123,
        provider_result=provider_result_factory(
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


def test_normalize_provider_success_warns_when_usage_missing(
    provider_result_factory,
) -> None:
    warnings: list[str] = []

    normalized = normalize_provider_success(
        provider="openai_compat",
        model="gpt-4o-mini",
        request_id="req-1",
        latency_ms=123,
        provider_result=provider_result_factory(usage=None),
        warnings=warnings,
    )

    assert normalized.text == "ok"
    assert normalized.usage is None
    assert "usage_unavailable" in warnings


def test_normalize_provider_success_warns_on_length_finish_reason(
    provider_result_factory,
) -> None:
    warnings: list[str] = []

    normalize_provider_success(
        provider="openai_compat",
        model="gpt-4o-mini",
        request_id="req-1",
        latency_ms=123,
        provider_result=provider_result_factory(
            finish_reason="length",
            usage={"prompt_tokens": 1},
        ),
        warnings=warnings,
    )

    assert "provider_finish_reason_length" in warnings


def test_normalize_provider_success_warns_on_content_filter_finish_reason(
    provider_result_factory,
) -> None:
    warnings: list[str] = []

    normalize_provider_success(
        provider="openai_compat",
        model="gpt-4o-mini",
        request_id="req-1",
        latency_ms=123,
        provider_result=provider_result_factory(
            finish_reason="content_filter",
            usage={"prompt_tokens": 1},
        ),
        warnings=warnings,
    )

    assert "provider_finish_reason_content_filter" in warnings


def test_generate_chat_reply_snapshot_keeps_normalize_warnings(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir)

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(finish_reason="length", usage=None),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(
        ChatRequest(user_text="請回答我"),
        db=None,
    )

    assert response.warnings is not None
    assert "usage_unavailable" in response.warnings
    assert "provider_finish_reason_length" in response.warnings

    snapshot_dir = snapshot_temp_dir / response.request_id
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
    snapshot_temp_dir: Path,
    fake_chat_settings,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir)

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "generate_openai_compat_text", lambda **kwargs: "fallback-ok")
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="hi"), db=None)

    assert response.text == "fallback-ok"
    assert response.provider == "openai_compat"
    assert response.model == "gpt-4o-mini"
    assert response.error_type is None
