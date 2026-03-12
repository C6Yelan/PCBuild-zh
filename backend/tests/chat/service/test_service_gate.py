# backend/tests/chat/service/test_service_gate.py
from __future__ import annotations

import json
from pathlib import Path

import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.gate import validate_text_response


def test_validate_text_response_passes_for_normal_text() -> None:
    report = validate_text_response("你好\n世界\tok", max_chars=20)

    assert report.passed is True
    assert report.sanitized_text == "你好\n世界\tok"
    assert report.reasons == []
    assert report.warnings == []


def test_validate_text_response_rejects_empty_text() -> None:
    report = validate_text_response("   \n\t  ", max_chars=20)

    assert report.passed is False
    assert "empty_text" in report.reasons


def test_validate_text_response_rejects_too_long_text() -> None:
    report = validate_text_response("abcdefghij", max_chars=5)

    assert report.passed is False
    assert "text_too_long" in report.reasons


def test_validate_text_response_removes_control_chars_but_keeps_newlines() -> None:
    report = validate_text_response("A\0B\u200bC\n\tD", max_chars=20)

    assert report.passed is True
    assert report.sanitized_text == "ABC\n\tD"
    assert "control_chars_removed" in report.warnings
    assert report.removed_chars_count == 2


def test_generate_chat_reply_sanitizes_control_chars_and_writes_validation_report(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir, max_output_chars=20)

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            text="abc\0\u200bdef",
            request_id=kwargs["request_id"],
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.text == "abcdef"
    assert response.warnings is not None
    assert "control_chars_removed" in response.warnings

    snapshot_dir = snapshot_temp_dir / response.request_id
    request_context = json.loads((snapshot_dir / "request_context.json").read_text(encoding="utf-8"))
    assert "control_chars_removed" in request_context["warnings"]

    validation_report = json.loads(
        (snapshot_dir / "validation_report.json").read_text(encoding="utf-8")
    )
    assert validation_report["passed"] is True
    assert validation_report["warnings"] == ["control_chars_removed"]


def test_generate_chat_reply_rejects_empty_after_sanitize(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir, max_output_chars=20)

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            text="\0\u200b \t\n",
            request_id=kwargs["request_id"],
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "validation_failed"
    assert response.text.startswith("目前 AI 回覆格式異常，請稍後再試。request_id=")
    assert response.warnings is not None
    assert "control_chars_removed" in response.warnings

    snapshot_dir = snapshot_temp_dir / response.request_id
    validation_report = json.loads(
        (snapshot_dir / "validation_report.json").read_text(encoding="utf-8")
    )
    assert validation_report["passed"] is False
    assert "empty_text" in validation_report["reasons"]

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["gate_status"] == "fail"
    assert "empty_text" in meta["gate_reasons"]
