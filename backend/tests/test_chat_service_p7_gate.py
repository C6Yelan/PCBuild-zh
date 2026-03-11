# backend/tests/test_chat_service_p7_gate.py
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
import backend.tools.ops.chat_snapshot_inspect as chat_snapshot_inspect
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.gate import validate_text_response


class _FakeSettings:
    def __init__(self, raw_snapshot_dir: str) -> None:
        self.ai_oai_base_url = "https://example.invalid/v1"
        self.ai_oai_api_key = None
        self.ai_model = "gpt-4o-mini"
        self.ai_timeout_seconds = 10.0
        self.ai_max_output_chars = 20
        self.ai_provider = "openai_compat"
        self.ai_raw_snapshot_dir = raw_snapshot_dir
        self.p2_max_value_len = 120
        self.p2_max_specs_per_part = 12
        self.p2_spec_whitelist_by_category = {}


def _provider_result(
    *,
    text: str,
    request_id: str,
) -> chat_provider_caller.ProviderCallResult:
    return chat_provider_caller.ProviderCallResult(
        text=text,
        endpoint="https://example.invalid/v1/chat/completions",
        status_code=200,
        request_headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Client-Request-Id": request_id,
        },
        request_json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        response_headers={"x-request-id": "up-1"},
        response_json={"choices": [{"message": {"content": text}}]},
        raw_response_text=json.dumps({"choices": [{"message": {"content": text}}]}, ensure_ascii=False),
        upstream_request_id="up-1",
    )


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
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: _provider_result(text="abc\0\u200bdef", request_id=kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.text == "abcdef"
    assert response.warnings is not None
    assert "control_chars_removed" in response.warnings

    snapshot_dir = tmp_path / response.request_id
    request_context = json.loads((snapshot_dir / "request_context.json").read_text(encoding="utf-8"))
    assert "control_chars_removed" in request_context["warnings"]

    validation_report = json.loads(
        (snapshot_dir / "validation_report.json").read_text(encoding="utf-8")
    )
    assert validation_report["passed"] is True
    assert validation_report["warnings"] == ["control_chars_removed"]


def test_generate_chat_reply_rejects_empty_after_sanitize(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: _provider_result(text="\0\u200b \t\n", request_id=kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "validation_failed"
    assert response.text.startswith("目前 AI 回覆格式異常，請稍後再試。request_id=")
    assert response.warnings is not None
    assert "control_chars_removed" in response.warnings

    snapshot_dir = tmp_path / response.request_id
    validation_report = json.loads(
        (snapshot_dir / "validation_report.json").read_text(encoding="utf-8")
    )
    assert validation_report["passed"] is False
    assert "empty_text" in validation_report["reasons"]

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["gate_status"] == "fail"
    assert "empty_text" in meta["gate_reasons"]


def test_snapshot_inspect_includes_validation_report(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    monkeypatch.setattr(
        chat_snapshot_inspect,
        "get_ai_settings",
        lambda: SimpleNamespace(ai_raw_snapshot_dir=str(tmp_path)),
    )

    snapshot_dir = tmp_path / "req-ok"
    snapshot_dir.mkdir()
    for filename, payload in {
        "raw_request.json": {"ok": True},
        "raw_response.json": {"ok": True},
        "meta.json": {"request_id": "req-ok"},
        "request_context.json": {"request_id": "req-ok"},
        "validation_report.json": {"passed": True, "reasons": []},
    }.items():
        (snapshot_dir / filename).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    assert chat_snapshot_inspect.main(["--request-id", "req-ok"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["validation_report"] == {"passed": True, "reasons": []}
