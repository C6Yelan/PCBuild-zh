# backend/tests/test_chat_service_p4_health.py
from __future__ import annotations

from pathlib import Path

import backend.services.chat.health as chat_health
import backend.services.chat.service as chat_service
from backend.services.chat.config import SYSTEM_PROMPT
from backend.services.chat.contracts import ChatRequest, ChatResponse


class _FakeHealthSettings:
    def __init__(self, raw_snapshot_dir: str) -> None:
        self.ai_provider = "openai_compat"
        self.ai_model = "gpt-4o-mini"
        self.ai_raw_snapshot_dir = raw_snapshot_dir


def _make_response(*, index: int, error_type: str | None = None, warnings=None) -> ChatResponse:
    return ChatResponse(
        request_id=f"req-{index}",
        provider="openai_compat",
        model="gpt-4o-mini",
        text="ok" if error_type is None else "failed",
        latency_ms=100 + index * 10,
        error_type=error_type,
        warnings=warnings,
    )


def test_run_provider_health_check_success(monkeypatch, tmp_path: Path) -> None:
    responses = [_make_response(index=index) for index in range(5)]
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        chat_health,
        "get_ai_settings",
        lambda: _FakeHealthSettings(str(tmp_path)),
    )
    monkeypatch.setattr(
        chat_health,
        "generate_chat_reply",
        lambda request, db=None: responses.pop(0),
    )
    monkeypatch.setattr(
        chat_health,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )

    report = chat_health.run_provider_health_check()

    assert report["total_cases"] == 5
    assert report["passed_cases"] == 5
    assert report["failed_cases"] == 0
    assert report["pass"] is True
    assert report["latency_ms_p50"] == 120
    assert report["latency_ms_p95"] == 140
    case_request_ids = [case["request_id"] for case in report["cases"]]
    assert case_request_ids == ["req-0", "req-1", "req-2", "req-3", "req-4"]

    health_events = [fields for event, fields in events if event == "provider_health_check"]
    assert len(health_events) == 1
    assert health_events[0]["provider"] == "openai_compat"
    assert health_events[0]["model"] == "gpt-4o-mini"
    assert health_events[0]["total_cases"] == 5
    assert health_events[0]["failed_cases"] == 0
    assert health_events[0]["latency_ms_p95"] == 140
    assert health_events[0]["pass"] is True


def test_run_provider_health_check_failure_accumulates_error_types(
    monkeypatch,
    tmp_path: Path,
) -> None:
    responses = [
        _make_response(index=0),
        _make_response(index=1, error_type="timeout"),
        _make_response(index=2),
        _make_response(index=3),
        _make_response(index=4),
    ]

    monkeypatch.setattr(
        chat_health,
        "get_ai_settings",
        lambda: _FakeHealthSettings(str(tmp_path)),
    )
    monkeypatch.setattr(
        chat_health,
        "generate_chat_reply",
        lambda request, db=None: responses.pop(0),
    )
    monkeypatch.setattr(chat_health, "log_operation", lambda *args, **kwargs: None)

    report = chat_health.run_provider_health_check()

    assert report["passed_cases"] == 4
    assert report["failed_cases"] == 1
    assert report["pass"] is False
    assert report["error_type_counts"] == {"timeout": 1}
    failed_cases = [case for case in report["cases"] if case["ok"] is False]
    assert len(failed_cases) == 1
    assert failed_cases[0]["error_type"] == "timeout"


def test_run_provider_health_check_writes_report_under_snapshot_dir(
    monkeypatch,
    tmp_path: Path,
) -> None:
    responses = [_make_response(index=index) for index in range(5)]

    monkeypatch.setattr(
        chat_health,
        "get_ai_settings",
        lambda: _FakeHealthSettings(str(tmp_path)),
    )
    monkeypatch.setattr(
        chat_health,
        "generate_chat_reply",
        lambda request, db=None: responses.pop(0),
    )
    monkeypatch.setattr(chat_health, "log_operation", lambda *args, **kwargs: None)

    report = chat_health.run_provider_health_check()
    report_path = Path(str(report["report_path"]))

    assert report_path.parent == tmp_path / "provider_health_reports"
    assert report_path.exists()


def test_build_provider_messages_prepends_internal_system_prompt_for_messages_mode() -> None:
    request = ChatRequest(
        messages=[
            {"role": "system", "content": "原始 system"},
            {"role": "user", "content": "請幫我比較兩顆 CPU。"},
        ]
    )

    provider_messages = chat_service._build_provider_messages(request)

    assert provider_messages[0] == {"role": "system", "content": SYSTEM_PROMPT}
    assert provider_messages[1] == {"role": "system", "content": "原始 system"}
    assert provider_messages[2] == {"role": "user", "content": "請幫我比較兩顆 CPU。"}


def test_build_provider_messages_prepends_internal_system_prompt_for_user_text_mode() -> None:
    request = ChatRequest(user_text="幫我推薦文書機")

    provider_messages = chat_service._build_provider_messages(request)

    assert provider_messages[0] == {"role": "system", "content": SYSTEM_PROMPT}
    assert provider_messages[1]["role"] == "user"
    assert "幫我推薦文書機" in provider_messages[1]["content"]
    assert not provider_messages[1]["content"].startswith(SYSTEM_PROMPT)
