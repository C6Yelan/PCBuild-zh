# backend/tests/test_chat_service_p10_publish.py
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx

import backend.services.chat.clients.openai_compat_client as oai_client
import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
import backend.tools.ops.chat_regression_report as chat_regression_report
from backend.services.chat.clients.openai_compat_client import (
    OpenAICompatError,
    generate_openai_compat_completion,
)
from backend.services.chat.contracts import ChatRequest, ChatResponse


class _FakeSettings:
    def __init__(self, raw_snapshot_dir: str) -> None:
        self.ai_oai_base_url = "https://example.invalid/v1"
        self.ai_oai_api_key = None
        self.ai_model = "gpt-4o-mini"
        self.ai_timeout_seconds = 10.0
        self.ai_max_output_chars = 200
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
        usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
    )


def test_publish_staged_response_keeps_public_text_and_logs_statuses(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: _provider_result(
            text="這是一段正常的建議內容，包含 CPU 與主機板。",
            request_id=kwargs["request_id"],
        ),
    )
    monkeypatch.setattr(
        chat_service,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type is None
    assert response.text == "這是一段正常的建議內容，包含 CPU 與主機板。"
    assert f"request_id={response.request_id}" not in response.text

    ai_fields = [fields for event, fields in events if event == "ai_call"]
    assert len(ai_fields) == 1
    assert ai_fields[0]["gate_status"] == "pass"
    assert ai_fields[0]["dq_status"] == "pass"
    assert ai_fields[0]["staging_status"] == "staged"
    assert ai_fields[0]["quarantine_status"] == "not_quarantined"


def test_publish_validation_failed_includes_request_id_and_quarantine_reason(
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
    assert f"request_id={response.request_id}" in response.text

    quarantine_entry = json.loads(
        (tmp_path / response.request_id / "quarantine_entry.json").read_text(encoding="utf-8")
    )
    assert quarantine_entry["publish_blocked"] is True
    assert quarantine_entry["publish_reason"] == "validation_failed"


def test_publish_dq_failed_includes_request_id_and_quarantine_reason(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: _provider_result(text="短", request_id=kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "dq_failed"
    assert f"request_id={response.request_id}" in response.text

    quarantine_entry = json.loads(
        (tmp_path / response.request_id / "quarantine_entry.json").read_text(encoding="utf-8")
    )
    assert quarantine_entry["publish_blocked"] is True
    assert quarantine_entry["publish_reason"] == "dq_failed"


def test_publish_provider_error_keeps_request_id_and_skips_stage_and_quarantine(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: (_ for _ in ()).throw(
            OpenAICompatError("network_error", endpoint="https://example.invalid/v1")
        ),
    )
    monkeypatch.setattr(
        chat_service,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "network_error"
    assert f"request_id={response.request_id}" in response.text
    snapshot_dir = tmp_path / response.request_id
    assert not (snapshot_dir / "staging_record.json").exists()
    assert not (snapshot_dir / "quarantine_entry.json").exists()

    ai_fields = [fields for event, fields in events if event == "ai_call"]
    assert len(ai_fields) == 1
    assert ai_fields[0]["staging_status"] == "skipped"
    assert ai_fields[0]["quarantine_status"] == "not_applicable"


def test_openai_client_retries_timeout_once_then_succeeds(monkeypatch) -> None:
    calls = {"count": 0}
    retry_events: list[tuple[str, dict[str, object]]] = []

    class _Response:
        status_code = 200
        headers = httpx.Headers({"x-request-id": "up-2"})
        text = '{"choices":[{"message":{"content":"ok"}}]}'

        def json(self) -> dict[str, object]:
            return {
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }

    def fake_post(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise httpx.TimeoutException("timeout")
        return _Response()

    monkeypatch.setattr(oai_client.httpx, "post", fake_post)
    monkeypatch.setattr(oai_client, "sleep", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        oai_client,
        "log_operation",
        lambda event, **fields: retry_events.append((event, fields)),
    )

    result = generate_openai_compat_completion(
        base_url="https://example.invalid/v1",
        api_key=None,
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hi"}],
        timeout_seconds=1.0,
        client_request_id="req-timeout",
        provider="openai_compat",
    )

    assert result.text == "ok"
    assert calls["count"] == 2
    assert retry_events == [
        (
            "ai_retry",
            {
                "request_id": "req-timeout",
                "provider": "openai_compat",
                "model": "gpt-4o-mini",
                "attempt": 2,
                "error_type": "timeout",
            },
        )
    ]


def test_openai_client_retries_429_once_then_succeeds(monkeypatch) -> None:
    calls = {"count": 0}
    retry_events: list[tuple[str, dict[str, object]]] = []

    class _RateLimited:
        status_code = 429
        headers = httpx.Headers({"x-request-id": "up-1"})
        text = '{"error":"rate limited"}'

        def json(self) -> dict[str, object]:
            return {"error": "rate limited"}

    class _Response:
        status_code = 200
        headers = httpx.Headers({"x-request-id": "up-2"})
        text = '{"choices":[{"message":{"content":"ok"}}]}'

        def json(self) -> dict[str, object]:
            return {
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }

    def fake_post(*args, **kwargs):
        calls["count"] += 1
        return _RateLimited() if calls["count"] == 1 else _Response()

    monkeypatch.setattr(oai_client.httpx, "post", fake_post)
    monkeypatch.setattr(oai_client, "sleep", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        oai_client,
        "log_operation",
        lambda event, **fields: retry_events.append((event, fields)),
    )

    result = generate_openai_compat_completion(
        base_url="https://example.invalid/v1",
        api_key=None,
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hi"}],
        timeout_seconds=1.0,
        client_request_id="req-429",
        provider="openai_compat",
    )

    assert result.text == "ok"
    assert calls["count"] == 2
    assert retry_events[0][1]["error_type"] == "429"


def test_openai_client_does_not_retry_parse_error(monkeypatch) -> None:
    calls = {"count": 0}
    retry_events: list[tuple[str, dict[str, object]]] = []

    class _BadResponse:
        status_code = 200
        headers = httpx.Headers({"x-request-id": "up-1"})
        text = '{"not_choices":true}'

        def json(self) -> dict[str, object]:
            return {"not_choices": True}

    def fake_post(*args, **kwargs):
        calls["count"] += 1
        return _BadResponse()

    monkeypatch.setattr(oai_client.httpx, "post", fake_post)
    monkeypatch.setattr(oai_client, "sleep", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        oai_client,
        "log_operation",
        lambda event, **fields: retry_events.append((event, fields)),
    )

    try:
        generate_openai_compat_completion(
            base_url="https://example.invalid/v1",
            api_key=None,
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "hi"}],
            timeout_seconds=1.0,
            client_request_id="req-parse",
            provider="openai_compat",
        )
    except OpenAICompatError as exc:
        assert exc.error_type == "parse_error"
    else:
        raise AssertionError("expected parse_error")

    assert calls["count"] == 1
    assert retry_events == []


def test_openai_client_keeps_error_type_after_retry_exhausted(monkeypatch) -> None:
    calls = {"count": 0}

    def fake_post(*args, **kwargs):
        calls["count"] += 1
        raise httpx.RequestError("network down")

    monkeypatch.setattr(oai_client.httpx, "post", fake_post)
    monkeypatch.setattr(oai_client, "sleep", lambda *args, **kwargs: None)
    monkeypatch.setattr(oai_client, "log_operation", lambda *args, **kwargs: None)

    try:
        generate_openai_compat_completion(
            base_url="https://example.invalid/v1",
            api_key=None,
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "hi"}],
            timeout_seconds=1.0,
            client_request_id="req-network",
            provider="openai_compat",
        )
    except OpenAICompatError as exc:
        assert exc.error_type == "network_error"
    else:
        raise AssertionError("expected network_error")

    assert calls["count"] == 2


def test_chat_regression_report_writes_file_and_returns_exit_code(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    monkeypatch.setattr(
        chat_regression_report,
        "get_ai_settings",
        lambda: SimpleNamespace(
            ai_raw_snapshot_dir=str(tmp_path),
            ai_provider="openai_compat",
            ai_model="gpt-4o-mini",
        ),
    )
    monkeypatch.setattr(
        chat_regression_report,
        "run_provider_health_check",
        lambda: {
            "provider": "openai_compat",
            "model": "gpt-4o-mini",
            "ran_at": "2026-03-09T00:00:00Z",
            "total_cases": 5,
            "passed_cases": 4,
            "failed_cases": 1,
            "latency_ms_p50": 120,
            "latency_ms_p95": 180,
            "cases": [
                {
                    "request_id": "req-1",
                    "ok": True,
                    "error_type": None,
                    "latency_ms": 100,
                    "warnings": None,
                },
                {
                    "request_id": "req-2",
                    "ok": False,
                    "error_type": "dq_failed",
                    "latency_ms": 200,
                    "warnings": ["usage_unavailable"],
                },
            ],
        },
    )

    exit_code = chat_regression_report.main([])

    assert exit_code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["dq_fail_cases"] == 1
    assert payload["failed_cases"] == 1
    assert Path(payload["report_path"]).exists()
