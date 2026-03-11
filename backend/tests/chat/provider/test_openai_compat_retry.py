from __future__ import annotations

import httpx

import backend.services.chat.clients.openai_compat_client as oai_client
from backend.services.chat.clients.openai_compat_client import (
    OpenAICompatError,
    generate_openai_compat_completion,
)


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
