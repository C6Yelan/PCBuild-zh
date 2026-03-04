# backend/tests/test_chat_p0_contracts.py
import pytest
from pydantic import SecretStr, ValidationError

from backend.services.chat.clients.openai_compat_client import generate_openai_compat_text
from backend.services.chat.config import AISettings
from backend.services.chat.contracts import ChatRequest, ChatResponse
from backend.services.chat.clients import openai_compat_client
from backend.schemas.chat import ChatOut


def test_ai_settings_reject_invalid_provider() -> None:
    with pytest.raises(ValidationError):
        AISettings(
            _env_file=None,
            AI_PROVIDER="invalid_provider",
        )


def test_chat_request_rejects_provider_overrides() -> None:
    with pytest.raises(ValidationError):
        ChatRequest.model_validate(
            {
                "user_text": "幫我配一台遊戲機",
                "provider": "evil",
                "base_url": "https://attacker.invalid/v1",
                "api_key": "leak",
            }
        )


def test_chat_response_has_required_fields() -> None:
    response = ChatResponse(
        request_id="req_123",
        provider="openai_compat",
        model="gpt-4o-mini",
        text="建議配置如下",
        latency_ms=42,
    )

    dumped = response.model_dump()
    assert dumped["request_id"] == "req_123"
    assert dumped["provider"] == "openai_compat"
    assert dumped["model"] == "gpt-4o-mini"
    assert dumped["text"] == "建議配置如下"
    assert dumped["latency_ms"] == 42


def test_openai_compat_secretstr_uses_real_auth_header(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_headers: dict[str, str] = {}

    class FakeResponse:
        status_code = 200

        def json(self) -> dict:
            return {"choices": [{"message": {"content": "ok"}}]}

    def fake_post(url: str, headers=None, json=None, timeout=None):
        captured_headers.update(headers or {})
        return FakeResponse()

    monkeypatch.setattr(openai_compat_client.httpx, "post", fake_post)

    text = generate_openai_compat_text(
        base_url="https://example.com/v1",
        api_key=SecretStr("abc"),
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hi"}],
        timeout_seconds=10,
    )

    assert captured_headers["Authorization"] == "Bearer abc"
    assert text == "ok"


def test_chat_out_accepts_chat_response_dump() -> None:
    resp = ChatResponse(
        request_id="req_1",
        provider="openai_compat",
        model="gpt-4o-mini",
        text="ok",
        latency_ms=10,
    )

    out = ChatOut.model_validate(resp.model_dump())
    assert out.request_id == "req_1"
    assert out.text == "ok"
