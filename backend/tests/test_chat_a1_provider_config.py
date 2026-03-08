# backend/tests/test_chat_a1_provider_config.py
import pytest
from pydantic import SecretStr, ValidationError

import backend.services.chat.service as chat_service
from backend.schemas.chat import ChatIn
from backend.services.chat.config import AISettings
from backend.services.chat.contracts import ChatRequest


@pytest.fixture
def isolate_ai_env(monkeypatch: pytest.MonkeyPatch) -> None:
    keys = (
        "AI_PROVIDER",
        "AI_MODEL",
        "AI_TIMEOUT_SECONDS",
        "AI_MAX_OUTPUT_CHARS",
        "AI_OAI_BASE_URL",
        "AI_OAI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
    )
    for key in keys:
        monkeypatch.delenv(key, raising=False)


def _openai_settings_kwargs() -> dict[str, object]:
    return {
        "AI_PROVIDER": "openai_compat",
        "AI_MODEL": "gpt-4o-mini",
        "AI_TIMEOUT_SECONDS": 30,
        "AI_MAX_OUTPUT_CHARS": 4000,
        "AI_OAI_BASE_URL": "https://example.invalid/v1",
    }


def test_ai_settings_accepts_valid_openai_compat(isolate_ai_env) -> None:
    settings = AISettings(_env_file=None, **_openai_settings_kwargs())
    assert settings.ai_provider == "openai_compat"
    assert settings.ai_model == "gpt-4o-mini"
    assert settings.ai_oai_base_url == "https://example.invalid/v1"


def test_ai_settings_requires_provider_and_model(isolate_ai_env) -> None:
    with pytest.raises(ValidationError):
        AISettings(
            _env_file=None,
            AI_MODEL="gpt-4o-mini",
            AI_TIMEOUT_SECONDS=30,
            AI_MAX_OUTPUT_CHARS=4000,
            AI_OAI_BASE_URL="https://example.invalid/v1",
        )

    with pytest.raises(ValidationError):
        AISettings(
            _env_file=None,
            AI_PROVIDER="openai_compat",
            AI_TIMEOUT_SECONDS=30,
            AI_MAX_OUTPUT_CHARS=4000,
            AI_OAI_BASE_URL="https://example.invalid/v1",
        )


def test_openai_compat_requires_base_url(isolate_ai_env) -> None:
    with pytest.raises(ValidationError):
        AISettings(
            _env_file=None,
            AI_PROVIDER="openai_compat",
            AI_MODEL="gpt-4o-mini",
            AI_TIMEOUT_SECONDS=30,
            AI_MAX_OUTPUT_CHARS=4000,
        )


def test_gemini_requires_any_api_key(isolate_ai_env) -> None:
    with pytest.raises(ValidationError):
        AISettings(
            _env_file=None,
            AI_PROVIDER="gemini",
            AI_MODEL="gemini-2.0-flash",
            AI_TIMEOUT_SECONDS=30,
            AI_MAX_OUTPUT_CHARS=4000,
        )


def test_gemini_prefers_google_api_key(isolate_ai_env) -> None:
    settings = AISettings(
        _env_file=None,
        AI_PROVIDER="gemini",
        AI_MODEL="gemini-2.0-flash",
        AI_TIMEOUT_SECONDS=30,
        AI_MAX_OUTPUT_CHARS=4000,
        GEMINI_API_KEY="gemini-key",
        GOOGLE_API_KEY="google-key",
    )

    resolved = settings.get_gemini_api_key()
    assert isinstance(resolved, SecretStr)
    assert resolved.get_secret_value() == "google-key"
    assert settings.ai_oai_base_url is None


def test_ai_settings_missing_all_required_fields_when_env_isolated(isolate_ai_env) -> None:
    with pytest.raises(ValidationError):
        AISettings(_env_file=None)


def test_gemini_accepts_only_gemini_api_key_and_base_url_is_none(isolate_ai_env) -> None:
    settings = AISettings(
        _env_file=None,
        AI_PROVIDER="gemini",
        AI_MODEL="gemini-2.0-flash",
        AI_TIMEOUT_SECONDS=30,
        AI_MAX_OUTPUT_CHARS=4000,
        GEMINI_API_KEY="gemini-only",
    )
    resolved = settings.get_gemini_api_key()
    assert isinstance(resolved, SecretStr)
    assert resolved.get_secret_value() == "gemini-only"
    assert settings.ai_oai_base_url is None


@pytest.mark.parametrize("blocked_field", ["provider", "model", "base_url", "api_key"])
def test_chat_in_rejects_override_fields(blocked_field: str) -> None:
    payload = {"message": "hi", blocked_field: "blocked"}
    with pytest.raises(ValidationError):
        ChatIn.model_validate(payload)


class _GeminiSettings:
    ai_provider = "gemini"
    ai_model = "gemini-2.0-flash"
    ai_timeout_seconds = 10.0
    ai_max_output_chars = 4000
    ai_oai_base_url = None
    ai_oai_api_key = None
    p2_max_value_len = 120
    p2_max_specs_per_part = 12
    p2_spec_whitelist_by_category = {}


class _OpenAISettings:
    ai_provider = "openai_compat"
    ai_model = "gpt-4o-mini"
    ai_timeout_seconds = 10.0
    ai_max_output_chars = 4000
    ai_oai_base_url = "https://example.invalid/v1"
    ai_oai_api_key = None
    p2_max_value_len = 120
    p2_max_specs_per_part = 12
    p2_spec_whitelist_by_category = {}


def test_generate_chat_reply_gemini_does_not_call_openai_client(monkeypatch) -> None:
    def fail_if_openai_called(**kwargs):
        raise AssertionError("openai-compatible client must not be called for gemini provider")

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: _GeminiSettings())
    monkeypatch.setattr(chat_service, "generate_openai_compat_text", fail_if_openai_called)
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="hi"), db=None)
    assert response.provider == "gemini"
    assert response.model == "gemini-2.0-flash"
    assert response.error_type == "provider_not_ready"
    assert "尚未啟用" in response.text


def test_generate_chat_reply_openai_compat_dispatch_still_works(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_openai_call(**kwargs):
        captured.update(kwargs)
        return "ok"

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: _OpenAISettings())
    monkeypatch.setattr(chat_service, "generate_openai_compat_text", fake_openai_call)
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="hi"), db=None)
    assert response.text == "ok"
    assert response.error_type is None
    assert response.provider == "openai_compat"
    assert response.model == "gpt-4o-mini"
    assert captured["base_url"] == "https://example.invalid/v1"
    assert captured["model"] == "gpt-4o-mini"
