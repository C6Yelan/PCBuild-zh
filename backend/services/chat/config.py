# backend/services/chat/config.py
from __future__ import annotations

from functools import lru_cache
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ALLOWED_AI_PROVIDERS = (
    "openai_compat",
    "local_openai_compat",
    "backup_openai_compat",
)

HISTORY_MAX_TURNS = 8
SYSTEM_PROMPT = "你是電腦組裝顧問，所有回覆一律使用繁體中文。"


class AISettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    ai_provider: str = Field(default="openai_compat", alias="AI_PROVIDER")
    ai_model: str = Field(default="gpt-4o-mini", alias="AI_MODEL")
    ai_timeout_seconds: float = Field(default=30.0, gt=0, alias="AI_TIMEOUT_SECONDS")
    ai_max_output_chars: int = Field(default=4000, gt=0, alias="AI_MAX_OUTPUT_CHARS")
    ai_oai_base_url: str = Field(default="http://localhost:11434/v1", alias="AI_OAI_BASE_URL")
    ai_oai_api_key: SecretStr | None = Field(default=None, alias="AI_OAI_API_KEY")

    @field_validator("ai_provider")
    @classmethod
    def _validate_ai_provider(cls, value: str) -> str:
        value = value.strip()
        if value in ALLOWED_AI_PROVIDERS:
            return value
        allowed = ", ".join(ALLOWED_AI_PROVIDERS)
        raise ValueError(f"AI_PROVIDER must be one of: {allowed}")

    @field_validator("ai_oai_base_url")
    @classmethod
    def _validate_oai_base_url(cls, value: str) -> str:
        value = value.strip()
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("AI_OAI_BASE_URL must use http or https")
        if not parsed.netloc:
            raise ValueError("AI_OAI_BASE_URL must include host")
        return value.rstrip("/")


@lru_cache(maxsize=1)
def get_ai_settings() -> AISettings:
    return AISettings()
