# backend/services/chat/config.py
from __future__ import annotations

import json
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
    p2_max_value_len: int = Field(default=120, gt=0, alias="P2_MAX_VALUE_LEN")
    p2_max_specs_per_part: int = Field(default=12, gt=0, alias="P2_MAX_SPECS_PER_PART")
    p2_spec_whitelist_by_category: dict[str, list[str]] = Field(
        default_factory=dict,
        alias="P2_SPEC_WHITELIST_BY_CATEGORY",
    )

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

    @field_validator("p2_spec_whitelist_by_category", mode="before")
    @classmethod
    def _parse_p2_spec_whitelist_by_category(cls, value: object) -> dict[str, list[str]]:
        if value is None or value == "":
            return {}

        raw = value
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError("P2_SPEC_WHITELIST_BY_CATEGORY must be valid JSON") from exc

        if not isinstance(raw, dict):
            raise ValueError("P2_SPEC_WHITELIST_BY_CATEGORY must be a mapping")

        normalized: dict[str, list[str]] = {}
        for category, keys in raw.items():
            category_name = str(category).strip()
            if not category_name:
                continue

            if isinstance(keys, str):
                key_values = [keys]
            elif isinstance(keys, (list, tuple, set)):
                key_values = list(keys)
            else:
                raise ValueError(f"P2 whitelist keys for {category_name!r} must be a list or string")

            normalized_keys = sorted({str(key).strip() for key in key_values if str(key).strip()})
            normalized[category_name] = normalized_keys

        return normalized


@lru_cache(maxsize=1)
def get_ai_settings() -> AISettings:
    return AISettings()
