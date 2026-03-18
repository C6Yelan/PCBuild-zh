# backend/services/chat/config.py
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, SecretBytes, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

OPENAI_COMPAT_PROVIDERS = (
    "openai_compat",
    "local_openai_compat",
    "backup_openai_compat",
)
ALLOWED_AI_PROVIDERS = OPENAI_COMPAT_PROVIDERS + ("gemini",)
AIProviderAlias = Literal[
    "openai_compat",
    "local_openai_compat",
    "backup_openai_compat",
    "gemini",
]

HISTORY_MAX_TURNS = 8
SYSTEM_PROMPT = "你是電腦組裝顧問，所有回覆一律使用繁體中文。"


@dataclass(frozen=True, slots=True)
class OpenAICompatRuntimeConfig:
    provider: str
    model: str
    timeout_seconds: float
    base_url: str | None
    api_key: SecretStr | SecretBytes | str | None


@dataclass(frozen=True, slots=True)
class GeminiRuntimeConfig:
    provider: Literal["gemini"]
    model: str
    timeout_seconds: float
    api_key: SecretStr | SecretBytes | str | None


ProviderRuntimeConfig = OpenAICompatRuntimeConfig | GeminiRuntimeConfig


class AISettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    ai_provider: AIProviderAlias = Field(alias="AI_PROVIDER")
    ai_model: str = Field(alias="AI_MODEL")
    ai_timeout_seconds: float = Field(gt=0, alias="AI_TIMEOUT_SECONDS")
    ai_max_output_chars: int = Field(gt=0, alias="AI_MAX_OUTPUT_CHARS")
    ai_oai_base_url: str | None = Field(default=None, alias="AI_OAI_BASE_URL")
    ai_oai_api_key: SecretStr | None = Field(default=None, alias="AI_OAI_API_KEY")
    ai_raw_snapshot_dir: str = Field(
        default="/tmp/pcbuild_ai_raw_snapshots",
        alias="AI_RAW_SNAPSHOT_DIR",
    )
    gemini_api_key: SecretStr | None = Field(default=None, alias="GEMINI_API_KEY")
    google_api_key: SecretStr | None = Field(default=None, alias="GOOGLE_API_KEY")
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

    @field_validator("ai_model")
    @classmethod
    def _validate_ai_model(cls, value: str) -> str:
        value = value.strip()
        if value:
            return value
        raise ValueError("AI_MODEL must not be empty")

    @field_validator("ai_oai_base_url")
    @classmethod
    def _validate_oai_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("AI_OAI_BASE_URL must use http or https")
        if not parsed.netloc:
            raise ValueError("AI_OAI_BASE_URL must include host")
        return value.rstrip("/")

    @field_validator("ai_raw_snapshot_dir")
    @classmethod
    def _validate_ai_raw_snapshot_dir(cls, value: str) -> str:
        value = value.strip()
        if value:
            return value
        raise ValueError("AI_RAW_SNAPSHOT_DIR must not be empty")

    @model_validator(mode="after")
    def _validate_provider_requirements(self) -> "AISettings":
        if self.ai_provider in OPENAI_COMPAT_PROVIDERS:
            if not self.ai_oai_base_url:
                raise ValueError(
                    "AI_OAI_BASE_URL is required for openai-compatible providers"
                )
            return self

        if self.ai_provider == "gemini":
            if self.get_gemini_api_key() is None:
                raise ValueError(
                    "GEMINI_API_KEY or GOOGLE_API_KEY is required for gemini provider"
                )
            return self

        return self

    def get_gemini_api_key(self) -> SecretStr | None:
        return self.google_api_key or self.gemini_api_key

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
                raise ValueError(
                    f"Compression whitelist keys for {category_name!r} must be a list or string"
                )

            normalized_keys = sorted({str(key).strip() for key in key_values if str(key).strip()})
            normalized[category_name] = normalized_keys

        return normalized


@lru_cache(maxsize=1)
def get_ai_settings() -> AISettings:
    return AISettings()


def resolve_secret_text(
    value: SecretStr | SecretBytes | str | None,
) -> str | None:
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    if isinstance(value, SecretBytes):
        secret_bytes = value.get_secret_value()
        return secret_bytes.decode("utf-8", errors="ignore")
    if isinstance(value, str):
        return value
    return None


def resolve_gemini_api_key_secret(
    settings: AISettings | object | None = None,
) -> SecretStr | SecretBytes | str | None:
    resolved_settings = settings or get_ai_settings()
    if isinstance(resolved_settings, AISettings):
        return resolved_settings.get_gemini_api_key()
    google_api_key = getattr(resolved_settings, "google_api_key", None)
    if google_api_key is not None:
        return google_api_key
    return getattr(resolved_settings, "gemini_api_key", None)


def get_gemini_api_key_value(settings: AISettings | object | None = None) -> str | None:
    return resolve_secret_text(resolve_gemini_api_key_secret(settings))


def build_provider_runtime_config(settings: AISettings | object) -> ProviderRuntimeConfig:
    provider = str(getattr(settings, "ai_provider"))
    model = str(getattr(settings, "ai_model"))
    timeout_seconds = float(getattr(settings, "ai_timeout_seconds"))

    if provider in OPENAI_COMPAT_PROVIDERS:
        return OpenAICompatRuntimeConfig(
            provider=provider,
            model=model,
            timeout_seconds=timeout_seconds,
            base_url=getattr(settings, "ai_oai_base_url", None),
            api_key=getattr(settings, "ai_oai_api_key", None),
        )

    if provider == "gemini":
        return GeminiRuntimeConfig(
            provider="gemini",
            model=model,
            timeout_seconds=timeout_seconds,
            api_key=resolve_gemini_api_key_secret(settings),
        )

    raise ValueError(f"Unsupported AI provider: {provider}")
