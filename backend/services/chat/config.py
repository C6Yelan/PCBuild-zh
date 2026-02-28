# backend/services/chat/config.py
from __future__ import annotations

from enum import Enum
from functools import lru_cache

from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

HISTORY_MAX_TURNS = 8
SYSTEM_PROMPT = "你是電腦組裝顧問，所有回覆一律使用繁體中文。"


class AIProvider(str, Enum):
    OPENAI_COMPAT = "openai_compat"
    LOCAL_OPENAI_COMPAT = "local_openai_compat"
    BACKUP_OPENAI_COMPAT = "backup_openai_compat"


class ChatSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # P0 provider 白名單（env-only；前端不得覆寫）
    ai_provider: AIProvider = Field(default=AIProvider.OPENAI_COMPAT, alias="AI_PROVIDER")
    ai_model: str = Field(default="gemini-2.5-flash", alias="AI_MODEL")

    # OpenAI-compatible transport 設定（僅後端讀取）
    ai_oai_base_url: HttpUrl = Field(default="http://localhost:8001/v1", alias="AI_OAI_BASE_URL")
    ai_oai_api_key: str = Field(default="", alias="AI_OAI_API_KEY", repr=False)

    # P0 先定義治理參數，行為由 client 視需要接入
    ai_timeout_seconds: float = Field(default=30.0, alias="AI_TIMEOUT_SECONDS", gt=0)
    ai_max_output_chars: int = Field(default=2000, alias="AI_MAX_OUTPUT_CHARS", ge=1)

    @field_validator("ai_model", "ai_oai_api_key")
    @classmethod
    def _strip_text(cls, value: str) -> str:
        return value.strip()


@lru_cache(maxsize=1)
def get_chat_settings() -> ChatSettings:
    return ChatSettings()


# fail-fast：AI_PROVIDER 不在白名單時，服務啟動即 ValidationError
CHAT_SETTINGS = get_chat_settings()
