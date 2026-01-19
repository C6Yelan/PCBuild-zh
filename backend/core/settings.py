# backend/core/settings.py
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    專案設定單一入口（Single Source of Truth）。
    - 從環境變數讀取
    - 可選讀取 .env（若存在）
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    # DB
    database_url: str = Field(alias="DATABASE_URL")

    # GenAI（保留相容性；若兩者同時存在，仍讓 GOOGLE_API_KEY 優先）
    gemini_api_key: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")
    google_api_key: Optional[str] = Field(default=None, alias="GOOGLE_API_KEY")

    # CORS（維持你目前 app.py 的既有行為預設值）
    cors_allow_origins: list[str] = Field(default_factory=lambda: ["https://pcbuild.redfiretw.xyz"])

    def genai_api_key(self) -> Optional[str]:
        # Google SDK 文件亦說明兩者同時存在時 GOOGLE_API_KEY 會優先
        return self.google_api_key or self.gemini_api_key
    
    # Rate limit（可用環境變數覆蓋）
    rate_limit_enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")
    rate_limit_default: str = Field(default="300/minute", alias="RATE_LIMIT_DEFAULT")
    rate_limit_storage_uri: str = Field(default="memory://", alias="RATE_LIMIT_STORAGE_URI")

    # CSRF trusted origins（用逗號分隔的字串）
    csrf_trusted_origins: str = Field(default="", alias="CSRF_TRUSTED_ORIGINS")

    # Debug routes
    debug_routes_enabled: bool = Field(default=False, alias="DEBUG_ROUTES_ENABLED")

    # Logging
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    # FastAPI 官方建議用 lru_cache 避免每次 request 反覆載入設定
    return Settings()
