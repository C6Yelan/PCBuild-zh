# backend/services/crawler/config.py
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CrawlerSettings(BaseSettings):
    """
    爬蟲抓取層設定（僅 HTTP fetch）。
    - 解析（parser）與 DB 寫入（ingestion）之後再加，避免耦合。
    """

    model_config = SettingsConfigDict(env_prefix="PCBUILD_CRAWLER_", extra="ignore")

    user_agent: str = Field(
        default="pcbuild-zh-crawler/0.1 (+contact: admin@localhost)",
        description="請放可辨識的 UA，避免被視為惡意流量。",
    )
    timeout_seconds: float = Field(default=15.0, ge=1.0, le=120.0)
    max_redirects: int = Field(default=5, ge=0, le=10)

    # httpx transport 連線層 retries：僅針對 ConnectError/ConnectTimeout 類型較安全
    connect_retries: int = Field(default=2, ge=0, le=10)

    # 之後做 robots / 封鎖策略時會用到（先保留設定）
    respect_robots_txt: bool = Field(default=True)
