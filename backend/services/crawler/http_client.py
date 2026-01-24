# backend/services/crawler/http_client.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

import time
from urllib.parse import urlparse
import httpx

from .config import CrawlerSettings
from .robots import RobotsManager

@dataclass(frozen=True)
class FetchResult:
    url: str
    final_url: str
    status_code: int
    headers: Mapping[str, str]
    content: bytes
    text: str


class CrawlerHttpClient:
    """
    純 HTTP 抓取核心：
    - 統一 timeout、UA、redirect policy
    - 連線層 retries（降低不穩網路的失敗率）
    - 先不做解析、不做 DB，保持單一職責
    """

    def __init__(self, settings: Optional[CrawlerSettings] = None) -> None:
        self.settings = settings or CrawlerSettings()

        transport = httpx.HTTPTransport(retries=self.settings.connect_retries)

        # httpx 的 timeout 概念是「網路閒置超時」等分項 timeout；此處先用總體簡化版
        timeout = httpx.Timeout(self.settings.timeout_seconds)

        self._client = httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=True,
            max_redirects=self.settings.max_redirects,
            headers={"User-Agent": self.settings.user_agent},
        )
        self._robots = RobotsManager(
            client=self._client,
            user_agent=self.settings.user_agent,
            cache_ttl_seconds=self.settings.robots_cache_ttl_seconds,
        )
        self._last_req_mono_by_origin: dict[str, float] = {}

        self._robots = RobotsManager(
            client=self._client,
            user_agent=self.settings.user_agent,
            cache_ttl_seconds=self.settings.robots_cache_ttl_seconds,
        )
        self._last_req_mono_by_host: dict[str, float] = {}

    def close(self) -> None:
        self._client.close()

    def fetch(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
    ) -> FetchResult:
        """
        回傳文字內容（HTML/JSON 皆可用 text 先承接）。
        - 解析 JSON / HTML 的責任留給下一層 parser
        - headers 可用於條件式請求（If-None-Match/If-Modified-Since）後續擴充
          這類 HTTP revalidation(重新驗證) 機制可參考 MDN 的說明。:contentReference[oaicite:3]{index=3}
        """
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""

        # 禮貌延遲：同一 origin 兩次請求間隔
        delay = float(self.settings.politeness_delay_seconds or 0.0)
        if delay > 0 and origin:
            last = self._last_req_mono_by_origin.get(origin)
            now = time.monotonic()
            if last is not None:
                wait = delay - (now - last)
                if wait > 0:
                    time.sleep(wait)

        # robots.txt：不允許就直接擋下
        if self.settings.respect_robots_txt and not self._robots.can_fetch(url):
            raise PermissionError(f"Blocked by robots.txt: {url}")


        req_headers = {}
        if headers:
            req_headers.update(headers)

        resp = self._client.get(url, headers=req_headers)
        if origin:
            self._last_req_mono_by_origin[origin] = time.monotonic()

        return FetchResult(
            url=url,
            final_url=str(resp.url),
            status_code=resp.status_code,
            headers=dict(resp.headers),
            content=resp.content,
            text=resp.text,
        )

    def __enter__(self) -> "CrawlerHttpClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
