# backend/services/crawler/robots.py
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx


@dataclass
class _CachedRobots:
    parser: RobotFileParser
    fetched_at_mono: float


class RobotsManager:
    """
    robots.txt 管理器（最小可用版）：
    - 以 httpx 取得 robots.txt
    - 以 RobotFileParser 解析並用 can_fetch 判斷
    - 設 TTL 快取，避免頻繁抓 robots.txt

    參考：
    - robots.txt 協議屬於爬蟲應遵循的規範，但不是授權機制。:contentReference[oaicite:3]{index=3}
    - RobotFileParser 的 can_fetch 用法見 Python 文件。:contentReference[oaicite:4]{index=4}
    """

    def __init__(
        self,
        *,
        client: httpx.Client,
        user_agent: str,
        cache_ttl_seconds: int,
    ) -> None:
        self._client = client
        self._ua = user_agent
        self._ttl = cache_ttl_seconds
        self._cache: dict[str, _CachedRobots] = {}

    def can_fetch(self, url: str) -> bool:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False

        cache_key = f"{parsed.scheme}://{parsed.netloc}"
        rp = self._get_or_fetch(cache_key)

        # RobotFileParser.can_fetch(useragent, url)
        return rp.can_fetch(self._ua, url)

    def _get_or_fetch(self, origin: str) -> RobotFileParser:
        now = time.monotonic()
        cached = self._cache.get(origin)
        if cached and (now - cached.fetched_at_mono) < self._ttl:
            return cached.parser

        robots_url = f"{origin}/robots.txt"

        rp = RobotFileParser()
        rp.set_url(robots_url)

        try:
            resp = self._client.get(robots_url, headers={"User-Agent": self._ua})
            status = resp.status_code

            # 依 Google 對狀態碼的整理：4xx(除 429) 視為沒有 crawl restrictions。:contentReference[oaicite:5]{index=5}
            if 200 <= status < 300:
                rp.parse(resp.text.splitlines())
            elif 400 <= status < 500 and status != 429:
                rp.parse([])  # allow all
            else:
                # 429 / 5xx / 其他：保守起見先暫停抓取（disallow all）
                rp.parse(["User-agent: *", "Disallow: /"])
        except Exception:
            # 網路/DNS/timeout 等，Google 也視作 server error 類型處理。:contentReference[oaicite:6]{index=6}
            rp.parse(["User-agent: *", "Disallow: /"])

        self._cache[origin] = _CachedRobots(parser=rp, fetched_at_mono=now)
        return rp
