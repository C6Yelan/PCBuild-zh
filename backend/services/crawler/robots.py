# backend/services/crawler/robots.py
from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx


@dataclass(frozen=True)
class _CachedRobots:
    parser: RobotFileParser
    fetched_at_mono: float


class RobotsManager:
    """
    robots.txt 管理器（最小可用版）：
    - 下載 /robots.txt
    - RobotFileParser.parse + can_fetch 判斷是否允許抓取
    - 以 origin 快取，避免每次都重抓
    """

    def __init__(self, *, client: httpx.Client, user_agent: str, cache_ttl_seconds: int) -> None:
        self._client = client
        self._ua = user_agent
        self._ttl = cache_ttl_seconds
        self._cache: dict[str, _CachedRobots] = {}

    def can_fetch(self, url: str) -> bool:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False

        origin = f"{parsed.scheme}://{parsed.netloc}"
        rp = self._get_or_fetch(origin)
        return rp.can_fetch(self._ua, url)  # Python RobotFileParser.can_fetch :contentReference[oaicite:1]{index=1}

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
            if 200 <= resp.status_code < 300:
                rp.parse(resp.text.splitlines())
            elif 400 <= resp.status_code < 500 and resp.status_code != 429:
                rp.parse([])  # 視為沒有 robots 限制（allow all）
            else:
                rp.parse(["User-agent: *", "Disallow: /"])  # 保守：暫時禁止
        except Exception:
            rp.parse(["User-agent: *", "Disallow: /"])

        self._cache[origin] = _CachedRobots(parser=rp, fetched_at_mono=now)
        return rp
