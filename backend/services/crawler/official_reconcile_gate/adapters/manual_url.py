# backend/services/crawler/official_reconcile_gate/adapters/manual_url.py
"""Manual URL adapter for T6 pilot flow."""

from __future__ import annotations

from ..extract import extract_signals
from ..fetch import fetch_text
from ..types import ListingInput, OfficialCandidate, OfficialSignals
from ...config import CrawlerSettings

_DEFAULT_MAX_BYTES = 1_048_576


class ManualUrlAdapter:
    official_source = "manual_url"

    def __init__(
        self,
        *,
        user_agent: str | None = None,
        timeout_s: float | None = None,
        max_bytes: int = _DEFAULT_MAX_BYTES,
    ) -> None:
        settings = CrawlerSettings()
        self._user_agent = user_agent or settings.user_agent
        self._timeout_s = float(timeout_s) if timeout_s is not None else settings.timeout_seconds
        self._max_bytes = int(max_bytes)

        if not self._user_agent:
            raise ValueError("user_agent must be non-empty")
        if self._timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        if self._max_bytes <= 0:
            raise ValueError("max_bytes must be > 0")

    def search_candidates(self, item: ListingInput) -> list[OfficialCandidate]:
        extra = item.get("extra")
        if not isinstance(extra, dict):
            return []

        urls: list[tuple[str, str]] = []

        official_url = extra.get("official_url")
        if isinstance(official_url, str):
            value = official_url.strip()
            if value:
                urls.append((value, "official_url"))

        official_urls = extra.get("official_urls")
        if isinstance(official_urls, list):
            if all(isinstance(u, str) for u in official_urls):
                for u in official_urls:
                    value = u.strip()
                    if value:
                        urls.append((value, "official_urls"))

        candidates: list[OfficialCandidate] = []
        for rank, (url, source_field) in enumerate(urls):
            candidates.append(
                {
                    "official_source": self.official_source,
                    "candidate_url": url,
                    "rank": rank,
                    "evidence": {"source_field": source_field},
                }
            )
        return candidates

    def fetch_signals(self, candidate: OfficialCandidate) -> OfficialSignals:
        http_status, final_url, text = fetch_text(
            candidate["candidate_url"],
            user_agent=self._user_agent,
            timeout_s=self._timeout_s,
            max_bytes=self._max_bytes,
        )
        return extract_signals(
            official_url=final_url,
            http_status=http_status,
            html_text=text,
        )
