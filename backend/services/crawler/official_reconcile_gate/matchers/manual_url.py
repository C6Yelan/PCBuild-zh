# backend/services/crawler/official_reconcile_gate/matchers/manual_url.py
from __future__ import annotations

from urllib.parse import urlparse

from ..types import MatchResult, RetailRecord


class ManualUrlMatcher:
    """
    Generic matcher:
    - extra.official_url: string
    - extra.official_urls: list[string] or string
    """

    def match(self, record: RetailRecord) -> MatchResult:
        candidates = _collect_candidates(record)
        if not candidates:
            return MatchResult(status="skipped", official_url=None, reason="NO_OFFICIAL_URL")
        return MatchResult(status="matched", official_url=candidates[0], reason="MANUAL_URL")


def _collect_candidates(record: RetailRecord) -> list[str]:
    out: list[str] = []
    extra = record.extra or {}

    _push_candidate(out, extra.get("official_url"))

    raw_urls = extra.get("official_urls")
    if isinstance(raw_urls, list):
        for item in raw_urls:
            _push_candidate(out, item)
    else:
        _push_candidate(out, raw_urls)

    dedup: list[str] = []
    seen: set[str] = set()
    for u in out:
        if u in seen:
            continue
        seen.add(u)
        dedup.append(u)
    return dedup


def _push_candidate(out: list[str], candidate: object) -> None:
    if not isinstance(candidate, str):
        return
    url = candidate.strip()
    if not url:
        return

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        return
    if not parsed.netloc:
        return
    out.append(url)
