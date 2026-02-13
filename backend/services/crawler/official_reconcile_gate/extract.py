# backend/services/crawler/official_reconcile_gate/extract.py
from __future__ import annotations

import html as html_lib
import re

from .types import FetchedResponse, OfficialDocument


class ExtractError(RuntimeError):
    pass


_RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", flags=re.IGNORECASE | re.DOTALL)
_RE_OG_TITLE = re.compile(
    r"<meta[^>]+(?:property|name)=[\"']og:title[\"'][^>]*content=[\"']([^\"']+)[\"'][^>]*>",
    flags=re.IGNORECASE,
)
_RE_TAG = re.compile(r"<[^>]+>", flags=re.DOTALL)
_RE_SCRIPT = re.compile(r"<script\b[^>]*>.*?</script>", flags=re.IGNORECASE | re.DOTALL)
_RE_STYLE = re.compile(r"<style\b[^>]*>.*?</style>", flags=re.IGNORECASE | re.DOTALL)
_RE_WS = re.compile(r"\s+", flags=re.UNICODE)


def extract_official_document(response: FetchedResponse, *, max_excerpt_chars: int = 280) -> OfficialDocument:
    if response.body is None:  # pragma: no cover - defensive
        raise ExtractError("response body is None")

    text = response.body.decode("utf-8", errors="replace")
    title = _clean_text(_extract_first(text, _RE_TITLE))
    og_title = _clean_text(_extract_first(text, _RE_OG_TITLE))

    content_type = (response.headers.get("content-type") or "").strip()
    excerpt = _html_to_text(text, max_chars=max_excerpt_chars)

    return OfficialDocument(
        url=response.url,
        final_url=response.final_url,
        status_code=response.status_code,
        fetched_at=response.fetched_at,
        content_type=content_type,
        title=title or og_title,
        raw_excerpt=excerpt or None,
    )


def _extract_first(text: str, pattern: re.Pattern[str]) -> str | None:
    m = pattern.search(text)
    if not m:
        return None
    return m.group(1)


def _clean_text(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = html_lib.unescape(value)
    cleaned = _RE_TAG.sub(" ", cleaned)
    cleaned = _RE_WS.sub(" ", cleaned).strip()
    return cleaned or None


def _html_to_text(text: str, *, max_chars: int) -> str:
    visible = _RE_SCRIPT.sub(" ", text)
    visible = _RE_STYLE.sub(" ", visible)
    visible = _RE_TAG.sub(" ", visible)
    visible = html_lib.unescape(visible)
    visible = _RE_WS.sub(" ", visible).strip()
    if max_chars >= 0:
        visible = visible[:max_chars]
    return visible
