# backend/services/crawler/parsers/coolpc_url.py
from __future__ import annotations

import re
from urllib.parse import quote, unquote, urljoin

_IBUY_IN_HREF_RE = re.compile(r"[?&]iBuy=([^&]+)", flags=re.IGNORECASE)


def extract_ibuy_from_href(href: str) -> str | None:
    normalized_href = (href or "").strip()
    if not normalized_href:
        return None
    match = _IBUY_IN_HREF_RE.search(normalized_href)
    if match is None:
        return None
    return unquote(match.group(1))


def build_buy_url(*, page_url: str, ibuy: str) -> str:
    buy_url = f"https://www.coolpc.com.tw/evaluate.php?iBuy={quote(ibuy, safe='')}"
    return urljoin(page_url, buy_url)


def resolve_listing_url(*, page_url: str, href: str) -> str:
    return urljoin(page_url, href)
