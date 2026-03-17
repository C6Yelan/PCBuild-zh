# backend/services/crawler/parsers/coolpc_ram.py
from __future__ import annotations

import re

from .base import ListingCandidate
from .coolpc_filters import is_ram_promo, normalize_listing_extra, should_skip_listing
from .coolpc_text import parse_int_price, to_text
from .coolpc_url import build_buy_url, extract_ibuy_from_href, resolve_listing_url
from .sku_hints import extract_listing_hints

_RAM_BLOCK_RE = re.compile(
    r"(?is)"
    r"(?:<div\s+class=w>\s*(?P<ibuy>[^<]+?)\s*</div>\s*)?"
    r"<span\b[^>]*onclick=['\"]Show\(this\)['\"][^>]*>.*?"
    r"(?:<a\b[^>]*href=['\"](?P<href>[^'\"]+)['\"][^>]*>)?.*?"
    r"<div\s+class=t>\s*(?P<title>.*?)\s*</div>\s*"
    r"<div\s+class=x>\s*含稅[:：]?\s*NT(?P<price>[0-9,]{1,})\b.*?</div>.*?"
    r"</span>",
    flags=re.IGNORECASE | re.DOTALL,
)


def parse_ram_fast_path(
    *,
    html: str,
    page_url: str,
    category: str,
    seen_ibuy: set[str],
) -> list[ListingCandidate]:
    items: list[ListingCandidate] = []
    seen: set[tuple[str, int]] = set()

    for match in _RAM_BLOCK_RE.finditer(html):
        raw_title = to_text(match.group("title"))
        price = parse_int_price(match.group("price"))
        href = (match.group("href") or "").strip()
        ibuy = (match.group("ibuy") or "").strip()
        buy_url = None

        if not ibuy and href:
            extracted_ibuy = extract_ibuy_from_href(href)
            if extracted_ibuy:
                ibuy = extracted_ibuy
        if ibuy:
            if ibuy in seen_ibuy:
                continue
            seen_ibuy.add(ibuy)
            buy_url = build_buy_url(page_url=page_url, ibuy=ibuy)
        if category != "RAM" and not buy_url:
            continue
        url = buy_url or (resolve_listing_url(page_url=page_url, href=href) if href else page_url)

        if not raw_title or price is None:
            continue
        if is_ram_promo(raw_title, url, price):
            continue
        if not ibuy:
            key = (raw_title, price)
            if key in seen:
                continue
            seen.add(key)

        hints = extract_listing_hints(category, raw_title, None)
        if should_skip_listing(
            category=category,
            title=raw_title,
            price=price,
            hints_extra=hints.extra,
            hints_is_bundle=hints.is_bundle,
        ):
            continue

        items.append(
            ListingCandidate(
                title=raw_title,
                price=price,
                currency="TWD",
                category=category,
                url=url,
                sku_hint=hints.sku_hint,
                extra=normalize_listing_extra(category, hints.extra),
            )
        )

    return items
