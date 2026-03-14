# backend/services/crawler/parsers/coolpc.py
from __future__ import annotations

import re

from .base import ListingCandidate
from .coolpc_category import infer_category_from_page_url
from .coolpc_filters import (
    is_ram_promo,
    normalize_listing_extra,
    requires_detail_lines,
    requires_single_item_url,
    should_skip_listing,
)
from .coolpc_ram import parse_ram_fast_path
from .coolpc_text import extract_detail_lines, parse_int_price, to_text
from .coolpc_url import build_buy_url
from .sku_hints import extract_listing_hints

# 以「div.w(iBuy token) + span(商品區塊)」成對解析
_BLOCK_RE = re.compile(
    r"(?is)"
    r"<div\s+class=w>\s*(?P<ibuy>[^<]+?)\s*</div>\s*"
    r"<span\b[^>]*>.*?"
    r"<div\s+class=t>\s*(?P<title>.*?)\s*</div>\s*"
    r"(?P<details>.*?)"
    r"<div\s+class=x>\s*含稅[:：]?\s*NT(?P<price>[0-9,]{3,})\b"
)

# 退回純文字模式（拿不到 iBuy 時，url 只能先用 page_url）
_ITEM_TEXT_RE = re.compile(
    r"(?m)^(?P<title>.{6,200}?)\s*含稅[:：]?\s*NT(?P<price>[0-9,]{3,})\b"
)

class CoolpcListingParser:
    source_id = "coolpc"

    def parse_listings(self, *, html: str, page_url: str) -> list[ListingCandidate]:
        category = infer_category_from_page_url(page_url) or "UNKNOWN"
        if not html:
            return []

        items: list[ListingCandidate] = []
        seen_ibuy: set[str] = set()

        if category == "RAM":
            items = parse_ram_fast_path(
                html=html,
                page_url=page_url,
                category=category,
                seen_ibuy=seen_ibuy,
            )

            # RAM 可能真的拿不到 iBuy，所以 RAM 仍保留這段 fast-path；其餘類別繼續往下用 _BLOCK_RE 解析 iBuy
            if category == "RAM" and items:
                return items

        # 1) 優先用 iBuy token 解析：可產生每筆單品唯一 URL
        for m in _BLOCK_RE.finditer(html):
            ibuy = (m.group("ibuy") or "").strip()
            raw_title = to_text(m.group("title"))
            price = parse_int_price(m.group("price"))

            if not ibuy or not raw_title or price is None:
                continue
            if ibuy in seen_ibuy:
                continue
            seen_ibuy.add(ibuy)

            # iBuy 是 base64，含 + / =，必須 URL encode 才穩定
            buy_url = build_buy_url(page_url=page_url, ibuy=ibuy)
            if category == "RAM" and is_ram_promo(raw_title, buy_url, price):
                continue
            detail_lines = extract_detail_lines(m.group("details")) if requires_detail_lines(category) else None
            hints = extract_listing_hints(category, raw_title, detail_lines)
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
                    url=buy_url,
                    sku_hint=hints.sku_hint,
                    extra=normalize_listing_extra(category, hints.extra),
                )
            )

        if items:
            return items
        
        # 這些類別必須有“單品 URL”，純文字 fallback 只能給分類頁 page_url，會造成錯連結污染
        if requires_single_item_url(category):
            return []

        # 2) fallback：純文字（拿不到 iBuy 時就只能用 page_url）
        text = to_text(html)
        seen: set[tuple[str, int]] = set()
        for m in _ITEM_TEXT_RE.finditer(text):
            raw_title = (m.group("title") or "").strip()
            price = parse_int_price(m.group("price"))
            if not raw_title or price is None:
                continue
            key = (raw_title, price)
            if key in seen:
                continue
            seen.add(key)

            if category == "RAM" and is_ram_promo(raw_title, page_url, price):
                continue
            hints = extract_listing_hints(category, raw_title, None)
            if should_skip_listing(
                category=category,
                title=raw_title,
                price=price,
                hints_extra=hints.extra,
                hints_is_bundle=hints.is_bundle,
            ):
                continue
            
            # 這些類別必須有 evaluate.php?iBuy= 的單品 URL；純文字 fallback 只能給分類頁 page_url，直接跳過
            if requires_single_item_url(category):
                continue

            items.append(
                ListingCandidate(
                    title=raw_title,
                    price=price,
                    currency="TWD",
                    category=category,
                    url=page_url,
                    sku_hint=hints.sku_hint,
                    extra=normalize_listing_extra(category, hints.extra),
                )
            )

        return items
