# backend/services/crawler/parsers/coolpc.py
from __future__ import annotations

import html as _html
import re
from urllib.parse import quote, urljoin, urlparse, parse_qs

from .sku_hints import extract_listing_hints
from .base import ListingCandidate

_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style)\b.*?>.*?</\1>")
_BR_RE = re.compile(r"(?i)<br\s*/?>")

# 以「div.w(iBuy token) + span(商品區塊)」成對解析
_BLOCK_RE = re.compile(
    r"(?is)"
    r"<div\s+class=w>\s*(?P<ibuy>[^<]+?)\s*</div>\s*"
    r"<span\b[^>]*>.*?"
    r"<div\s+class=t>\s*(?P<title>.*?)\s*</div>\s*"
    r"<div\s+class=x>\s*含稅[:：]?\s*NT(?P<price>[0-9,]{3,})\b"
)

# 退回純文字模式（拿不到 iBuy 時，url 只能先用 page_url）
_ITEM_TEXT_RE = re.compile(
    r"(?m)^(?P<title>.{6,200}?)\s*含稅[:：]?\s*NT(?P<price>[0-9,]{3,})\b"
)

_COOLPC_IGRP_CATEGORY: dict[str, str] = {
    "4": "CPU",   # 處理器總覽 :contentReference[oaicite:1]{index=1}
    "5": "MB",    # 主機板總覽 :contentReference[oaicite:2]{index=2}
    "12": "GPU",  # 顯示卡總覽 :contentReference[oaicite:3]{index=3}
    # 之後要擴充再加：機殼 IGrp=14、電源 IGrp=15、風扇/配件 IGrp=16 ... :contentReference[oaicite:4]{index=4}
}

def _infer_category_from_page_url(page_url: str) -> str | None:
    try:
        q = parse_qs(urlparse(page_url).query)
        igrp = (q.get("IGrp") or [None])[0]
        if igrp and igrp in _COOLPC_IGRP_CATEGORY:
            return _COOLPC_IGRP_CATEGORY[igrp]
    except Exception:
        pass
    return None

def _to_text(fragment: str) -> str:
    fragment = _SCRIPT_STYLE_RE.sub(" ", fragment)
    fragment = _BR_RE.sub("\n", fragment)
    fragment = _TAG_RE.sub(" ", fragment)
    fragment = _html.unescape(fragment)
    fragment = re.sub(r"[ \t\u3000]+", " ", fragment)
    fragment = re.sub(r"\n{2,}", "\n", fragment)
    return fragment.strip()

def _parse_int_price(s: str) -> int | None:
    s = (s or "").replace(",", "").strip()
    return int(s) if s.isdigit() else None

class CoolpcListingParser:
    source_id = "coolpc"

    def parse_listings(self, *, html: str, page_url: str) -> list[ListingCandidate]:
        category = _infer_category_from_page_url(page_url) or "UNKNOWN"
        if not html:
            return []

        items: list[ListingCandidate] = []
        seen_ibuy: set[str] = set()

        # 1) 優先用 iBuy token 解析：可產生每筆單品唯一 URL
        for m in _BLOCK_RE.finditer(html):
            ibuy = (m.group("ibuy") or "").strip()
            raw_title = _to_text(m.group("title"))
            price = _parse_int_price(m.group("price"))

            if not ibuy or not raw_title or price is None:
                continue
            if ibuy in seen_ibuy:
                continue
            seen_ibuy.add(ibuy)

            # iBuy 是 base64，含 + / =，必須 URL encode 才穩定
            buy_url = f"https://www.coolpc.com.tw/evaluate.php?iBuy={quote(ibuy, safe='')}"
            buy_url = urljoin(page_url, buy_url)
            hints = extract_listing_hints(category, raw_title)
            if category == "CPU" and hints.extra and hints.extra.get("is_accessory"):
                continue
            if category == "MB" and hints.is_bundle:
                continue
            if category == "GPU" and hints.extra and hints.extra.get("is_accessory"):
                continue

            items.append(
                ListingCandidate(
                    title=raw_title,
                    price=price,
                    currency="TWD",
                    category=category,
                    url=buy_url,
                    sku_hint=hints.sku_hint,
                    extra=hints.extra,
                )
            )

        if items:
            return items

        # 2) fallback：純文字（拿不到 iBuy 時就只能用 page_url）
        text = _to_text(html)
        seen: set[tuple[str, int]] = set()
        for m in _ITEM_TEXT_RE.finditer(text):
            raw_title = (m.group("title") or "").strip()
            price = _parse_int_price(m.group("price"))
            if not raw_title or price is None:
                continue
            key = (raw_title, price)
            if key in seen:
                continue
            seen.add(key)

            hints = extract_listing_hints(category, raw_title)
            if category == "CPU" and hints.extra and hints.extra.get("is_accessory"):
                continue
            if category == "MB" and hints.is_bundle:
                continue
            if category == "GPU" and hints.extra and hints.extra.get("is_accessory"):
                continue

            items.append(
                ListingCandidate(
                    title=raw_title,
                    price=price,
                    currency="TWD",
                    category=category,
                    url=page_url,
                    sku_hint=hints.sku_hint,
                    extra=hints.extra,
                )
            )

        return items
