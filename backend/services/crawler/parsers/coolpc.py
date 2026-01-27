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
    r"(?P<details>.*?)"
    r"<div\s+class=x>\s*含稅[:：]?\s*NT(?P<price>[0-9,]{3,})\b"
)

# RAM: span onclick=Show(this) 形式（不保證有 iBuy）
_RAM_BLOCK_RE = re.compile(
    r"<span\b[^>]*onclick=['\"]Show\(this\)['\"][^>]*>.*?"
    r"(?:<a\b[^>]*href=['\"](?P<href>[^'\"]+)['\"][^>]*>)?.*?"
    r"<div\s+class=t>\s*(?P<title>.*?)\s*</div>\s*"
    r"<div\s+class=x>\s*含稅[:：]?\s*NT(?P<price>[0-9,]{1,})\b.*?</div>.*?"
    r"</span>\s*(?:<div\s+class=w>\s*(?P<ibuy>[^<]+?)\s*</div>)?",
    flags=re.IGNORECASE | re.DOTALL,
)

_RAM_PROMO_TITLE_RE = re.compile(r"^\s*活動", flags=re.IGNORECASE)
_RAM_PROMO_URL_RE = re.compile(r"docs\.google\.com/forms", flags=re.IGNORECASE)

# 用於解析 CASE 描述行（div 內容）
_DETAIL_DIV_RE = re.compile(r"(?is)<div\b[^>]*>(?P<text>.*?)</div>")

# 退回純文字模式（拿不到 iBuy 時，url 只能先用 page_url）
_ITEM_TEXT_RE = re.compile(
    r"(?m)^(?P<title>.{6,200}?)\s*含稅[:：]?\s*NT(?P<price>[0-9,]{3,})\b"
)

_COOLPC_IGRP_CATEGORY: dict[str, str] = {
    "4": "CPU",   # 處理器總覽
    "5": "MB",    # 主機板總覽
    "6": "RAM",   # 記憶體總覽
    "7": "SSD",   # 固態硬碟 M.2｜SSD
    "8": "HDD",   # 硬碟 HDD
    "10": "COOLER", # CPU散熱｜散熱墊｜散熱膏總覽
    "11": "LIQUID_COOLING", # 水冷總覽
    "14": "CASE", # 機殼總覽
    "15": "PSU",  # 電源供應器總覽
    "16": "CASE_FAN",  # 機殼風扇｜機殼配件總覽
    "27": "EXPANSION_CARD",  # 介面擴充卡｜專業Raid卡總覽
    "12": "GPU",  # 顯示卡總覽 :contentReference[oaicite:3]{index=3}
    # 之後要擴充再加：機殼 IGrp=14、電源 IGrp=15、風扇/配件 IGrp=16 ...
}

def _compact_extra(extra: dict | None) -> dict | None:
    if not extra:
        return extra
    return {k: v for k, v in extra.items() if v is not None}

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

def _is_ram_promo(title: str, url: str, price: int | None) -> bool:
    if price is not None and price <= 1:
        return True
    if _RAM_PROMO_TITLE_RE.search(title or ""):
        return True
    if _RAM_PROMO_URL_RE.search(url or ""):
        return True
    return False

def _extract_detail_lines(fragment: str) -> list[str]:
    lines: list[str] = []
    for m in _DETAIL_DIV_RE.finditer(fragment or ""):
        text = _to_text(m.group("text"))
        if text:
            lines.append(text)
    return lines

class CoolpcListingParser:
    source_id = "coolpc"

    def parse_listings(self, *, html: str, page_url: str) -> list[ListingCandidate]:
        category = _infer_category_from_page_url(page_url) or "UNKNOWN"
        if not html:
            return []

        items: list[ListingCandidate] = []
        seen_ibuy: set[str] = set()

        if category in ("RAM", "SSD", "HDD", "COOLER", "LIQUID_COOLING"):
            seen: set[tuple[str, int]] = set()
            for m in _RAM_BLOCK_RE.finditer(html):
                raw_title = _to_text(m.group("title"))
                price = _parse_int_price(m.group("price"))
                href = (m.group("href") or "").strip()
                ibuy = (m.group("ibuy") or "").strip()
                buy_url = None
                if ibuy:
                    if ibuy in seen_ibuy:
                        continue
                    seen_ibuy.add(ibuy)
                    buy_url = f"https://www.coolpc.com.tw/evaluate.php?iBuy={quote(ibuy, safe='')}"
                    buy_url = urljoin(page_url, buy_url)
                url = buy_url or (urljoin(page_url, href) if href else page_url)

                if not raw_title or price is None:
                    continue
                if _is_ram_promo(raw_title, url, price):
                    continue
                if not ibuy:
                    key = (raw_title, price)
                    if key in seen:
                        continue
                    seen.add(key)

                hints = extract_listing_hints(category, raw_title, None)
                if category == "LIQUID_COOLING" and hints.extra and hints.extra.get("is_accessory"):
                    continue
                items.append(
                    ListingCandidate(
                        title=raw_title,
                        price=price,
                        currency="TWD",
                        category=category,
                        url=url,
                        sku_hint=hints.sku_hint,
                        extra=_compact_extra(hints.extra),
                    )
                )

            if items:
                return items

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
            if category == "RAM" and _is_ram_promo(raw_title, buy_url, price):
                continue
            detail_lines = _extract_detail_lines(m.group("details")) if category in ("CASE", "PSU", "CASE_FAN", "EXPANSION_CARD") else None
            hints = extract_listing_hints(category, raw_title, detail_lines)
            if category == "CPU" and hints.extra and hints.extra.get("is_accessory"):
                continue
            if category == "MB" and hints.is_bundle:
                continue
            if category == "GPU" and hints.extra and hints.extra.get("is_accessory"):
                continue
            if category == "LIQUID_COOLING" and hints.extra and hints.extra.get("is_accessory"):
                continue

            items.append(
                ListingCandidate(
                    title=raw_title,
                    price=price,
                    currency="TWD",
                    category=category,
                    url=buy_url,
                    sku_hint=hints.sku_hint,
                    extra=_compact_extra(hints.extra) if category in ("RAM", "SSD", "HDD", "COOLER", "LIQUID_COOLING", "CASE", "PSU", "CASE_FAN", "EXPANSION_CARD") else hints.extra,
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

            if category == "RAM" and _is_ram_promo(raw_title, page_url, price):
                continue
            hints = extract_listing_hints(category, raw_title, None)
            if category == "CPU" and hints.extra and hints.extra.get("is_accessory"):
                continue
            if category == "MB" and hints.is_bundle:
                continue
            if category == "GPU" and hints.extra and hints.extra.get("is_accessory"):
                continue
            if category == "LIQUID_COOLING" and hints.extra and hints.extra.get("is_accessory"):
                continue

            items.append(
                ListingCandidate(
                    title=raw_title,
                    price=price,
                    currency="TWD",
                    category=category,
                    url=page_url,
                    sku_hint=hints.sku_hint,
                    extra=_compact_extra(hints.extra) if category in ("RAM", "SSD", "HDD", "COOLER", "LIQUID_COOLING", "CASE", "PSU", "CASE_FAN", "EXPANSION_CARD") else hints.extra,
                )
            )

        return items
