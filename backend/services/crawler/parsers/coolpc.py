# backend/services/crawler/parsers/coolpc.py
from __future__ import annotations

import html as _html
import re
from urllib.parse import quote, urljoin

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

_SKU_HINT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])("  # 左邊界：前一字元不是英數（避免吃到字中間）
    r"(?:i[3579]-\d{4,5}[a-z0-9]{0,6})|"                       # i5-12400F / i7-14700K
    r"(?:core\s+ultra\s+\d+\s+\d{3}[a-z0-9]{0,6})|"            # Core Ultra 5 225F
    r"(?:ryzen\s+[3579]\s+\d{4,5}[a-z0-9]{0,6})|"              # Ryzen 7 9800X3D（含 X3D）
    r"(?:amd\s+)?r[3579]\s*\d{4,5}[a-z0-9]{0,6}|"              # AMD R5 8400F盒 / R7 9800X3D代理...
    r"(?:xeon\s+w\d+-\d{4,5}[a-z0-9]{0,6})|"                   # Xeon W7-3465X
    r"(?:ryzen\s+tr\s+(?:pro\s+)?\d{4,5}[a-z0-9]{0,6})|"       # Ryzen TR / TR PRO
    r"(?:threadripper\s+(?:pro\s+)?\d{4,5}[a-z0-9]{0,6})"
    r")(?=[^A-Za-z0-9]|$)"  # 右邊界：下一字元不是英數（中文緊貼也能切開）
)

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

def _sku_hint(title: str) -> str | None:
    m = _SKU_HINT_RE.search(title or "")
    return m.group(1) if m else None

class CoolpcListingParser:
    source_id = "coolpc"

    def parse_listings(self, *, html: str, page_url: str) -> list[ListingCandidate]:
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

            items.append(
                ListingCandidate(
                    title=raw_title,
                    price=price,
                    currency="TWD",
                    category="CPU",
                    url=buy_url,
                    sku_hint=_sku_hint(raw_title),
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

            items.append(
                ListingCandidate(
                    title=raw_title,
                    price=price,
                    currency="TWD",
                    category="CPU",
                    url=page_url,
                    sku_hint=_sku_hint(raw_title),
                )
            )

        return items
