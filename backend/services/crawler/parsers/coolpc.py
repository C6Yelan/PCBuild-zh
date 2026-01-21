# backend/services/crawler/parsers/coolpc.py
from __future__ import annotations

import html as _html
import re
from urllib.parse import urljoin

from .base import ListingCandidate


_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style)\b.*?>.*?</\1>")
_BR_RE = re.compile(r"(?i)<br\s*/?>")

# 盡量先用「a 標籤 + 含稅：NTxxxx」抓（可同時拿到 href）
_ITEM_ANCHOR_RE = re.compile(
    r'(?is)<a[^>]+href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>.*?含稅[:：]?\s*NT(?P<price>[0-9,]{3,})'
)

# 若頁面結構變動，退回「純文字」抓（url 就先用 page_url）
_ITEM_TEXT_RE = re.compile(
    r"(?m)^(?P<title>.{6,200}?)\s*含稅[:：]?\s*NT(?P<price>[0-9,]{3,})\b"
)

# 初版 sku_hint：只做「保守抽取」，抽不到就 None（避免亂推導）
_SKU_HINT_RE = re.compile(
    r"(?i)\b("
    r"(?:i[3579]-\d{4,5}[a-z]{0,4})|"                 # Intel i5-12400F / i7-14700K ...
    r"(?:core\s+ultra\s+\d+\s+\d{3}[a-z]{0,3})|"      # Core Ultra 5 225F ...
    r"(?:ryzen\s+[3579]\s+\d{4,5}[a-z]{0,4})|"        # Ryzen 7 9800X3D（粗略）
    r"(?:r[3579]\s*\d{4,5}[a-z]{0,4})"                # R7 9800X3D（粗略）
    r")\b"
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
    if not s.isdigit():
        return None
    try:
        return int(s)
    except Exception:
        return None


def _sku_hint(title: str) -> str | None:
    m = _SKU_HINT_RE.search(title or "")
    return m.group(1) if m else None


class CoolpcListingParser:
    """
    原價屋 CPU 總覽頁（eachview.php?IGrp=4）解析器（第一版）：
    - 優先解析「a 標籤 + 含稅：NTxxxx」以取得商品 URL
    - 解析不到則退回文字模式（URL 先用 page_url）
    - 僅輸出 listing 候選；不在此步驟做 SKU 正規化與驗證
    """
    source_id = "coolpc"

    def parse_listings(self, *, html: str, page_url: str) -> list[ListingCandidate]:
        if not html:
            return []

        items: list[ListingCandidate] = []
        seen: set[tuple[str, int]] = set()

        # 1) anchor 模式：可取得 href
        for m in _ITEM_ANCHOR_RE.finditer(html):
            raw_title = _to_text(m.group("title"))
            price = _parse_int_price(m.group("price"))
            if not raw_title or price is None:
                continue

            href = m.group("href") or ""
            abs_url = urljoin(page_url, href) if href else page_url

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
                    url=abs_url,
                    sku_hint=_sku_hint(raw_title),
                )
            )

        if items:
            return items

        # 2) fallback：文字模式（無法穩定取得 href）
        text = _to_text(html)
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
