# backend/services/crawler/link_consistency_gate/extract.py
# 把「網頁原始 HTML」轉成「可判斷連結是否正確」的結構化訊號，讓你的 Link Consistency Gate 能穩定地做偵測、判斷與留證據
from __future__ import annotations

import html as html_lib
import re
from typing import Optional
from urllib.parse import urljoin

from .types import PageSignals


_RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", flags=re.IGNORECASE | re.DOTALL) # 抓取<title>標籤中的內容
_RE_H1 = re.compile(r"<h1[^>]*>(.*?)</h1>", flags=re.IGNORECASE | re.DOTALL) # 抓取<h1>標籤中的內容
_RE_TAG = re.compile(r"<[^>]+>", flags=re.DOTALL) # 移除所有HTML標籤
_RE_WS = re.compile(r"\s+", flags=re.UNICODE) # 將各種空白字符壓成一個空格
_RE_SCRIPT = re.compile(r"<script\b[^>]*>.*?</script>", flags=re.IGNORECASE | re.DOTALL) # 抓取<script>標籤及其內容
_RE_STYLE = re.compile(r"<style\b[^>]*>.*?</style>", flags=re.IGNORECASE | re.DOTALL) # 抓取<style>標籤及其內容
_RE_LINK_TAG = re.compile(r"<link\b[^>]*>", flags=re.IGNORECASE) # 抓取<link>標籤
_RE_REL_CANONICAL = re.compile(r"""rel\s*=\s*["']canonical["']""", flags=re.IGNORECASE) # 抓取<link>中是否有rel="canonical"屬性
_RE_ATTR_HREF = re.compile(r"""href\s*=\s*["']([^"']+)["']""", flags=re.IGNORECASE) # 抓取href屬性


def _clean_text(s: str) -> str: # 將抽出的title/h1內容變成乾淨文字
    s = html_lib.unescape(s)
    s = _RE_TAG.sub(" ", s)
    s = _RE_WS.sub(" ", s).strip()
    return s


def html_to_text(html_bytes: bytes, *, max_chars: Optional[int] = None) -> str:
    """
    HTML bytes → 輕量「可視文字」的轉換：
    - 移除 script/style 區塊
    - 移除標籤
    - 壓縮空白

    阻擋頁/驗證頁比對；產生 text hint(ex: 前400字)供後續比對使用
    """
    text = html_bytes.decode("utf-8", errors="replace")
    text = _RE_SCRIPT.sub(" ", text)
    text = _RE_STYLE.sub(" ", text)
    text = _RE_TAG.sub(" ", text)
    text = html_lib.unescape(text)
    text = _RE_WS.sub(" ", text).strip()
    if max_chars is not None and max_chars >= 0:
        text = text[:max_chars]
    return text


def extract_page_signals( # 從HTML bytes中抽取頁面訊號
    html_bytes: bytes,
    *,
    final_url: str,
    http_status: int,
    max_text_hint_chars: int = 400,
) -> PageSignals:
    text = html_bytes.decode("utf-8", errors="replace")

    page_title = _extract_first(text, _RE_TITLE) # 用_RE_TITLE正則表達式從HTML中抽取<title>標籤的內容
    if page_title is not None:
        page_title = _clean_text(page_title)
        if not page_title:
            page_title = None

    page_h1 = _extract_first(text, _RE_H1) # 用_RE_H1正則表達式從HTML中抽取<h1>標籤的內容
    if page_h1 is not None:
        page_h1 = _clean_text(page_h1)
        if not page_h1:
            page_h1 = None

    canonical_url = _extract_canonical(text, base_url=final_url) # 用_extract_canonical函數從HTML中抽取<link rel="canonical">標籤的href屬性，並將相對URL轉換為絕對URL
    if canonical_url is not None:
        canonical_url = canonical_url.strip()
        if not canonical_url:
            canonical_url = None

    text_hint = html_to_text(html_bytes, max_chars=max_text_hint_chars) if max_text_hint_chars > 0 else "" # 從HTML bytes中抽取可視文字，並限制最大字數為max_text_hint_chars
    if not text_hint:
        text_hint = None

    return PageSignals(
        final_url=final_url,
        http_status=http_status,
        page_title=page_title,
        page_h1=page_h1,
        canonical_url=canonical_url,
        text_hint=text_hint,
    )


def _extract_first(text: str, pattern: re.Pattern[str]) -> Optional[str]: # 從text中使用正則表達式pattern抽取第一個匹配的內容
    m = pattern.search(text)
    if not m:
        return None
    return m.group(1)


def _extract_canonical(text: str, *, base_url: str) -> Optional[str]: # 從text中抽取<link rel="canonical">標籤的href屬性，並將相對URL轉換為絕對URL  
    for m in _RE_LINK_TAG.finditer(text):
        tag = m.group(0)
        if not _RE_REL_CANONICAL.search(tag):
            continue
        href_m = _RE_ATTR_HREF.search(tag)
        if not href_m:
            continue
        href = html_lib.unescape(href_m.group(1)).strip()
        if not href:
            continue
        return urljoin(base_url, href)
    return None
