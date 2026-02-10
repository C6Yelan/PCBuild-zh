# backend/services/crawler/link_consistency_gate/strategies/cpu.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..types import ListingInput, MatchDecision, PageSignals


_RE_WS = re.compile(r"\s+", flags=re.UNICODE) # 壓縮所有類型的空白字符為單一空格，並去除首尾空白。
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE) # 匹配包含字母和數字的連字符分隔的標記，例如 "I5-14400F" 或 "W7-3465X"。
_RE_ALPHA_WORD = re.compile(r"[A-Z]{2,}", flags=re.UNICODE) # 匹配至少兩個連續大寫字母的單詞，這些通常是上下文詞，例如 "INTEL"、"CPU" 等。

_TITLE_PREFIXES = ( # 常見的CPU相關標題前綴，這些會在提取模型信息前被剝離，以避免干擾模型識別。
    "[組裝價]",
    "[組裝/升級]",
)

_BRAND_TOKENS = {"AMD", "INTEL"} # 在提取模型短語時，這些品牌相關的詞會被過濾掉，以避免干擾模型識別。

# 上下文詞列表，在評估模型匹配時會被提取出來用於提供額外的匹配信號，但這些詞本身不具有區分力，因此在提取模型短語時會被過濾掉。
_CONTEXT_STOPWORDS = {
    "AMD",
    "INTEL",
    "CPU",
    "PROCESSOR",
    "MPK",
    "BOX",
    "TRAY",
}


def _normalize(s: str) -> str: 
    # 對輸入字符串進行標準化處理：替換全形空格和不間斷空格為普通空格，將所有字符轉為大寫，壓縮多個空白字符為單一空格，並去除首尾空白。
    s = (s or "").replace("\u3000", " ").replace("\xa0", " ")
    s = s.upper()
    s = _RE_WS.sub(" ", s).strip()
    return s


def _strip_title_prefix(title: str) -> str: 
    # 從標題中剝離常見的CPU相關前綴，以避免干擾模型識別。這些前綴包括 "[組裝價]"、"[組裝/升級]" 等。
    s = (title or "").lstrip()
    for p in _TITLE_PREFIXES:
        if s.startswith(p):
            s = s[len(p) :].lstrip()
    return s


def _pick_listing_identifier(listing: ListingInput) -> tuple[str, str]: 
    # 從 ListingInput 中選擇用於模型識別的字符串，優先級為：extra.model_hint > sku_hint > title。返回選中的字符串和其來源字段名稱。
    extra_model_hint = listing.extra.get("model_hint")
    if isinstance(extra_model_hint, str) and extra_model_hint.strip():
        return extra_model_hint, "extra.model_hint"

    if (listing.sku_hint or "").strip():
        return listing.sku_hint, "sku_hint"

    return listing.title, "title"


def _build_model_phrase(identifier: str) -> str:
    # 從選定的識別字符串中構建型號片語。這裡會過濾掉品牌相關的詞（如 "INTEL"、"AMD"），以避免干擾模型識別，並返回剩餘部分的標準化結果。
    parts = [p for p in (identifier or "").split(" ") if p and p not in _BRAND_TOKENS]
    return _normalize(" ".join(parts))


def _build_page_text(signals: PageSignals) -> str: 
    # 從 PageSignals 中構建頁面文本，用於模型匹配。這裡會將 page_title、page_h1 和 text_hint 這三個字段的內容合併起來，並進行標準化處理。如果這三個字段都缺失或為空，則返回空字符串。
    parts: list[str] = []
    for s in (signals.page_title, signals.page_h1, signals.text_hint):
        if s:
            parts.append(s)
    return _normalize(" ".join(parts))


def _contains_phrase(page_text: str, phrase: str) -> bool:
    # 檢查頁面文本中是否包含指定的型號片語，邊界感知匹配以避免前綴衝突（例如 "I5-14400" 與 "I5-14400F"）。
    # 如果 page_text 或 phrase 為空，則直接返回 False。否則，使用正則表達式進行匹配，確保匹配的片語前後不是字母或數字，以避免部分匹配的誤判。
    if not page_text or not phrase:
        return False
    # Boundary-aware match to avoid prefix collisions (e.g., "I5-14400" vs "I5-14400F").
    rx = re.compile(rf"(?<![A-Z0-9]){re.escape(phrase)}(?![A-Z0-9])", flags=re.UNICODE)
    return rx.search(page_text) is not None


def _extract_model_tokens(s: str) -> list[str]:
    """
    從輸入字符串中提取模型標記，用於模型匹配。
    - 保留包含數字的標記，因為CPU型號通常包含數字。
    - 保留連字符分隔的標記（例如 W7-3465X、I5-14400F），因為這些通常是完整的型號標識。
    - 同時保留連字符分隔標記中的較長部分（例如從 I5-14400F 中提取 14400F），以提高匹配的正確性，但避免提取過短的部分（例如 I5），以減少弱匹配的誤判。
    """
    text = _normalize(s)
    out: set[str] = set()
    for m in _RE_TOKEN.finditer(text):
        tok = m.group(0).strip("-")
        if not tok or not any(ch.isdigit() for ch in tok):
            continue
        out.add(tok)
        if "-" in tok:
            for part in tok.split("-"):
                part = part.strip("-")
                if not part:
                    continue
                if any(ch.isdigit() for ch in part) and len(part) >= 3:
                    out.add(part)
    return sorted(out)


def _extract_context_words(s: str) -> set[str]:
    # 從輸入字符串中提取上下文詞，用於提供額外的匹配信號，但這些詞本身不具有區分力。
    # 這裡會過濾掉常見的CPU相關詞（如 "INTEL"、"CPU" 等），以避免干擾模型識別，並返回剩餘部分的標準化結果中的單詞集合。
    text = _normalize(s)
    words: set[str] = set()
    for m in _RE_ALPHA_WORD.finditer(text):
        w = m.group(0)
        if w in _CONTEXT_STOPWORDS:
            continue
        words.add(w)
    return words


def _is_strong_alnum_token(tok: str) -> bool:
    # Strong tokens are distinctive model ids like "14400F", "7800X3D", "W7-3465X".
    if not tok or len(tok) < 4:
        return False
    has_alpha = any("A" <= ch <= "Z" for ch in tok)
    has_digit = any("0" <= ch <= "9" for ch in tok)
    return has_alpha and has_digit


@dataclass(frozen=True)
class CpuStrategy: # CPU類別的鏈接一致性檢查策略，根據ListingInput中的型號信息與頁面文本中的型號信息進行匹配，並返回匹配決策。
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        identifier_raw, identifier_src = _pick_listing_identifier(listing)
        if identifier_src == "title":
            identifier_raw = _strip_title_prefix(identifier_raw)
        identifier_norm = _normalize(identifier_raw)

        model_phrase = _build_model_phrase(identifier_norm)
        listing_tokens = _extract_model_tokens(model_phrase)

        page_text = _build_page_text(signals)
        if not page_text:
            evidence: dict[str, Any] = {
                "listing_tokens": listing_tokens,
                "page_tokens": [],
                "matched_tokens": [],
                "notes": ["page_text is empty (page_title/page_h1/text_hint all missing or blank)"],
            }
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="PAGE_TEXT_EMPTY",
                evidence=evidence,
            )

        page_tokens = _extract_model_tokens(page_text)

        if not model_phrase:
            evidence = {
                "listing_tokens": listing_tokens,
                "page_tokens": page_tokens,
                "matched_tokens": [],
                "notes": ["model_phrase is empty after normalization (no usable model identifier)"],
            }
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="MODEL_EMPTY",
                evidence=evidence,
            )

        if _contains_phrase(page_text, model_phrase):
            evidence = {
                "listing_tokens": listing_tokens,
                "page_tokens": page_tokens,
                "matched_tokens": sorted(set(listing_tokens) & set(page_tokens)),
                "notes": ["model_phrase found in page_text"],
            }
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_PHRASE_FOUND",
                evidence=evidence,
            )

        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))
        matched_strong = [t for t in matched_tokens if _is_strong_alnum_token(t)]
        if matched_strong:
            evidence = {
                "listing_tokens": listing_tokens,
                "page_tokens": page_tokens,
                "matched_tokens": matched_tokens,
                "notes": [f"strong model token matched: {matched_strong[0]}"],
            }
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_TOKEN_MATCH",
                evidence=evidence,
            )

        matched_numeric_ids = [t for t in matched_tokens if t.isdigit() and len(t) >= 3]
        if matched_numeric_ids:
            # Numeric-only token matches are ambiguous; require at least one context signal.
            has_context_token = any(not t.isdigit() for t in matched_tokens)
            listing_ctx = _extract_context_words(model_phrase)
            page_ctx = _extract_context_words(page_text)
            matched_ctx = sorted(listing_ctx & page_ctx)
            if has_context_token or matched_ctx:
                if has_context_token and matched_ctx:
                    note = f"numeric token matched with context token(s) and word(s): {', '.join(matched_ctx[:3])}"
                elif has_context_token:
                    note = "numeric token matched with context token(s)"
                else:
                    note = f"numeric token matched with context word(s): {', '.join(matched_ctx[:3])}"
                evidence = {
                    "listing_tokens": listing_tokens,
                    "page_tokens": page_tokens,
                    "matched_tokens": matched_tokens,
                    "notes": [note],
                }
                return MatchDecision(
                    status="match",
                    score=None,
                    reason_code="MODEL_TOKEN_MATCH",
                    evidence=evidence,
                )

            evidence = {
                "listing_tokens": listing_tokens,
                "page_tokens": page_tokens,
                "matched_tokens": matched_tokens,
                "notes": ["only numeric tokens matched; no context word matched (weak match)"],
            }
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="NUMERIC_ONLY_WEAK_MATCH",
                evidence=evidence,
            )

        if not matched_tokens and any(_is_strong_alnum_token(t) for t in listing_tokens):
            evidence = {
                "listing_tokens": listing_tokens,
                "page_tokens": page_tokens,
                "matched_tokens": [],
                "notes": ["no model tokens matched, but listing has strong model token(s)"],
            }
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="MODEL_TOKEN_MISSING",
                evidence=evidence,
            )

        evidence = {
            "listing_tokens": listing_tokens,
            "page_tokens": page_tokens,
            "matched_tokens": matched_tokens,
            "notes": ["token overlap is inconclusive for CPU model"],
        }
        return MatchDecision(
            status="uncertain",
            score=None,
            reason_code="TOKEN_OVERLAP_INCONCLUSIVE",
            evidence=evidence,
        )
