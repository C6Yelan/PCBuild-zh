# backend/services/crawler/link_consistency_gate/strategies/compute/mb_primitives.py
from __future__ import annotations

import re
from typing import Any

from ...types import ListingInput, PageSignals

_RE_WS = re.compile(r"\s+", flags=re.UNICODE)
_RE_BRACKET_SQ = re.compile(r"【[^】]*】", flags=re.UNICODE)
_RE_BRACKET_PAREN = re.compile(r"\([^)]*\)", flags=re.UNICODE)
_RE_BRACKET_PAREN_FULL = re.compile(r"（[^）]*）", flags=re.UNICODE)
_RE_SEP = re.compile(r"[\\/._-]+", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[a-z0-9]+", flags=re.UNICODE)
_TITLE_BRAND_PREFIXES = ("ASUS", "華碩", "MSI", "微星", "GIGABYTE", "技嘉", "ASROCK", "華擎")


def build_mb_evidence(
    listing_tokens: list[str],
    page_tokens: list[str],
    matched_tokens: list[str],
    notes: list[str],
) -> dict[str, Any]:
    return {
        "listing_tokens": listing_tokens,
        "page_tokens": page_tokens,
        "matched_tokens": matched_tokens,
        "notes": notes,
    }


def build_mb_page_text(signals: PageSignals) -> tuple[str, str]:
    parts = [part for part in (signals.page_title, signals.page_h1, signals.text_hint) if part]
    page_text = normalize_mb_text(" ".join(parts))
    return page_text, page_text


def build_mb_page_text_text(text: str) -> str:
    return normalize_mb_text(text)


def extract_mb_model_phrase(listing: ListingInput) -> tuple[str, str]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint, "extra.model_hint"
    if (listing.sku_hint or "").strip():
        return listing.sku_hint, "sku_hint"
    return strip_mb_title_brand_prefix(listing.title), "title"


def normalize_mb_text(text: str) -> str:
    normalized = (text or "").replace("\u3000", " ").replace("\xa0", " ").lower()
    normalized = _RE_BRACKET_SQ.sub(" ", normalized)
    normalized = _RE_BRACKET_PAREN.sub(" ", normalized)
    normalized = _RE_BRACKET_PAREN_FULL.sub(" ", normalized)
    normalized = _RE_SEP.sub(" ", normalized)
    return _RE_WS.sub(" ", normalized).strip()


def strip_mb_title_brand_prefix(title: str) -> str:
    text = (title or "").strip()
    if not text:
        return text
    lowered = text.lower()
    for prefix in _TITLE_BRAND_PREFIXES:
        if lowered.startswith(prefix.lower()):
            return text[len(prefix) :].lstrip(" :-_/|")
    return text


def tokenize_mb_text(text: str) -> list[str]:
    base = [token for token in _RE_TOKEN.findall(text or "") if token]
    out: set[str] = set(base)
    for i in range(len(base) - 1):
        a = base[i]
        b = base[i + 1]
        if is_mb_strong_token(a) and b:
            out.add(f"{a}-{b}")
            if i + 2 < len(base):
                c = base[i + 2]
                if c:
                    out.add(f"{a}-{b}-{c}")
    return sorted(out)


def is_mb_strong_token(token: str) -> bool:
    if not token or len(token) < 4:
        return False
    return any("a" <= ch <= "z" for ch in token) and any("0" <= ch <= "9" for ch in token)


def extract_mb_strong_tokens(tokens: list[str]) -> set[str]:
    strong = {token for token in tokens if is_mb_strong_token(token)}
    compound = {token for token in strong if "-" in token}
    simple = {token for token in strong if "-" not in token}
    filtered_simple = {token for token in simple if not any(compound_token.startswith(f"{token}-") for compound_token in compound)}
    return filtered_simple | compound


def extract_mb_matched_tokens(listing_tokens: list[str], page_tokens: list[str]) -> list[str]:
    return sorted(set(listing_tokens) & set(page_tokens))
