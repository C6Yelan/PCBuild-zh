from __future__ import annotations

import re

from ...types import ListingInput, PageSignals
from ..shared_primitives import compose_page_text, normalize_spaces, normalize_upper_pattern_text, tokenize_model_tokens

_RE_BRACKET_SYMBOLS = re.compile(r"[\[\]【】\(\)（）\{\}<>]", flags=re.UNICODE)
_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~\-]+", flags=re.UNICODE)
_RE_SEP_TOKEN = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)  # keep '-'
_RE_COMPACT_KEEP = re.compile(r"[^A-Z0-9\u4e00-\u9fff]+", flags=re.UNICODE)

_COLOR_TOKENS = {
    "黑",
    "白",
    "灰",
    "銀",
    "紅",
    "藍",
    "綠",
    "粉",
    "金",
    "棕",
    "黑色",
    "白色",
    "灰色",
    "銀色",
    "紅色",
    "藍色",
    "綠色",
    "粉色",
    "金色",
    "棕色",
    "BLACK",
    "WHITE",
    "GRAY",
    "GREY",
    "SILVER",
    "RED",
    "BLUE",
    "GREEN",
    "PINK",
    "GOLD",
    "BROWN",
}

_IDENTITY_STOPWORDS = {
    "ATX",
    "MATX",
    "MICROATX",
    "ITX",
    "MINIITX",
    "EATX",
    "RGB",
    "ARGB",
    "USB",
    "TYPE",
    "TYPEC",
    "PCIE",
    "CASE",
    "CHASSIS",
    "TG",
    "GLASS",
    "MESH",
    "WINDOW",
    "FAN",
    "NOFAN",
    "BLACK",
    "WHITE",
    "GRAY",
    "GREY",
    "SILVER",
    "RED",
    "BLUE",
    "GREEN",
    "PINK",
    "GOLD",
    "BROWN",
}

_BRACKET_OPENERS = "([（【<[{"


def normalize_case_phrase(text: str) -> str:
    return normalize_upper_pattern_text(
        text,
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_PHRASE,
    )


def tokenize_case_tokens(text: str) -> list[str]:
    return tokenize_model_tokens(text, normalize=normalize_case_token_text)


def compact_case_phrase(text: str) -> str:
    return _RE_COMPACT_KEEP.sub("", normalize_case_phrase(text))


def build_case_page_text(signals: PageSignals) -> str:
    return compose_page_text(
        signals.text_hint,
        signals.page_title,
        signals.page_h1,
        normalize=normalize_spaces,
    )


def build_case_model_candidates(raw: str) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        normalized = normalize_case_phrase(candidate)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        ordered.append(normalized)

    add(raw)
    add(strip_case_bracket_tail(raw))

    for candidate in list(ordered):
        add(strip_case_trailing_color(candidate))

    return ordered


def extract_case_identity_tokens(tokens: list[str]) -> set[str]:
    return {token for token in tokens if is_case_identity_token(token)}


def pick_case_model_phrase(listing: ListingInput) -> tuple[str, str]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint"

    if (listing.sku_hint or "").strip():
        return listing.sku_hint.strip(), "sku_hint"

    return case_title_first_line(listing.title), "title_first_line"


def normalize_case_token_text(text: str) -> str:
    return normalize_upper_pattern_text(
        text,
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_TOKEN,
    )


def case_title_first_line(title: str) -> str:
    return (title or "").splitlines()[0].strip() if title else ""


def strip_case_bracket_tail(text: str) -> str:
    normalized = (text or "").strip()
    if not normalized:
        return ""

    first_idx = -1
    for opener in _BRACKET_OPENERS:
        idx = normalized.find(opener)
        if idx != -1 and (first_idx == -1 or idx < first_idx):
            first_idx = idx

    if first_idx == -1:
        return normalized
    return normalized[:first_idx].strip()


def strip_case_trailing_color(text: str) -> str:
    normalized = normalize_case_phrase(text)
    if not normalized:
        return ""

    parts = normalized.split(" ")
    if parts and parts[-1] in _COLOR_TOKENS:
        return " ".join(parts[:-1]).strip()
    return normalized


def is_case_identity_token(token: str) -> bool:
    cleaned = (token or "").strip("-")
    if not cleaned or cleaned in _IDENTITY_STOPWORDS:
        return False
    if cleaned.isdigit():
        return False
    return any(ch.isdigit() for ch in cleaned)
