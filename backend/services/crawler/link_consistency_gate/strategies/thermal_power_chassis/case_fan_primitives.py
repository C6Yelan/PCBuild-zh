# backend/services/crawler/link_consistency_gate/strategies/thermal_power_chassis/case_fan_primitives.py
from __future__ import annotations

import re

from ...types import ListingInput, PageSignals
from ..shared_primitives import compose_page_text, normalize_pattern_text, normalize_spaces, tokenize_model_tokens

_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~\-]+", flags=re.UNICODE)
_RE_SEP_TOKEN = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)
_RE_BRACKET_SYMBOLS = re.compile(r"[\[\]【】\(\)（）\{\}<>]", flags=re.UNICODE)
_RE_CLEAN_COMPACT = re.compile(r"[^A-Z0-9\u4e00-\u9fff]+", flags=re.UNICODE)
_RE_TITLE_TRUNC = re.compile(r"[\(（【\[]", flags=re.UNICODE)
_RE_TITLE_SLASH = re.compile(r"[／/]", flags=re.UNICODE)
_RE_ASCII_START = re.compile(r"[A-Z0-9]", flags=re.UNICODE)
_RE_HAS_CJK = re.compile(r"[\u4e00-\u9fff]", flags=re.UNICODE)
_RE_SIZE_TOKEN = re.compile(r"^(?:\d{2,4}|\d{1,3}(?:MM|CM)|\d{2,4}RPM)$", flags=re.UNICODE)

_IDENTITY_STOPWORDS = {
    "ARGB",
    "RGB",
    "LED",
    "PWM",
    "RPM",
    "MM",
    "CM",
    "CASE",
    "FAN",
    "USB",
    "TYPE",
    "TYPEC",
    "TYPE-C",
    "PACK",
    "PCS",
    "BLACK",
    "WHITE",
    "SILENT",
}


def normalize_case_fan_phrase(text: str) -> str:
    return normalize_pattern_text(
        text,
        transform="upper",
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_PHRASE,
    )


def normalize_case_fan_token_text(text: str) -> str:
    return normalize_pattern_text(
        text,
        transform="upper",
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_TOKEN,
    )


def compact_case_fan_phrase(text: str) -> str:
    return _RE_CLEAN_COMPACT.sub("", normalize_case_fan_phrase(text))


def build_case_fan_title_head(title: str) -> str:
    line = (title or "").splitlines()[0].strip() if title else ""
    if not line:
        return ""
    line = _RE_TITLE_SLASH.split(line, maxsplit=1)[0].strip()
    match = _RE_TITLE_TRUNC.search(line)
    if match is not None:
        line = line[: match.start()]
    return normalize_spaces(line)


def pick_case_fan_model_phrase(listing: ListingInput) -> tuple[str, str]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint"

    if (listing.sku_hint or "").strip():
        return listing.sku_hint.strip(), "sku_hint"

    return build_case_fan_title_head(listing.title), "title_head"


def prefer_case_fan_alnum_subphrase(text: str) -> str:
    normalized = normalize_spaces(text)
    if not normalized:
        return ""

    match = _RE_ASCII_START.search(normalized.upper())
    if match is None:
        return normalized

    idx = match.start()
    prefix = normalized[:idx]
    if idx > 0 and _RE_HAS_CJK.search(prefix) is not None and _RE_ASCII_START.search(prefix.upper()) is None:
        tail = normalized[idx:].strip()
        if tail:
            return tail
    return normalized


def build_case_fan_model_candidates(text: str) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        normalized = normalize_case_fan_phrase(candidate)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        ordered.append(normalized)

    add(text)
    add(prefer_case_fan_alnum_subphrase(text))
    return ordered


def build_case_fan_page_text(signals: PageSignals) -> str:
    return compose_page_text(
        signals.text_hint,
        signals.page_title,
        signals.page_h1,
        normalize=normalize_spaces,
    )


def build_case_fan_tokens(text: str) -> list[str]:
    return tokenize_model_tokens(text, normalize=normalize_case_fan_token_text, join_hyphen_parts=True)


def is_case_fan_size_token(token: str) -> bool:
    normalized = (token or "").replace("-", "")
    if not normalized:
        return True
    return _RE_SIZE_TOKEN.fullmatch(normalized) is not None


def is_case_fan_identity_token(token: str) -> bool:
    normalized = (token or "").strip("-")
    if not normalized:
        return False

    base = normalized.replace("-", "")
    if not base:
        return False
    if normalized in _IDENTITY_STOPWORDS or base in _IDENTITY_STOPWORDS:
        return False
    if is_case_fan_size_token(base):
        return False

    has_alpha = any("A" <= ch <= "Z" for ch in base)
    has_digit = any("0" <= ch <= "9" for ch in base)
    if has_alpha and has_digit:
        return True
    return has_alpha and len(base) >= 4


def extract_case_fan_identity_tokens(tokens: list[str]) -> set[str]:
    return {token for token in tokens if is_case_fan_identity_token(token)}
