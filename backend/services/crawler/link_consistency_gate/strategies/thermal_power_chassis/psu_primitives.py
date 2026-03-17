# backend/services/crawler/link_consistency_gate/strategies/thermal_power_chassis/psu_primitives.py
from __future__ import annotations

import re

from ...types import ListingInput, PageSignals
from ..shared_primitives import compose_page_text, normalize_spaces, normalize_upper_pattern_text, tokenize_model_tokens

_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~\-]+", flags=re.UNICODE)
_RE_SEP_TOKEN = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)  # keep '-'
_RE_BRACKET_SYMBOLS = re.compile(r"[\[\]【】\(\)（）\{\}<>]", flags=re.UNICODE)
_RE_CLEAN_COMPACT = re.compile(r"[^A-Z0-9\u4e00-\u9fff]+", flags=re.UNICODE)
_RE_NON_ALNUM = re.compile(r"[^A-Z0-9]+", flags=re.UNICODE)
_RE_TITLE_TRUNC = re.compile(r"[\(（【\[]", flags=re.UNICODE)
_RE_TITLE_SLASH = re.compile(r"[／/]", flags=re.UNICODE)
_RE_ASCII_START = re.compile(r"[A-Z0-9]", flags=re.UNICODE)
_RE_HAS_CJK = re.compile(r"[\u4e00-\u9fff]", flags=re.UNICODE)
_RE_WEAK_POWER = re.compile(r"^[0-9]{2,4}W$", flags=re.UNICODE)

_STOPWORDS = {
    "ATX",
    "SFX",
    "SFXL",
    "TFX",
    "EPS",
    "PCIE",
    "PCI",
    "GEN",
    "GEN5",
    "MODULAR",
    "FULL",
    "SEMI",
    "NON",
    "FAN",
    "SILENT",
    "BLACK",
    "WHITE",
    "GOLD",
    "BRONZE",
    "PLATINUM",
    "TITANIUM",
    "POWER",
    "SUPPLY",
    "PSU",
}


def normalize_psu_phrase(text: str) -> str:
    return normalize_upper_pattern_text(
        text,
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_PHRASE,
    )


def tokenize_psu_tokens(text: str) -> list[str]:
    return tokenize_model_tokens(text, normalize=normalize_psu_token_text)


def compact_psu_phrase(text: str) -> str:
    return _RE_CLEAN_COMPACT.sub("", normalize_psu_phrase(text))


def build_psu_page_text(signals: PageSignals) -> str:
    return compose_page_text(
        signals.text_hint,
        signals.page_title,
        signals.page_h1,
        normalize=normalize_spaces,
    )


def build_psu_model_candidates(raw: str) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        normalized = normalize_psu_phrase(candidate)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        ordered.append(normalized)

    add(raw)
    add(prefer_psu_alnum_subphrase(raw))
    return ordered


def extract_psu_identity_tokens(tokens: list[str]) -> set[str]:
    return {token for token in tokens if is_psu_identity_token(token)}


def is_psu_weak_token(token: str) -> bool:
    cleaned = (token or "").strip("-")
    if _RE_WEAK_POWER.fullmatch(cleaned) is not None:
        return True
    return cleaned in {"80PLUS", "BRONZE", "GOLD", "PLATINUM", "TITANIUM"}


def pick_psu_model_phrase(listing: ListingInput) -> tuple[str, str, bool]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint", False

    sku_hint = (listing.sku_hint or "").strip()
    if sku_hint:
        if not is_psu_weak_model_phrase(sku_hint):
            return sku_hint, "sku_hint", False
        title_head = psu_title_head(listing.title)
        title_ascii_tail = psu_title_ascii_tail(title_head)
        if title_ascii_tail:
            return title_ascii_tail, "title_ascii_tail", True
        if title_head:
            return title_head, "title_head", True
        return sku_hint, "sku_hint", True

    return psu_title_head(listing.title), "title_first_line", False


def normalize_psu_token_text(text: str) -> str:
    return normalize_upper_pattern_text(
        text,
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_TOKEN,
    )


def psu_title_head(title: str) -> str:
    line = (title or "").splitlines()[0].strip() if title else ""
    if not line:
        return ""
    line = _RE_TITLE_SLASH.split(line, maxsplit=1)[0].strip()
    match = _RE_TITLE_TRUNC.search(line)
    if match is not None:
        line = line[: match.start()]
    return normalize_spaces(line)


def is_psu_weak_model_phrase(text: str) -> bool:
    canonical = _RE_NON_ALNUM.sub("", normalize_spaces(text).upper())
    if not canonical:
        return True
    return _RE_WEAK_POWER.fullmatch(canonical) is not None


def psu_title_ascii_tail(title_head: str) -> str:
    segment = normalize_spaces(title_head)
    if not segment or _RE_HAS_CJK.search(segment) is None:
        return ""

    match = _RE_ASCII_START.search(segment.upper())
    if match is None:
        return ""

    idx = match.start()
    prefix = segment[:idx]
    if idx > 0 and _RE_HAS_CJK.search(prefix) is not None and _RE_ASCII_START.search(prefix.upper()) is None:
        return segment[idx:].strip()
    return ""


def prefer_psu_alnum_subphrase(raw: str) -> str:
    text = normalize_spaces(raw)
    if not text:
        return ""

    match = _RE_ASCII_START.search(text.upper())
    if match is None:
        return text

    idx = match.start()
    prefix = text[:idx]
    if idx > 0 and _RE_HAS_CJK.search(prefix) is not None and _RE_ASCII_START.search(prefix.upper()) is None:
        tail = text[idx:].strip()
        if tail:
            return tail
    return text


def is_psu_identity_token(token: str) -> bool:
    cleaned = (token or "").strip("-")
    if not cleaned or cleaned in _STOPWORDS:
        return False

    has_alpha = any("A" <= ch <= "Z" for ch in cleaned)
    has_digit = any("0" <= ch <= "9" for ch in cleaned)
    if has_digit:
        return True
    return has_alpha and len(cleaned) >= 5
