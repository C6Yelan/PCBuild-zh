# backend/services/crawler/link_consistency_gate/strategies/thermal_power_chassis/liquid_cooling_primitives.py
from __future__ import annotations

import re

from ...types import ListingInput, PageSignals
from ..shared_primitives import compose_page_text, normalize_pattern_text, normalize_spaces

_RE_M2 = re.compile(r"M[\s\.．]*2", flags=re.UNICODE)
_RE_ARGB = re.compile(r"A[\s\.\-_/]*RGB", flags=re.UNICODE)
_RE_RAD_MM = re.compile(r"(?<![0-9A-Z])(240|280|360|420)\s*MM(?![0-9A-Z])", flags=re.UNICODE)
_RE_BRACKET_SYMBOLS = re.compile(r"[\(\)（）【】\[\]\{\}<>]", flags=re.UNICODE)
_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~-]+", flags=re.UNICODE)
_RE_SEP_TOKEN = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)
_RE_CJK = re.compile(r"[\u4e00-\u9fff]", flags=re.UNICODE)
_RE_CJK_TOKEN = re.compile(r"[\u4e00-\u9fff]{2,}", flags=re.UNICODE)
_RE_BRACKET_CONTENT = re.compile(r"(【[^】]*】|\([^)]*\)|（[^）]*）|\[[^\]]*\]|\{[^}]*\})", flags=re.UNICODE)
_RE_ALNUM_TO_CJK = re.compile(r"(?<=[A-Z0-9])(?=[\u4e00-\u9fff])", flags=re.UNICODE)
_RE_CJK_TO_ALNUM = re.compile(r"(?<=[\u4e00-\u9fff])(?=[A-Z0-9])", flags=re.UNICODE)
_RE_ASCII_BRAND = re.compile(r"[A-Z0-9 ._/\-+&]+", flags=re.UNICODE)
_RE_SPEC_NUM = re.compile(r"^\d{2,4}(?:W|MM|CM)$", flags=re.UNICODE)
_RE_RAD_SIZE = re.compile(r"(?<!\d)(240|280|360|420)(?!\d)", flags=re.UNICODE)

_SPEC_ALPHA = {"M2", "ARGB", "RGB", "PWM", "TDP"}


def normalize_liquid_cooling_phrase(text: str) -> str:
    return normalize_pattern_text(
        text,
        transform="upper",
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_PHRASE,
        replacements_before=(
            (_RE_M2, "M2"),
            (_RE_ARGB, "ARGB"),
            (_RE_RAD_MM, r"\1"),
        ),
        replacements_after=(
            (_RE_ALNUM_TO_CJK, " "),
            (_RE_CJK_TO_ALNUM, " "),
        ),
    )


def normalize_liquid_cooling_token_text(text: str) -> str:
    return normalize_pattern_text(
        text,
        transform="upper",
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_TOKEN,
        replacements_before=(
            (_RE_M2, "M2"),
            (_RE_ARGB, "ARGB"),
            (_RE_RAD_MM, r"\1"),
        ),
        replacements_after=(
            (_RE_ALNUM_TO_CJK, " "),
            (_RE_CJK_TO_ALNUM, " "),
        ),
    )


def build_liquid_cooling_title_head(title: str) -> str:
    line = (title or "").splitlines()[0].strip() if title else ""
    if not line:
        return ""
    line = _RE_BRACKET_CONTENT.sub(" ", line)
    line = normalize_spaces(line)
    if not line:
        return ""
    return re.split(r"[／/]", line, maxsplit=1)[0].strip()


def is_liquid_cooling_ascii_brand(text: str) -> bool:
    normalized = normalize_spaces(text).upper()
    if not normalized:
        return False
    if _RE_CJK.search(normalized):
        return False
    if _RE_ASCII_BRAND.fullmatch(normalized) is None:
        return False
    return any("A" <= ch <= "Z" for ch in normalized)


def pick_liquid_cooling_model_phrase(listing: ListingInput) -> tuple[str, str]:
    raw = ""
    source = "title_head"

    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        raw = model_hint.strip()
        source = "extra.model_hint"
    elif (listing.sku_hint or "").strip():
        raw = listing.sku_hint.strip()
        source = "sku_hint"
    else:
        raw = build_liquid_cooling_title_head(listing.title)
        source = "title_head"

    brand_hint = listing.extra.get("brand_hint")
    if isinstance(brand_hint, str) and brand_hint.strip():
        brand = brand_hint.strip()
        phrase_norm = normalize_liquid_cooling_phrase(raw)
        brand_norm = normalize_liquid_cooling_phrase(brand)

        if not phrase_norm:
            return raw, f"{source}(empty_base)"

        if _RE_CJK.search(raw) and is_liquid_cooling_ascii_brand(brand):
            return raw, f"{source}(no_brand_for_cjk)"

        if not _RE_CJK.search(raw):
            if brand_norm and brand_norm in phrase_norm:
                return raw, f"{source}(brand_already_present)"
            return f"{brand} {raw}", f"{source}+brand_hint"

    return raw, source


def build_liquid_cooling_tokens(text: str) -> list[str]:
    normalized = normalize_liquid_cooling_token_text(text)
    base_tokens = [match.group(0) for match in _RE_TOKEN.finditer(normalized)]
    tokens: set[str] = set(base_tokens)

    for idx in range(len(base_tokens) - 1):
        tokens.add(f"{base_tokens[idx]}-{base_tokens[idx + 1]}")
        if idx + 2 < len(base_tokens):
            tokens.add(f"{base_tokens[idx]}-{base_tokens[idx + 1]}-{base_tokens[idx + 2]}")

    for match in _RE_RAD_SIZE.finditer(normalized):
        tokens.add(match.group(1))

    for token in _RE_CJK_TOKEN.findall(normalized):
        tokens.add(token)

    return sorted(tokens)


def is_liquid_cooling_identity_token(token: str) -> bool:
    raw = (token or "").replace("-", "")
    if len(raw) < 4:
        return False
    if raw in _SPEC_ALPHA:
        return False
    if _RE_SPEC_NUM.fullmatch(raw) is not None:
        return False
    has_alpha = any("A" <= ch <= "Z" for ch in raw)
    has_digit = any("0" <= ch <= "9" for ch in raw)
    return has_alpha and has_digit


def build_liquid_cooling_identity_keys(tokens: list[str]) -> set[str]:
    return {
        token.replace("-", "")
        for token in tokens
        if is_liquid_cooling_identity_token(token)
    }


def build_liquid_cooling_page_text(signals: PageSignals) -> str:
    return compose_page_text(
        signals.page_title,
        signals.page_h1,
        signals.text_hint,
        normalize=normalize_spaces,
    )
