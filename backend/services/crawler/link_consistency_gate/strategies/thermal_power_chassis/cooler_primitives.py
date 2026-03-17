from __future__ import annotations

import re

from ...types import ListingInput, PageSignals
from ..shared_primitives import compose_page_text, normalize_pattern_text, normalize_spaces

_RE_BRACKET_CHARS = re.compile(r"[\(\)（）【】\[\]\{\}<>]", flags=re.UNICODE)
_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~-]+", flags=re.UNICODE)
_RE_SEP_TOKEN = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)
_RE_M2 = re.compile(r"M[\s\.．]*2", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)
_RE_CJK = re.compile(r"[\u4e00-\u9fff]", flags=re.UNICODE)
_RE_ENGLISH_BRAND = re.compile(r"[A-Z0-9 ._/\-+&]+", flags=re.UNICODE)
_RE_SPEC_NUM = re.compile(r"^\d{2,4}(?:W|MM|CM)$", flags=re.UNICODE)
_SPEC_ALPHA = {"M2", "ARGB", "RGB", "PWM", "TDP"}


def normalize_cooler_phrase(text: str) -> str:
    return normalize_pattern_text(
        text,
        transform="upper",
        bracket_re=_RE_BRACKET_CHARS,
        separator_re=_RE_SEP_PHRASE,
        replacements_before=((_RE_M2, "M2"),),
    )


def normalize_cooler_token(text: str) -> str:
    return normalize_pattern_text(
        text,
        transform="upper",
        bracket_re=_RE_BRACKET_CHARS,
        separator_re=_RE_SEP_TOKEN,
        replacements_before=((_RE_M2, "M2"),),
    )


def build_cooler_page_text(signals: PageSignals) -> tuple[str, str]:
    page_text = compose_page_text(signals.page_title, signals.page_h1, signals.text_hint, normalize=normalize_spaces)
    return page_text, normalize_cooler_phrase(page_text)


def build_cooler_listing_tokens(text: str) -> list[str]:
    base = [match.group(0) for match in _RE_TOKEN.finditer(normalize_cooler_token(text))]
    out: set[str] = set(base)
    for i in range(len(base) - 1):
        token2 = f"{base[i]}-{base[i + 1]}"
        out.add(token2)
        if i + 2 < len(base):
            out.add(f"{base[i]}-{base[i + 1]}-{base[i + 2]}")
    return sorted(out)


def extract_cooler_model_phrase(listing: ListingInput) -> tuple[str, str]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint"
    if (listing.sku_hint or "").strip():
        return listing.sku_hint.strip(), "sku_hint"
    seg = extract_cooler_title_segment(listing.title)
    if not seg:
        return "", "title_segment"
    brand_hint = listing.extra.get("brand_hint")
    if isinstance(brand_hint, str) and brand_hint.strip():
        if _RE_CJK.search(seg) and is_cooler_english_brand(brand_hint):
            return seg, "title_segment(no_brand_for_cjk)"
        seg_norm = normalize_cooler_phrase(seg)
        brand_norm = normalize_cooler_phrase(brand_hint)
        if brand_norm and brand_norm in seg_norm:
            return seg, "title_segment(brand_already_in_segment)"
        return f"{brand_hint.strip()} {seg}", "title_segment+brand_hint"
    return seg, "title_segment"


def extract_cooler_title_segment(title: str) -> str:
    line = (title or "").splitlines()[0].strip() if title else ""
    if not line:
        return ""
    return re.split(r"[／/]", line, maxsplit=1)[0].strip()


def is_cooler_english_brand(text: str) -> bool:
    normalized = normalize_spaces(text).upper()
    if not normalized or _RE_CJK.search(normalized):
        return False
    if _RE_ENGLISH_BRAND.fullmatch(normalized) is None:
        return False
    return any("A" <= ch <= "Z" for ch in normalized)


def is_cooler_strong_identity_token(token: str) -> bool:
    raw = (token or "").replace("-", "")
    if not raw or len(raw) < 4 or raw in _SPEC_ALPHA or _RE_SPEC_NUM.fullmatch(raw) is not None:
        return False
    has_alpha = any("A" <= ch <= "Z" for ch in raw)
    has_digit = any("0" <= ch <= "9" for ch in raw)
    return has_alpha and has_digit


def extract_cooler_strong_tokens(tokens: list[str]) -> set[str]:
    return {token for token in tokens if is_cooler_strong_identity_token(token)}


def extract_cooler_matched_tokens(listing_tokens: list[str], page_tokens: list[str]) -> list[str]:
    return sorted(set(listing_tokens) & set(page_tokens))
