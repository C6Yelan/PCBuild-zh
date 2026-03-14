from __future__ import annotations

import re
from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from ..shared_primitives import build_evidence, compose_page_text, normalize_pattern_text, normalize_spaces


_RE_M2 = re.compile(r"M[\s\.．]*2", flags=re.UNICODE)
_RE_ARGB = re.compile(r"A[\s\.\-_/]*RGB", flags=re.UNICODE)
_RE_RAD_MM = re.compile(r"(?<![0-9A-Z])(240|280|360|420)\s*MM(?![0-9A-Z])", flags=re.UNICODE)
_RE_BRACKET_SYMBOLS = re.compile(r"[\(\)（）【】\[\]\{\}<>]", flags=re.UNICODE)
_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~-]+", flags=re.UNICODE)
_RE_SEP_TOKEN = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)  # keep '-'
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


def _normalize_spaces(s: str) -> str:
    return normalize_spaces(s)


def _normalize_phrase(s: str) -> str:
    return normalize_pattern_text(
        s,
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


def _normalize_token(s: str) -> str:
    return normalize_pattern_text(
        s,
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


def _title_head(title: str) -> str:
    line = (title or "").splitlines()[0].strip() if title else ""
    if not line:
        return ""
    line = _RE_BRACKET_CONTENT.sub(" ", line)
    line = _normalize_spaces(line)
    if not line:
        return ""
    return re.split(r"[／/]", line, maxsplit=1)[0].strip()


def _is_ascii_brand(s: str) -> bool:
    text = _normalize_spaces(s).upper()
    if not text:
        return False
    if _RE_CJK.search(text):
        return False
    if _RE_ASCII_BRAND.fullmatch(text) is None:
        return False
    return any("A" <= ch <= "Z" for ch in text)


def _pick_model_phrase(listing: ListingInput) -> tuple[str, str]:
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
        raw = _title_head(listing.title)
        source = "title_head"

    brand_hint = listing.extra.get("brand_hint")
    if isinstance(brand_hint, str) and brand_hint.strip():
        brand = brand_hint.strip()
        phrase_norm = _normalize_phrase(raw)
        brand_norm = _normalize_phrase(brand)

        if not phrase_norm:
            return raw, f"{source}(empty_base)"

        if _RE_CJK.search(raw) and _is_ascii_brand(brand):
            return raw, f"{source}(no_brand_for_cjk)"

        if not _RE_CJK.search(raw):
            if brand_norm and brand_norm in phrase_norm:
                return raw, f"{source}(brand_already_present)"
            return f"{brand} {raw}", f"{source}+brand_hint"

    return raw, source


def _tokenize(text: str) -> list[str]:
    norm = _normalize_token(text)
    base = [m.group(0) for m in _RE_TOKEN.finditer(norm)]
    out: set[str] = set(base)

    for i in range(len(base) - 1):
        out.add(f"{base[i]}-{base[i + 1]}")
        if i + 2 < len(base):
            out.add(f"{base[i]}-{base[i + 1]}-{base[i + 2]}")

    for m in _RE_RAD_SIZE.finditer(norm):
        out.add(m.group(1))

    for t in _RE_CJK_TOKEN.findall(norm):
        out.add(t)

    return sorted(out)


def _is_identity_token(tok: str) -> bool:
    raw = (tok or "").replace("-", "")
    if len(raw) < 4:
        return False
    if raw in _SPEC_ALPHA:
        return False
    if _RE_SPEC_NUM.fullmatch(raw) is not None:
        return False
    has_alpha = any("A" <= ch <= "Z" for ch in raw)
    has_digit = any("0" <= ch <= "9" for ch in raw)
    return has_alpha and has_digit


def _identity_key(tok: str) -> str:
    return (tok or "").replace("-", "")


@dataclass(frozen=True)
class LiquidCoolingStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_phrase_raw, model_source = _pick_model_phrase(listing)
        model_phrase_norm = _normalize_phrase(model_phrase_raw)

        page_text = compose_page_text(
            signals.page_title,
            signals.page_h1,
            signals.text_hint,
            normalize=normalize_spaces,
        )
        page_text_norm = _normalize_phrase(page_text)

        listing_tokens = _tokenize(model_phrase_raw)

        if not page_text_norm:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=[],
                matched_tokens=[],
                notes=[f"model_source={model_source}", "page_empty"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="PAGE_TEXT_EMPTY",
                evidence=evidence,
            )

        page_tokens = _tokenize(page_text)
        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))

        if model_phrase_norm and model_phrase_norm in page_text_norm:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "phrase_hit"],
            )
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_PHRASE_FOUND",
                evidence=evidence,
            )

        listing_identity = {t for t in listing_tokens if _is_identity_token(t)}
        page_identity = {t for t in page_tokens if _is_identity_token(t)}

        listing_identity_keys = {_identity_key(t) for t in listing_identity}
        page_identity_keys = {_identity_key(t) for t in page_identity}
        matched_identity_keys = sorted(listing_identity_keys & page_identity_keys)

        if matched_identity_keys:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "token_match"],
            )
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_TOKEN_MATCH",
                evidence=evidence,
            )

        if not listing_identity_keys:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "identity_missing"],
            )
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="IDENTITY_TOKEN_MISSING",
                evidence=evidence,
            )

        evidence = build_evidence(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=[f"model_source={model_source}", "overlap_inconclusive"],
        )
        return MatchDecision(
            status="uncertain",
            score=None,
            reason_code="TOKEN_OVERLAP_INCONCLUSIVE",
            evidence=evidence,
        )
