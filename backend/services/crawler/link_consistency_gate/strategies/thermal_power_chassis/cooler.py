from __future__ import annotations

import re
from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from ..shared_primitives import build_evidence, compose_page_text, normalize_pattern_text, normalize_spaces


_RE_BRACKET_CHARS = re.compile(r"[\(\)（）【】\[\]\{\}<>]", flags=re.UNICODE)
_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~-]+", flags=re.UNICODE)
_RE_SEP_TOKEN = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)  # keep '-'
_RE_M2 = re.compile(r"M[\s\.．]*2", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)
_RE_CJK = re.compile(r"[\u4e00-\u9fff]", flags=re.UNICODE)
_RE_ENGLISH_BRAND = re.compile(r"[A-Z0-9 ._/\-+&]+", flags=re.UNICODE)
_RE_SPEC_NUM = re.compile(r"^\d{2,4}(?:W|MM|CM)$", flags=re.UNICODE)

_SPEC_ALPHA = {"M2", "ARGB", "RGB", "PWM", "TDP"}


def _normalize_spaces(s: str) -> str:
    return normalize_spaces(s)


def _normalize_phrase(s: str) -> str:
    return normalize_pattern_text(
        s,
        transform="upper",
        bracket_re=_RE_BRACKET_CHARS,
        separator_re=_RE_SEP_PHRASE,
        replacements_before=((_RE_M2, "M2"),),
    )


def _normalize_token(s: str) -> str:
    return normalize_pattern_text(
        s,
        transform="upper",
        bracket_re=_RE_BRACKET_CHARS,
        separator_re=_RE_SEP_TOKEN,
        replacements_before=((_RE_M2, "M2"),),
    )


def _is_english_brand(s: str) -> bool:
    text = _normalize_spaces(s).upper()
    if not text:
        return False
    if _RE_CJK.search(text):
        return False
    if _RE_ENGLISH_BRAND.fullmatch(text) is None:
        return False
    return any("A" <= ch <= "Z" for ch in text)


def _title_segment(title: str) -> str:
    line = (title or "").splitlines()[0].strip() if title else ""
    if not line:
        return ""
    seg = re.split(r"[／/]", line, maxsplit=1)[0]
    return seg.strip()


def _pick_model_phrase(listing: ListingInput) -> tuple[str, str]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint"

    if (listing.sku_hint or "").strip():
        return listing.sku_hint.strip(), "sku_hint"

    seg = _title_segment(listing.title)
    if not seg:
        return "", "title_segment"

    brand_hint = listing.extra.get("brand_hint")
    if isinstance(brand_hint, str) and brand_hint.strip():
        if _RE_CJK.search(seg) and _is_english_brand(brand_hint):
            return seg, "title_segment(no_brand_for_cjk)"

        seg_norm = _normalize_phrase(seg)
        brand_norm = _normalize_phrase(brand_hint)
        if brand_norm and brand_norm in seg_norm:
            return seg, "title_segment(brand_already_in_segment)"
        return f"{brand_hint.strip()} {seg}", "title_segment+brand_hint"

    return seg, "title_segment"


def _tokenize(text: str) -> list[str]:
    base = [m.group(0) for m in _RE_TOKEN.finditer(_normalize_token(text))]
    out: set[str] = set(base)

    for i in range(len(base) - 1):
        t2 = f"{base[i]}-{base[i + 1]}"
        out.add(t2)
        if i + 2 < len(base):
            t3 = f"{base[i]}-{base[i + 1]}-{base[i + 2]}"
            out.add(t3)

    return sorted(out)


def _is_strong_identity_token(tok: str) -> bool:
    raw = (tok or "").replace("-", "")
    if not raw or len(raw) < 4:
        return False
    if raw in _SPEC_ALPHA:
        return False
    if _RE_SPEC_NUM.fullmatch(raw) is not None:
        return False

    has_alpha = any("A" <= ch <= "Z" for ch in raw)
    has_digit = any("0" <= ch <= "9" for ch in raw)
    return has_alpha and has_digit


@dataclass(frozen=True)
class CoolerStrategy:
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
                notes=[f"model_source={model_source}", "page_text is empty"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="PAGE_TEXT_EMPTY",
                evidence=evidence,
            )

        page_tokens = _tokenize(page_text)
        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))

        if not model_phrase_norm:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "model_phrase is empty after normalization"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="MODEL_EMPTY",
                evidence=evidence,
            )

        if model_phrase_norm in page_text_norm:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "phrase match by normalized substring"],
            )
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_PHRASE_FOUND",
                evidence=evidence,
            )

        listing_strong = {t for t in listing_tokens if _is_strong_identity_token(t)}
        page_strong = {t for t in page_tokens if _is_strong_identity_token(t)}
        matched_strong = sorted(listing_strong & page_strong)

        if matched_strong:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    f"model_source={model_source}",
                    f"strong token overlap hit: {matched_strong[0]}",
                ],
            )
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_TOKEN_MATCH",
                evidence=evidence,
            )

        if listing_strong and not matched_strong:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    f"model_source={model_source}",
                    f"strong_tokens(listing/page)={len(listing_strong)}/{len(page_strong)}",
                ],
            )
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="MODEL_TOKEN_MISSING",
                evidence=evidence,
            )

        evidence = build_evidence(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=[
                f"model_source={model_source}",
                f"strong_tokens(listing/page)={len(listing_strong)}/{len(page_strong)}",
            ],
        )
        return MatchDecision(
            status="uncertain",
            score=None,
            reason_code="TOKEN_WEAK_OR_EMPTY",
            evidence=evidence,
        )
