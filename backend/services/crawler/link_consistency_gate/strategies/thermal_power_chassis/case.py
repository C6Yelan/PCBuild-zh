# backend/services/crawler/link_consistency_gate/strategies/case.py
from __future__ import annotations

import re
from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from ..shared_primitives import build_evidence, compose_page_text, normalize_spaces, tokenize_model_tokens


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


def _normalize_spaces(s: str) -> str:
    return normalize_spaces(s)


def _normalize_for_phrase(s: str) -> str:
    s = _normalize_spaces(s).upper()
    s = _RE_BRACKET_SYMBOLS.sub(" ", s)
    s = _RE_SEP_PHRASE.sub(" ", s)
    return normalize_spaces(s)


def _normalize_for_token(s: str) -> str:
    s = _normalize_spaces(s).upper()
    s = _RE_BRACKET_SYMBOLS.sub(" ", s)
    s = _RE_SEP_TOKEN.sub(" ", s)
    return normalize_spaces(s)


def _compact_for_contains(s: str) -> str:
    return _RE_COMPACT_KEEP.sub("", _normalize_for_phrase(s))


def _title_first_line(title: str) -> str:
    return (title or "").splitlines()[0].strip() if title else ""


def _pick_model_phrase(listing: ListingInput) -> tuple[str, str]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint"

    if (listing.sku_hint or "").strip():
        return listing.sku_hint.strip(), "sku_hint"

    return _title_first_line(listing.title), "title_first_line"


def _strip_bracket_tail(s: str) -> str:
    text = (s or "").strip()
    if not text:
        return ""

    first_idx = -1
    for opener in _BRACKET_OPENERS:
        idx = text.find(opener)
        if idx != -1 and (first_idx == -1 or idx < first_idx):
            first_idx = idx

    if first_idx == -1:
        return text
    return text[:first_idx].strip()


def _strip_trailing_color(s: str) -> str:
    norm = _normalize_for_phrase(s)
    if not norm:
        return ""

    parts = norm.split(" ")
    if not parts:
        return ""

    if parts[-1] in _COLOR_TOKENS:
        return " ".join(parts[:-1]).strip()
    return norm


def _build_model_candidates(raw: str) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def _add(candidate: str) -> None:
        norm = _normalize_for_phrase(candidate)
        if not norm or norm in seen:
            return
        seen.add(norm)
        ordered.append(norm)

    _add(raw)

    no_bracket_tail = _strip_bracket_tail(raw)
    _add(no_bracket_tail)

    for cand in list(ordered):
        no_color = _strip_trailing_color(cand)
        _add(no_color)

    return ordered


def _build_page_text(signals: PageSignals) -> str:
    return compose_page_text(
        signals.text_hint,
        signals.page_title,
        signals.page_h1,
        normalize=_normalize_spaces,
    )


def _tokenize(text: str) -> list[str]:
    return tokenize_model_tokens(text, normalize=_normalize_for_token)


def _is_identity_token(tok: str) -> bool:
    t = (tok or "").strip("-")
    if not t or t in _IDENTITY_STOPWORDS:
        return False
    if t.isdigit():
        return False
    return any(ch.isdigit() for ch in t)


def _extract_identity_tokens(tokens: list[str]) -> set[str]:
    return {t for t in tokens if _is_identity_token(t)}


@dataclass(frozen=True)
class CaseStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_raw, model_source = _pick_model_phrase(listing)
        model_candidates = _build_model_candidates(model_raw)

        listing_tokens = _tokenize(" ".join(model_candidates))

        page_text = _build_page_text(signals)
        page_norm = _normalize_for_phrase(page_text)
        if not page_norm:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=[],
                matched_tokens=[],
                notes=[f"model_source={model_source}", "page_text_empty"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="PAGE_TEXT_EMPTY",
                evidence=evidence,
            )

        page_tokens = _tokenize(page_text)
        if len(page_tokens) < 2:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[f"model_source={model_source}", "page_tokens_too_weak"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="TOKEN_WEAK_OR_EMPTY",
                evidence=evidence,
            )

        page_compact = _compact_for_contains(page_text)
        for cand in model_candidates:
            cand_compact = _compact_for_contains(cand)
            if not cand_compact:
                continue
            if cand_compact in page_compact:
                evidence = build_evidence(
                    listing_tokens=listing_tokens,
                    page_tokens=page_tokens,
                    matched_tokens=[cand],
                    notes=[f"model_source={model_source}", f"candidate_used={cand}", "phrase_match"],
                )
                return MatchDecision(
                    status="match",
                    score=None,
                    reason_code="MODEL_PHRASE_FOUND",
                    evidence=evidence,
                )

        listing_identity = _extract_identity_tokens(listing_tokens)
        page_identity = _extract_identity_tokens(page_tokens)
        matched_identity = sorted(listing_identity & page_identity)

        if matched_identity:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_identity,
                notes=[
                    f"model_source={model_source}",
                    "fallback_token_match",
                    f"strong_overlap={len(matched_identity)}",
                ],
            )
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_TOKEN_MATCH",
                evidence=evidence,
            )

        if not listing_identity:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[f"model_source={model_source}", "listing_identity_empty"],
            )
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="MODEL_TOKEN_MISSING",
                evidence=evidence,
            )

        overlap_tokens = sorted(set(listing_tokens) & set(page_tokens))
        if not overlap_tokens:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[f"model_source={model_source}", "identity_overlap_empty"],
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
            matched_tokens=overlap_tokens,
            notes=[f"model_source={model_source}", "overlap_only_weak_tokens"],
        )
        return MatchDecision(
            status="uncertain",
            score=None,
            reason_code="TOKEN_OVERLAP_INCONCLUSIVE",
            evidence=evidence,
        )
