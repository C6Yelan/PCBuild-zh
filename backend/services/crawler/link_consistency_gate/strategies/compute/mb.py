# backend/services/crawler/link_consistency_gate/strategies/compute/mb.py
from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from .mb_primitives import (
    build_mb_evidence,
    build_mb_page_text,
    extract_mb_matched_tokens,
    extract_mb_model_phrase,
    extract_mb_strong_tokens,
    normalize_mb_text,
    tokenize_mb_text,
)


@dataclass(frozen=True)
class MbStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_phrase_raw, model_source = extract_mb_model_phrase(listing)
        model_phrase_norm = normalize_mb_text(model_phrase_raw)

        page_text, page_text_norm = build_mb_page_text(signals)
        listing_tokens = tokenize_mb_text(model_phrase_norm)

        if not page_text_norm:
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="PAGE_TEXT_EMPTY",
                evidence=build_mb_evidence(
                    listing_tokens,
                    [],
                    [],
                    [
                        "page_text is empty (page_title/page_h1/text_hint all missing or blank)",
                        f"model_source={model_source}",
                    ],
                ),
            )

        page_tokens = tokenize_mb_text(page_text)
        matched_tokens = extract_mb_matched_tokens(listing_tokens, page_tokens)

        if not model_phrase_norm:
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="MODEL_EMPTY",
                evidence=build_mb_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    ["model_phrase is empty after normalization", f"model_source={model_source}"],
                ),
            )

        if model_phrase_norm in page_text_norm:
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_PHRASE_FOUND",
                evidence=build_mb_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    ["phrase match via normalized substring", f"model_source={model_source}"],
                ),
            )

        listing_strong = extract_mb_strong_tokens(listing_tokens)
        page_strong = extract_mb_strong_tokens(page_tokens)
        matched_strong = sorted(listing_strong & page_strong)

        if listing_strong and page_strong and matched_strong:
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_TOKEN_MATCH",
                evidence=build_mb_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    [
                        "token match via strong token intersection",
                        f"strong_tokens(listing/page)={len(listing_strong)}/{len(page_strong)}",
                    ],
                ),
            )

        if listing_strong and not matched_strong:
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="MODEL_TOKEN_MISSING",
                evidence=build_mb_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    [
                        "listing has strong token(s) but none matched in page_text",
                        f"strong_tokens(listing/page)={len(listing_strong)}/{len(page_strong)}",
                    ],
                ),
            )

        return MatchDecision(
            status="uncertain",
            score=None,
            reason_code="TOKEN_WEAK_OR_EMPTY",
            evidence=build_mb_evidence(
                listing_tokens,
                page_tokens,
                matched_tokens,
                [
                    "insufficient strong tokens for a confident decision",
                    f"strong_tokens(listing/page)={len(listing_strong)}/{len(page_strong)}",
                ],
            ),
        )
