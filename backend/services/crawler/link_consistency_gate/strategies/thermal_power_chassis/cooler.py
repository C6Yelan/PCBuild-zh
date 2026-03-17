# backend/services/crawler/link_consistency_gate/strategies/thermal_power_chassis/cooler.py
from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from ..shared_primitives import build_evidence
from .cooler_primitives import (
    build_cooler_listing_tokens,
    build_cooler_page_text,
    extract_cooler_matched_tokens,
    extract_cooler_model_phrase,
    extract_cooler_strong_tokens,
    normalize_cooler_phrase,
)


@dataclass(frozen=True)
class CoolerStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_phrase_raw, model_source = extract_cooler_model_phrase(listing)
        model_phrase_norm = normalize_cooler_phrase(model_phrase_raw)
        page_text, page_text_norm = build_cooler_page_text(signals)
        listing_tokens = build_cooler_listing_tokens(model_phrase_raw)

        if not page_text_norm:
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="PAGE_TEXT_EMPTY",
                evidence=build_evidence(listing_tokens, [], [], [f"model_source={model_source}", "page_text is empty"]),
            )

        page_tokens = build_cooler_listing_tokens(page_text)
        matched_tokens = extract_cooler_matched_tokens(listing_tokens, page_tokens)

        if not model_phrase_norm:
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="MODEL_EMPTY",
                evidence=build_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    [f"model_source={model_source}", "model_phrase is empty after normalization"],
                ),
            )

        if model_phrase_norm in page_text_norm:
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_PHRASE_FOUND",
                evidence=build_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    [f"model_source={model_source}", "phrase match by normalized substring"],
                ),
            )

        listing_strong = extract_cooler_strong_tokens(listing_tokens)
        page_strong = extract_cooler_strong_tokens(page_tokens)
        matched_strong = sorted(listing_strong & page_strong)

        if matched_strong:
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_TOKEN_MATCH",
                evidence=build_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    [f"model_source={model_source}", f"strong token overlap hit: {matched_strong[0]}"],
                ),
            )

        if listing_strong and not matched_strong:
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="MODEL_TOKEN_MISSING",
                evidence=build_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    [f"model_source={model_source}", f"strong_tokens(listing/page)={len(listing_strong)}/{len(page_strong)}"],
                ),
            )

        return MatchDecision(
            status="uncertain",
            score=None,
            reason_code="TOKEN_WEAK_OR_EMPTY",
            evidence=build_evidence(
                listing_tokens,
                page_tokens,
                matched_tokens,
                [f"model_source={model_source}", f"strong_tokens(listing/page)={len(listing_strong)}/{len(page_strong)}"],
            ),
        )
