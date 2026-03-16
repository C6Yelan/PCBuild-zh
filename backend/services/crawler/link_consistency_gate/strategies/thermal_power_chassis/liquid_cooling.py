from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from .liquid_cooling_primitives import (
    build_liquid_cooling_identity_keys,
    build_liquid_cooling_page_text,
    build_liquid_cooling_tokens,
    normalize_liquid_cooling_phrase,
    pick_liquid_cooling_model_phrase,
)
from ..shared_primitives import (
    identity_token_missing_decision,
    model_phrase_found_decision,
    model_token_match_decision,
    page_text_empty_decision,
    token_overlap_inconclusive_decision,
)


@dataclass(frozen=True)
class LiquidCoolingStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_phrase_raw, model_source = pick_liquid_cooling_model_phrase(listing)
        model_phrase_norm = normalize_liquid_cooling_phrase(model_phrase_raw)

        page_text = build_liquid_cooling_page_text(signals)
        page_text_norm = normalize_liquid_cooling_phrase(page_text)

        listing_tokens = build_liquid_cooling_tokens(model_phrase_raw)

        if not page_text_norm:
            return page_text_empty_decision(
                listing_tokens=listing_tokens,
                notes=[f"model_source={model_source}", "page_empty"],
            )

        page_tokens = build_liquid_cooling_tokens(page_text)
        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))

        if model_phrase_norm and model_phrase_norm in page_text_norm:
            return model_phrase_found_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "phrase_hit"],
            )

        listing_identity_keys = build_liquid_cooling_identity_keys(listing_tokens)
        page_identity_keys = build_liquid_cooling_identity_keys(page_tokens)
        matched_identity_keys = sorted(listing_identity_keys & page_identity_keys)

        if matched_identity_keys:
            return model_token_match_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "token_match"],
            )

        if not listing_identity_keys:
            return identity_token_missing_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "identity_missing"],
            )

        return token_overlap_inconclusive_decision(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=[f"model_source={model_source}", "overlap_inconclusive"],
        )
