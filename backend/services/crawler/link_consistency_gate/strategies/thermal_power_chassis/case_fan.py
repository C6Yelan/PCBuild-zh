# backend/services/crawler/link_consistency_gate/strategies/case_fan.py
from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from .case_fan_primitives import (
    build_case_fan_model_candidates,
    build_case_fan_page_text,
    build_case_fan_tokens,
    compact_case_fan_phrase,
    extract_case_fan_identity_tokens,
    normalize_case_fan_phrase,
    pick_case_fan_model_phrase,
)
from ..shared_primitives import (
    identity_token_missing_decision,
    model_phrase_found_decision,
    model_token_match_decision,
    page_text_empty_decision,
    token_overlap_inconclusive_decision,
    token_weak_or_empty_decision,
)


@dataclass(frozen=True)
class CaseFanStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        raw_phrase, model_source = pick_case_fan_model_phrase(listing)
        candidates = build_case_fan_model_candidates(raw_phrase)
        listing_tokens = build_case_fan_tokens(" ".join(candidates))

        page_text = build_case_fan_page_text(signals)
        if not normalize_case_fan_phrase(page_text):
            return page_text_empty_decision(
                listing_tokens=listing_tokens,
                notes=[f"model_source={model_source}", "page_text_empty"],
            )

        page_tokens = build_case_fan_tokens(page_text)
        if len(page_tokens) < 2:
            return token_weak_or_empty_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[f"model_source={model_source}", "page_tokens_too_weak"],
            )

        page_compact = compact_case_fan_phrase(page_text)
        for cand in candidates:
            cand_compact = compact_case_fan_phrase(cand)
            if cand_compact and cand_compact in page_compact:
                return model_phrase_found_decision(
                    listing_tokens=listing_tokens,
                    page_tokens=page_tokens,
                    matched_tokens=[cand],
                    notes=[f"model_source={model_source}", f"candidate_used={cand}", "phrase_match"],
                )

        listing_identity = extract_case_fan_identity_tokens(listing_tokens)
        page_identity = extract_case_fan_identity_tokens(page_tokens)
        overlap_tokens = sorted(set(listing_tokens) & set(page_tokens))
        matched_identity = sorted(listing_identity & page_identity)

        if not listing_identity or not page_identity:
            return token_weak_or_empty_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=overlap_tokens,
                notes=[
                    f"model_source={model_source}",
                    f"identity tokens weak or empty(listing/page)={len(listing_identity)}/{len(page_identity)}",
                ],
            )

        if matched_identity:
            return model_token_match_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=overlap_tokens,
                notes=[
                    f"model_source={model_source}",
                    "fallback_token_match",
                    f"strong_overlap={len(matched_identity)}",
                ],
            )

        if not overlap_tokens:
            return identity_token_missing_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[f"model_source={model_source}", "identity_overlap_empty"],
            )

        return token_overlap_inconclusive_decision(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=overlap_tokens,
            notes=[f"model_source={model_source}", "only_weak_identity_overlap"],
        )
