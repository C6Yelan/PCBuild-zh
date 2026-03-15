# backend/services/crawler/link_consistency_gate/strategies/thermal_power_chassis/case_matching.py
from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from .case_primitives import (
    build_case_model_candidates,
    build_case_page_text,
    compact_case_phrase,
    extract_case_identity_tokens,
    pick_case_model_phrase,
    tokenize_case_tokens,
)
from ..shared_primitives import (
    identity_token_missing_decision,
    model_phrase_found_decision,
    model_token_match_decision,
    model_token_missing_decision,
    page_text_empty_decision,
    token_overlap_inconclusive_decision,
    token_weak_or_empty_decision,
)


@dataclass(frozen=True)
class CaseStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_raw, model_source = pick_case_model_phrase(listing)
        model_candidates = build_case_model_candidates(model_raw)

        listing_tokens = tokenize_case_tokens(" ".join(model_candidates))

        page_text = build_case_page_text(signals)
        page_norm = compact_case_phrase(page_text)
        if not page_norm:
            return page_text_empty_decision(
                listing_tokens=listing_tokens,
                notes=[f"model_source={model_source}", "page_text_empty"],
            )

        page_tokens = tokenize_case_tokens(page_text)
        if len(page_tokens) < 2:
            return token_weak_or_empty_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[f"model_source={model_source}", "page_tokens_too_weak"],
            )

        page_compact = compact_case_phrase(page_text)
        for cand in model_candidates:
            cand_compact = compact_case_phrase(cand)
            if not cand_compact:
                continue
            if cand_compact in page_compact:
                return model_phrase_found_decision(
                    listing_tokens=listing_tokens,
                    page_tokens=page_tokens,
                    matched_tokens=[cand],
                    notes=[f"model_source={model_source}", f"candidate_used={cand}", "phrase_match"],
                )

        listing_identity = extract_case_identity_tokens(listing_tokens)
        page_identity = extract_case_identity_tokens(page_tokens)
        matched_identity = sorted(listing_identity & page_identity)

        if matched_identity:
            return model_token_match_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_identity,
                notes=[
                    f"model_source={model_source}",
                    "fallback_token_match",
                    f"strong_overlap={len(matched_identity)}",
                ],
            )

        if not listing_identity:
            return model_token_missing_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[f"model_source={model_source}", "listing_identity_empty"],
            )

        overlap_tokens = sorted(set(listing_tokens) & set(page_tokens))
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
            notes=[f"model_source={model_source}", "overlap_only_weak_tokens"],
        )
