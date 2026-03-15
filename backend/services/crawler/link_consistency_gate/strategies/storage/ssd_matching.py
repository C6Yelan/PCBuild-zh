# backend/services/crawler/link_consistency_gate/strategies/storage/ssd_matching.py
from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from .ssd_primitives import (
    build_ssd_listing_tokens,
    build_ssd_page_text,
    build_ssd_tokens,
    extract_ssd_identity_tokens,
    extract_ssd_spec_tokens,
    normalize_ssd_phrase,
    pick_ssd_model_phrase,
)
from ..shared_primitives import (
    decision_with_evidence,
    identity_token_missing_decision,
    model_phrase_found_decision,
    model_token_match_decision,
    page_text_empty_decision,
    token_overlap_inconclusive_decision,
)


@dataclass(frozen=True)
class SsdStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        page_text_raw = build_ssd_page_text(signals)
        page_text_norm = normalize_ssd_phrase(page_text_raw)
        listing_tokens = build_ssd_listing_tokens(listing)

        if not page_text_norm:
            return page_text_empty_decision(
                listing_tokens=listing_tokens,
                notes=["page_text is empty (page_title/page_h1/text_hint all missing or blank)"],
            )

        page_tokens = build_ssd_tokens(page_text_raw)
        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))

        model_phrase_raw, model_src = pick_ssd_model_phrase(listing)
        model_phrase_norm = normalize_ssd_phrase(model_phrase_raw)
        if not model_phrase_norm:
            return decision_with_evidence(
                status="uncertain",
                reason_code="MODEL_EMPTY",
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=["model_phrase is empty after normalization (no usable identifier)"],
            )

        if model_phrase_norm in page_text_norm:
            return model_phrase_found_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"phrase match hit (model_source={model_src})"],
            )

        listing_identity = extract_ssd_identity_tokens(listing_tokens)
        listing_spec = extract_ssd_spec_tokens(listing_tokens)
        page_identity = extract_ssd_identity_tokens(page_tokens)
        page_spec = extract_ssd_spec_tokens(page_tokens)

        matched_identity = sorted(listing_identity & page_identity)
        matched_spec = sorted(listing_spec & page_spec)

        if matched_identity and matched_spec:
            return model_token_match_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    "token match via identity+spec overlap",
                    f"matched_identity={matched_identity[:2]}, matched_spec={matched_spec[:2]}",
                ],
            )

        if listing_identity and not matched_identity:
            return identity_token_missing_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=["listing has identity tokens but page has no identity-token overlap"],
            )

        return token_overlap_inconclusive_decision(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=["token overlap is inconclusive for SSD"],
            )
