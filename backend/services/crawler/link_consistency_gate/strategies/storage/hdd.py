# backend/services/crawler/link_consistency_gate/strategies/storage/hdd.py
from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from ..shared_primitives import build_evidence
from .hdd_primitives import (
    build_hdd_listing_tokens,
    build_hdd_page_text,
    extract_hdd_identity_tokens,
    extract_hdd_matched_tokens,
    normalize_hdd_model_key,
    pick_hdd_model_candidate,
    tokenize_hdd_text,
)


@dataclass(frozen=True)
class HddStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_candidate, model_src = pick_hdd_model_candidate(listing)
        canonical_model_key = normalize_hdd_model_key(model_candidate)
        page_text, canonical_page_text = build_hdd_page_text(signals)
        listing_tokens = build_hdd_listing_tokens(listing, model_candidate)

        if not page_text or not canonical_page_text:
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="PAGE_TEXT_EMPTY",
                evidence=build_evidence(
                    listing_tokens,
                    [],
                    [],
                    [f"model_source={model_src}", "page_text is empty after normalization"],
                ),
            )

        page_tokens = tokenize_hdd_text(page_text)
        matched_tokens = extract_hdd_matched_tokens(listing_tokens, page_tokens)

        if not canonical_model_key:
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="MODEL_EMPTY",
                evidence=build_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    [f"model_source={model_src}", "canonical model key is empty"],
                ),
            )

        if canonical_model_key in canonical_page_text:
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_PHRASE_FOUND",
                evidence=build_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    [f"model_source={model_src}", "canonical model phrase found in page text"],
                ),
            )

        listing_identity = extract_hdd_identity_tokens(listing_tokens)
        page_identity = extract_hdd_identity_tokens(page_tokens)
        matched_identity = sorted(listing_identity & page_identity)

        if matched_identity:
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_TOKEN_MATCH",
                evidence=build_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    [f"model_source={model_src}", f"identity token overlap found: {matched_identity[0]}"],
                ),
            )

        if listing_identity:
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="IDENTITY_TOKEN_MISSING",
                evidence=build_evidence(
                    listing_tokens,
                    page_tokens,
                    matched_tokens,
                    [f"model_source={model_src}", "listing has identity token(s) but page has no identity overlap"],
                ),
            )

        return MatchDecision(
            status="uncertain",
            score=None,
            reason_code="TOKEN_OVERLAP_INCONCLUSIVE",
            evidence=build_evidence(
                listing_tokens,
                page_tokens,
                matched_tokens,
                [f"model_source={model_src}", "token overlap is inconclusive for HDD"],
            ),
        )
