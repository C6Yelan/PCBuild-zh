from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from .ram_primitives import (
    build_ram_listing_tokens,
    build_ram_page_text,
    build_ram_tokens,
    extract_ram_identity_tokens,
    extract_ram_spec_tokens,
    normalize_ram_phrase,
    pick_ram_model_phrase,
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
class RamStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        page_text_raw = build_ram_page_text(signals)
        page_text_norm = normalize_ram_phrase(page_text_raw)
        listing_tokens = build_ram_listing_tokens(listing)

        if not page_text_norm:
            return page_text_empty_decision(
                listing_tokens=listing_tokens,
                notes=["page_text is empty (page_title/page_h1/text_hint all missing or blank)"],
            )

        page_tokens = build_ram_tokens(page_text_raw)
        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))

        model_phrase_raw, model_src = pick_ram_model_phrase(listing)
        model_phrase_norm = normalize_ram_phrase(model_phrase_raw)

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
                notes=[f"phrase_hit via normalized substring (model_source={model_src})"],
            )

        listing_identity = extract_ram_identity_tokens(listing, listing_tokens)
        listing_spec = extract_ram_spec_tokens(listing_tokens)

        page_set = set(page_tokens)
        matched_identity = sorted(listing_identity & page_set)
        matched_spec = sorted(listing_spec & page_set)

        if matched_identity and matched_spec:
            return model_token_match_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    "token_match: identity+spec tokens overlapped",
                    f"matched_identity={matched_identity[:2]}, matched_spec={matched_spec[:2]}",
                ],
            )

        if listing_identity and not matched_identity:
            return identity_token_missing_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    "mismatch: no identity token matched",
                    f"identity_tokens(listing)={len(listing_identity)}",
                ],
            )

        return token_overlap_inconclusive_decision(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=[
                "uncertain: token overlap insufficient (need >=1 identity + >=1 spec token)",
                f"identity/spec(listing)={len(listing_identity)}/{len(listing_spec)}",
            ],
        )
