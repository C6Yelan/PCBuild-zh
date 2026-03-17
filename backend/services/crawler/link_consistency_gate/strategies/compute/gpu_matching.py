# backend/services/crawler/link_consistency_gate/strategies/compute/gpu_matching.py
from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from .gpu_primitives import (
    build_gpu_listing_tokens,
    build_gpu_page_text,
    build_gpu_page_tokens,
    extract_gpu_identities,
    normalize_gpu_text,
    pick_gpu_model_phrase,
)
from ..shared_primitives import (
    model_phrase_found_decision,
    model_token_match_decision,
    model_token_missing_decision,
    page_text_empty_decision,
    token_overlap_inconclusive_decision,
    token_weak_or_empty_decision,
)


@dataclass(frozen=True)
class GpuStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_phrase_raw, model_source = pick_gpu_model_phrase(listing)
        model_phrase_norm = normalize_gpu_text(model_phrase_raw)
        page_text = build_gpu_page_text(signals)
        page_text_norm = normalize_gpu_text(page_text)

        listing_identities = extract_gpu_identities(
            " ".join(
                [
                    model_phrase_raw,
                    listing.sku_hint or "",
                    str(listing.extra.get("model_hint") or ""),
                ]
            )
        )
        page_identities = extract_gpu_identities(page_text)

        listing_tokens = build_gpu_listing_tokens(model_phrase_raw, listing_identities)
        page_tokens = build_gpu_page_tokens(page_text, page_identities)
        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))

        if not page_text_norm:
            return page_text_empty_decision(
                listing_tokens=listing_tokens,
                notes=[f"model_source={model_source}", "page text empty"],
            )

        if not page_tokens and not page_identities:
            return token_weak_or_empty_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "page tokens too weak"],
            )

        listing_identity_set = set(listing_identities)
        page_identity_set = set(page_identities)
        matched_identity = sorted(listing_identity_set & page_identity_set)

        if model_phrase_norm and model_phrase_norm in page_text_norm:
            if listing_identity_set and page_identity_set and not matched_identity:
                # Avoid prefix false positives such as RTX 4060 vs RTX 4060 TI.
                pass
            else:
                phrase_matches = sorted(set(matched_tokens) | {model_phrase_norm} | set(matched_identity))
                return model_phrase_found_decision(
                    listing_tokens=listing_tokens,
                    page_tokens=page_tokens,
                    matched_tokens=phrase_matches,
                    notes=[f"model_source={model_source}", "phrase hit"],
                )

        if matched_identity:
            return model_token_match_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_identity,
                notes=[f"model_source={model_source}", "identity token match"],
            )

        if listing_identity_set and page_identity_set and not matched_identity:
            return model_token_missing_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    f"model_source={model_source}",
                    f"identity mismatch: listing={sorted(listing_identity_set)[:2]} page={sorted(page_identity_set)[:2]}",
                ],
            )

        if not listing_identity_set or not page_identity_set:
            return token_weak_or_empty_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "identity tokens weak or empty"],
            )

        return token_overlap_inconclusive_decision(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=[f"model_source={model_source}", "token overlap inconclusive"],
        )
