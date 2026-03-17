# backend/services/crawler/link_consistency_gate/strategies/thermal_power_chassis/psu_matching.py
from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from .psu_primitives import (
    build_psu_model_candidates,
    build_psu_page_text,
    compact_psu_phrase,
    extract_psu_identity_tokens,
    is_psu_weak_token,
    normalize_psu_phrase,
    pick_psu_model_phrase,
    psu_title_head,
    tokenize_psu_tokens,
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
class PsuStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        raw_phrase, model_source, ignored_weak_sku_hint = pick_psu_model_phrase(listing)
        candidates = build_psu_model_candidates(raw_phrase)
        base_notes = [f"model_source={model_source}"]
        if ignored_weak_sku_hint:
            base_notes.append("ignored_weak_sku_hint")
        if model_source == "sku_hint":
            title_head = psu_title_head(listing.title)
            if title_head and normalize_psu_phrase(title_head) != normalize_psu_phrase(raw_phrase):
                title_candidates = build_psu_model_candidates(title_head)
                merged_candidates: list[str] = []
                seen_candidates: set[str] = set()
                for cand in [*candidates, *title_candidates]:
                    norm_cand = normalize_psu_phrase(cand)
                    if not norm_cand or norm_cand in seen_candidates:
                        continue
                    seen_candidates.add(norm_cand)
                    merged_candidates.append(cand)
                if merged_candidates != candidates:
                    candidates = merged_candidates
                    base_notes.append("added_title_head_candidates")

        listing_tokens = tokenize_psu_tokens(" ".join(candidates))

        page_text = build_psu_page_text(signals)
        if not normalize_psu_phrase(page_text):
            return page_text_empty_decision(
                listing_tokens=listing_tokens,
                notes=[*base_notes, "page_text_empty"],
            )

        page_tokens = tokenize_psu_tokens(page_text)
        if len(page_tokens) < 2:
            return token_weak_or_empty_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[*base_notes, "page_tokens_too_weak"],
            )

        page_compact = compact_psu_phrase(page_text)
        for cand in candidates:
            cand_compact = compact_psu_phrase(cand)
            if cand_compact and cand_compact in page_compact:
                return model_phrase_found_decision(
                    listing_tokens=listing_tokens,
                    page_tokens=page_tokens,
                    matched_tokens=[cand],
                    notes=[*base_notes, f"candidate_used={cand}", "phrase_match"],
                )

        listing_identity = extract_psu_identity_tokens(listing_tokens)
        if not listing_identity:
            return model_token_missing_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[*base_notes, "listing_identity_empty"],
            )

        matched_tokens = sorted(listing_identity & set(page_tokens))
        if not matched_tokens:
            return identity_token_missing_decision(
                listing_tokens=sorted(listing_identity),
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[*base_notes, "identity_overlap_empty"],
            )

        if all(is_psu_weak_token(tok) for tok in matched_tokens):
            return token_overlap_inconclusive_decision(
                listing_tokens=sorted(listing_identity),
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[*base_notes, "only_weak_identity_overlap"],
            )

        return model_token_match_decision(
            listing_tokens=sorted(listing_identity),
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=[*base_notes, "fallback_token_match"],
        )
