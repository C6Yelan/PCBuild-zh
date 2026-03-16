from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from .expansion_card_primitives import (
    build_expansion_card_page_text,
    build_expansion_card_phrase_candidates,
    build_expansion_card_title_head_candidates,
    build_expansion_card_tokens,
    compact_expansion_card_phrase,
    extract_expansion_card_identity_tokens,
    is_expansion_card_pure_model_code_phrase,
    pick_expansion_card_model_phrase,
)
from ..shared_primitives import (
    identity_token_missing_decision,
    model_phrase_found_decision,
    model_token_match_decision,
    page_text_empty_decision,
    token_overlap_inconclusive_decision,
    token_weak_or_empty_decision,
)

_WEAK_IDENTITY_TOKENS = {"GEN3", "GEN4", "GEN5", "USB4"}


@dataclass(frozen=True)
class ExpansionCardStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_phrase, model_source, has_model = pick_expansion_card_model_phrase(listing)
        model_candidates = build_expansion_card_phrase_candidates(model_phrase)
        base_notes = [f"model_source={model_source}"]

        title_head_candidates, added_title_head_candidates = build_expansion_card_title_head_candidates(
            listing,
            model_phrase=model_phrase,
            model_source=model_source,
            has_model=has_model,
        )
        if added_title_head_candidates:
            base_notes.append("added_title_head_candidates")

        page_text = build_expansion_card_page_text(signals)
        listing_tokens = build_expansion_card_tokens(model_phrase)
        page_tokens = build_expansion_card_tokens(page_text)

        if not page_text.strip():
            return page_text_empty_decision(
                listing_tokens=listing_tokens,
                notes=[*base_notes, "page_text_empty"],
            )

        compact_page = compact_expansion_card_phrase(page_text)
        phrase_sources: list[tuple[str, str]] = [(cand, "model_phrase") for cand in model_candidates]
        phrase_sources.extend((cand, "title_head") for cand in title_head_candidates)

        for cand, phrase_source in phrase_sources:
            if is_expansion_card_pure_model_code_phrase(cand):
                continue
            compact_cand = compact_expansion_card_phrase(cand)
            if compact_cand and compact_cand in compact_page:
                match_notes = [*base_notes, f"candidate_used={cand}", "phrase_match"]
                if phrase_source == "title_head":
                    match_notes.append("phrase_source=title_head")
                return model_phrase_found_decision(
                    listing_tokens=build_expansion_card_tokens(cand),
                    page_tokens=page_tokens,
                    matched_tokens=[cand],
                    notes=match_notes,
                )

        listing_identity = extract_expansion_card_identity_tokens(listing_tokens)
        page_identity = extract_expansion_card_identity_tokens(page_tokens)
        matched_tokens = sorted(list(listing_identity & page_identity))

        if not listing_identity or not page_identity:
            return token_weak_or_empty_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[*base_notes, "identity_tokens_weak_or_empty"],
            )

        if matched_tokens:
            if all(tok in _WEAK_IDENTITY_TOKENS for tok in matched_tokens):
                return token_overlap_inconclusive_decision(
                    listing_tokens=listing_tokens,
                    page_tokens=page_tokens,
                    matched_tokens=matched_tokens,
                    notes=[*base_notes, "only_weak_identity_overlap"],
                )

            return model_token_match_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[*base_notes, "token_fallback_match"],
            )

        return identity_token_missing_decision(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=[],
            notes=[*base_notes, "no_identity_token_overlap"],
        )
