# backend/services/crawler/link_consistency_gate/strategies/compute/cpu.py
from __future__ import annotations

from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from .cpu_primitives import (
    build_cpu_model_phrase,
    build_cpu_model_tokens,
    build_cpu_page_text,
    cpu_model_phrase_in_page,
    extract_cpu_context_words,
    is_cpu_strong_alnum_token,
    normalize_cpu_text,
    pick_cpu_identifier,
    strip_cpu_title_prefix,
)
from ..shared_primitives import (
    decision_with_evidence,
    model_phrase_found_decision,
    model_token_match_decision,
    model_token_missing_decision,
    page_text_empty_decision,
    token_overlap_inconclusive_decision,
)


@dataclass(frozen=True)
class CpuStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        identifier_raw, identifier_src = pick_cpu_identifier(listing)
        if identifier_src == "title":
            identifier_raw = strip_cpu_title_prefix(identifier_raw)
        identifier_norm = normalize_cpu_text(identifier_raw)

        model_phrase = build_cpu_model_phrase(identifier_norm)
        listing_tokens = build_cpu_model_tokens(model_phrase)

        page_text = build_cpu_page_text(signals)
        if not page_text:
            return page_text_empty_decision(
                listing_tokens=listing_tokens,
                notes=["page_text is empty (page_title/page_h1/text_hint all missing or blank)"],
            )

        page_tokens = build_cpu_model_tokens(page_text)

        if not model_phrase:
            return decision_with_evidence(
                status="uncertain",
                reason_code="MODEL_EMPTY",
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=["model_phrase is empty after normalization (no usable model identifier)"],
            )

        if cpu_model_phrase_in_page(page_text, model_phrase):
            return model_phrase_found_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=sorted(set(listing_tokens) & set(page_tokens)),
                notes=["model_phrase found in page_text"],
            )

        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))
        matched_strong = [t for t in matched_tokens if is_cpu_strong_alnum_token(t)]
        if matched_strong:
            return model_token_match_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"strong model token matched: {matched_strong[0]}"],
            )

        matched_numeric_ids = [t for t in matched_tokens if t.isdigit() and len(t) >= 3]
        if matched_numeric_ids:
            has_context_token = any(not t.isdigit() for t in matched_tokens)
            listing_ctx = extract_cpu_context_words(model_phrase)
            page_ctx = extract_cpu_context_words(page_text)
            matched_ctx = sorted(listing_ctx & page_ctx)
            if has_context_token or matched_ctx:
                if has_context_token and matched_ctx:
                    note = f"numeric token matched with context token(s) and word(s): {', '.join(matched_ctx[:3])}"
                elif has_context_token:
                    note = "numeric token matched with context token(s)"
                else:
                    note = f"numeric token matched with context word(s): {', '.join(matched_ctx[:3])}"
                return model_token_match_decision(
                    listing_tokens=listing_tokens,
                    page_tokens=page_tokens,
                    matched_tokens=matched_tokens,
                    notes=[note],
                )

            return decision_with_evidence(
                status="uncertain",
                reason_code="NUMERIC_ONLY_WEAK_MATCH",
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=["only numeric tokens matched; no context word matched (weak match)"],
            )

        if not matched_tokens and any(is_cpu_strong_alnum_token(token) for token in listing_tokens):
            return model_token_missing_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=["no model tokens matched, but listing has strong model token(s)"],
            )

        return token_overlap_inconclusive_decision(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=["token overlap is inconclusive for CPU model"],
        )
