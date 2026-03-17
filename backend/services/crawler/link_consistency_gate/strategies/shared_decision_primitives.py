"""Shared evidence and decision builders for link consistency strategies."""

from __future__ import annotations

from typing import Any

from ..types import MatchDecision


def build_evidence(
    listing_tokens: list[str],
    page_tokens: list[str],
    matched_tokens: list[str],
    notes: list[str],
) -> dict[str, Any]:
    return {
        "listing_tokens": list(listing_tokens),
        "page_tokens": list(page_tokens),
        "matched_tokens": list(matched_tokens),
        "notes": list(notes),
    }


def decision_with_evidence(
    *,
    status: str,
    reason_code: str,
    listing_tokens: list[str],
    page_tokens: list[str],
    matched_tokens: list[str],
    notes: list[str],
) -> MatchDecision:
    return MatchDecision(
        status=status,
        score=None,
        reason_code=reason_code,
        evidence=build_evidence(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=notes,
        ),
    )


def page_text_empty_decision(
    *,
    listing_tokens: list[str],
    notes: list[str],
) -> MatchDecision:
    return decision_with_evidence(
        status="uncertain",
        reason_code="PAGE_TEXT_EMPTY",
        listing_tokens=listing_tokens,
        page_tokens=[],
        matched_tokens=[],
        notes=notes,
    )


def token_weak_or_empty_decision(
    *,
    listing_tokens: list[str],
    page_tokens: list[str],
    matched_tokens: list[str],
    notes: list[str],
) -> MatchDecision:
    return decision_with_evidence(
        status="uncertain",
        reason_code="TOKEN_WEAK_OR_EMPTY",
        listing_tokens=listing_tokens,
        page_tokens=page_tokens,
        matched_tokens=matched_tokens,
        notes=notes,
    )


def model_phrase_found_decision(
    *,
    listing_tokens: list[str],
    page_tokens: list[str],
    matched_tokens: list[str],
    notes: list[str],
) -> MatchDecision:
    return decision_with_evidence(
        status="match",
        reason_code="MODEL_PHRASE_FOUND",
        listing_tokens=listing_tokens,
        page_tokens=page_tokens,
        matched_tokens=matched_tokens,
        notes=notes,
    )


def model_token_match_decision(
    *,
    listing_tokens: list[str],
    page_tokens: list[str],
    matched_tokens: list[str],
    notes: list[str],
) -> MatchDecision:
    return decision_with_evidence(
        status="match",
        reason_code="MODEL_TOKEN_MATCH",
        listing_tokens=listing_tokens,
        page_tokens=page_tokens,
        matched_tokens=matched_tokens,
        notes=notes,
    )


def model_token_missing_decision(
    *,
    listing_tokens: list[str],
    page_tokens: list[str],
    matched_tokens: list[str],
    notes: list[str],
) -> MatchDecision:
    return decision_with_evidence(
        status="mismatch",
        reason_code="MODEL_TOKEN_MISSING",
        listing_tokens=listing_tokens,
        page_tokens=page_tokens,
        matched_tokens=matched_tokens,
        notes=notes,
    )


def identity_token_missing_decision(
    *,
    listing_tokens: list[str],
    page_tokens: list[str],
    matched_tokens: list[str],
    notes: list[str],
) -> MatchDecision:
    return decision_with_evidence(
        status="mismatch",
        reason_code="IDENTITY_TOKEN_MISSING",
        listing_tokens=listing_tokens,
        page_tokens=page_tokens,
        matched_tokens=matched_tokens,
        notes=notes,
    )


def token_overlap_inconclusive_decision(
    *,
    listing_tokens: list[str],
    page_tokens: list[str],
    matched_tokens: list[str],
    notes: list[str],
) -> MatchDecision:
    return decision_with_evidence(
        status="uncertain",
        reason_code="TOKEN_OVERLAP_INCONCLUSIVE",
        listing_tokens=listing_tokens,
        page_tokens=page_tokens,
        matched_tokens=matched_tokens,
        notes=notes,
    )
