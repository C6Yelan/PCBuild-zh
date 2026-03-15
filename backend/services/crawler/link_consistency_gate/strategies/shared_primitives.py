# backend/services/crawler/link_consistency_gate/strategies/shared_primitives.py
"""Shared low-risk text and evidence primitives for link consistency strategies."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, Callable

from ..types import MatchDecision

_RE_WS = re.compile(r"\s+", flags=re.UNICODE)
_RE_MODEL_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)


def normalize_spaces(text: str) -> str:
    normalized = (text or "").replace("\u3000", " ").replace("\xa0", " ")
    return _RE_WS.sub(" ", normalized).strip()


def normalize_pattern_text(
    text: str,
    *,
    transform: str | None = None,
    prepare: Callable[[str], str] | None = None,
    bracket_re: re.Pattern[str] | None = None,
    separator_re: re.Pattern[str] | None = None,
    replacements_before: Sequence[tuple[re.Pattern[str], str]] = (),
    replacements_after: Sequence[tuple[re.Pattern[str], str]] = (),
) -> str:
    normalized = normalize_spaces(text)
    if prepare is not None:
        normalized = prepare(normalized)
    if transform == "upper":
        normalized = normalized.upper()
    elif transform == "lower":
        normalized = normalized.lower()

    for pattern, replacement in replacements_before:
        normalized = pattern.sub(replacement, normalized)
    if bracket_re is not None:
        normalized = bracket_re.sub(" ", normalized)
    if separator_re is not None:
        normalized = separator_re.sub(" ", normalized)
    for pattern, replacement in replacements_after:
        normalized = pattern.sub(replacement, normalized)

    return normalize_spaces(normalized)


def normalize_upper_pattern_text(
    text: str,
    *,
    prepare: Callable[[str], str] | None = None,
    bracket_re: re.Pattern[str] | None = None,
    separator_re: re.Pattern[str] | None = None,
    replacements_before: Sequence[tuple[re.Pattern[str], str]] = (),
    replacements_after: Sequence[tuple[re.Pattern[str], str]] = (),
) -> str:
    return normalize_pattern_text(
        text,
        transform="upper",
        prepare=prepare,
        bracket_re=bracket_re,
        separator_re=separator_re,
        replacements_before=replacements_before,
        replacements_after=replacements_after,
    )


def compose_page_text(
    *parts: str | None,
    normalize: Callable[[str], str] | None = None,
) -> str:
    text = " ".join(part for part in parts if part).strip()
    if normalize is not None:
        return normalize(text)
    return text


def tokenize_model_tokens(
    text: str,
    *,
    normalize: Callable[[str], str],
    join_hyphen_parts: bool = False,
    min_length: int = 1,
) -> list[str]:
    normalized = normalize(text)
    tokens: set[str] = set()

    for match in _RE_MODEL_TOKEN.finditer(normalized):
        token = match.group(0).strip("-")
        if not token or len(token) < min_length:
            continue
        tokens.add(token)
        if "-" not in token:
            continue

        parts: list[str] = []
        for part in token.split("-"):
            part = part.strip("-")
            if not part or len(part) < min_length:
                continue
            tokens.add(part)
            parts.append(part)
        if join_hyphen_parts and parts:
            tokens.add("".join(parts))

    return sorted(tokens)


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
    evidence = build_evidence(
        listing_tokens=listing_tokens,
        page_tokens=page_tokens,
        matched_tokens=matched_tokens,
        notes=notes,
    )
    return MatchDecision(
        status=status,
        score=None,
        reason_code=reason_code,
        evidence=evidence,
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
