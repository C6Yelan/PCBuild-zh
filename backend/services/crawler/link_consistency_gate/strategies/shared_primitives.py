# backend/services/crawler/link_consistency_gate/strategies/shared_primitives.py
"""Stable façade for shared link-consistency primitives."""

from __future__ import annotations

from .shared_decision_primitives import (
    build_evidence,
    decision_with_evidence,
    identity_token_missing_decision,
    model_phrase_found_decision,
    model_token_match_decision,
    model_token_missing_decision,
    page_text_empty_decision,
    token_overlap_inconclusive_decision,
    token_weak_or_empty_decision,
)
from .shared_text_primitives import (
    compose_page_text,
    normalize_pattern_text,
    normalize_spaces,
    normalize_upper_pattern_text,
    tokenize_model_tokens,
)

__all__ = [
    "build_evidence",
    "compose_page_text",
    "decision_with_evidence",
    "identity_token_missing_decision",
    "model_phrase_found_decision",
    "model_token_match_decision",
    "model_token_missing_decision",
    "normalize_pattern_text",
    "normalize_spaces",
    "normalize_upper_pattern_text",
    "page_text_empty_decision",
    "token_overlap_inconclusive_decision",
    "token_weak_or_empty_decision",
    "tokenize_model_tokens",
]
