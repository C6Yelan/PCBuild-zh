# backend/services/crawler/official_reconcile_gate/matchers/base.py
"""Category matcher protocol for T6 official reconciliation."""

from __future__ import annotations

from typing import Protocol

from ..types import (
    ListingInput,
    MatchDecisionWithOfficial,
    OfficialCandidate,
    OfficialSignals,
)


class CategoryMatcher(Protocol):
    category: str

    def score(
        self,
        item: ListingInput,
        candidate: OfficialCandidate,
        signals: OfficialSignals,
    ) -> float:
        ...

    def decide(
        self,
        item: ListingInput,
        candidate: OfficialCandidate,
        signals: OfficialSignals,
        score: float,
    ) -> MatchDecisionWithOfficial:
        ...

    def safe_fields(self) -> set[str]:
        ...

    def anchor_check(
        self,
        item: ListingInput,
        signals: OfficialSignals,
    ) -> tuple[bool, dict[str, object]]:
        ...
