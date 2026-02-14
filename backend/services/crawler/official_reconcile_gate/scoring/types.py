from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

DecisionKind = Literal["accepted", "needs_manual_review", "no_candidates"]


@dataclass(frozen=True)
class ScoreBreakdown:
    plan_index: int
    retail_url: str
    source: str
    category: str
    brand_key: str | None
    official_url: str
    total_score: int
    components: dict[str, int] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    matched_tokens: list[str] = field(default_factory=list)
    title_token_hits: list[str] = field(default_factory=list)
    block_reason: str | None = None
    content_type: str | None = None


@dataclass(frozen=True)
class DecisionRecord:
    plan_index: int
    retail_url: str
    source: str
    category: str
    brand_key: str | None
    decision: DecisionKind
    decision_reason: str
    chosen_official_url: str | None
    confidence: int
    top1_score: int | None
    top_k_summary: list[dict[str, Any]] = field(default_factory=list)
