from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

DiscoveryMethod = Literal["sitemap"]


@dataclass(frozen=True)
class DiscoveryEvidence:
    discovery_method: DiscoveryMethod
    discovery_source: str
    query_terms: list[str] = field(default_factory=list)
    matched_tokens: list[str] = field(default_factory=list)
    candidate_rank: int = 0
    notes: str = ""


@dataclass(frozen=True)
class SitemapCandidate:
    plan_index: int
    retail_url: str
    source: str
    category: str
    brand_key: str | None
    official_url: str
    score: int
    evidence: DiscoveryEvidence


@dataclass
class DiscoveryResult:
    total_plans: int = 0
    ok_plans: int = 0
    skipped_plans: int = 0
    plans_with_hits: int = 0
    plans_no_hits: int = 0
    seeds_used_count: int = 0
    default_entrypoints_used_count: int = 0
    fetched_sitemaps: int = 0
    parsed_urlsets: int = 0
    parsed_indexes: int = 0
    total_candidates_emitted: int = 0
    errors_count: int = 0
    error_reasons: dict[str, int] = field(default_factory=dict)
    candidates: list[SitemapCandidate] = field(default_factory=list)

    def add_error(self, reason: str) -> None:
        self.errors_count += 1
        self.error_reasons[reason] = self.error_reasons.get(reason, 0) + 1
