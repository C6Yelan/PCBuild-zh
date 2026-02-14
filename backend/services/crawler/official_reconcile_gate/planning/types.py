# backend/services/crawler/official_reconcile_gate/planning/types.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict

BrandSource = Literal[
    "extra.brand_hint",
    "extra.maker_hint",
    "title_or_sku_hint+registry_alias",
    "unknown",
]

PlanDecision = Literal["ok", "needs_registry", "quarantine"]


class RetailCandidate(TypedDict, total=False):
    source: str
    category: str
    title: str
    url: str
    sku_hint: str
    extra: dict[str, Any]


@dataclass(frozen=True)
class BrandResolution:
    brand_key: str | None
    brand_source: BrandSource
    brand_raw: str | None


@dataclass(frozen=True)
class BrandRegistryEntry:
    brand_key: str
    brand_aliases: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class OfficialRegistry:
    version: int
    brands: list[BrandRegistryEntry] = field(default_factory=list)
    alias_map: dict[str, str] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class OfficialLookupPlan:
    retail_url: str
    source: str
    category: str
    title: str
    sku_hint: str
    brand_key: str | None
    brand_source: BrandSource
    brand_raw: str | None
    allowed_domains: list[str] = field(default_factory=list)
    query_terms: list[str] = field(default_factory=list)
    decision: PlanDecision = "quarantine"
    decision_notes: str = ""
