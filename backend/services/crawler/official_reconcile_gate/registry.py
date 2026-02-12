# backend/services/crawler/official_reconcile_gate/registry.py
"""Registry for T6 source adapters and category matchers."""

from __future__ import annotations

from .adapters.base import SourceAdapter
from .matchers.base import CategoryMatcher

_SOURCE_ADAPTERS: dict[str, SourceAdapter] = {}
_CATEGORY_MATCHERS: dict[str, CategoryMatcher] = {}


def register_source_adapter(adapter: SourceAdapter) -> None:
    key = adapter.official_source
    if key in _SOURCE_ADAPTERS:
        raise ValueError(f"duplicate source adapter: {key}")
    _SOURCE_ADAPTERS[key] = adapter


def register_category_matcher(matcher: CategoryMatcher) -> None:
    key = matcher.category
    if key in _CATEGORY_MATCHERS:
        raise ValueError(f"duplicate category matcher: {key}")
    _CATEGORY_MATCHERS[key] = matcher


def get_source_adapter(official_source: str) -> SourceAdapter | None:
    return _SOURCE_ADAPTERS.get(official_source)


def get_category_matcher(category: str) -> CategoryMatcher | None:
    return _CATEGORY_MATCHERS.get(category)
