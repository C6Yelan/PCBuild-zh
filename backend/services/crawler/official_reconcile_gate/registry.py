# backend/services/crawler/official_reconcile_gate/registry.py
from __future__ import annotations

from dataclasses import dataclass, field

from .adapters.base import OfficialAdapter
from .adapters.generic_html import GenericHtmlOfficialAdapter
from .matchers.base import OfficialMatcher
from .matchers.manual_url import ManualUrlMatcher


@dataclass
class ReconcileRegistry:
    _adapters_by_source: dict[str, OfficialAdapter] = field(default_factory=dict)
    _matchers_by_category: dict[str, OfficialMatcher] = field(default_factory=dict)
    _default_adapter: OfficialAdapter = field(default_factory=GenericHtmlOfficialAdapter)
    _default_matcher: OfficialMatcher = field(default_factory=ManualUrlMatcher)

    def register_adapter(self, source: str, adapter: OfficialAdapter) -> None:
        self._adapters_by_source[(source or "").upper()] = adapter

    def register_matcher(self, category: str, matcher: OfficialMatcher) -> None:
        self._matchers_by_category[(category or "").upper()] = matcher

    def get_adapter(self, source: str) -> OfficialAdapter:
        return self._adapters_by_source.get((source or "").upper(), self._default_adapter)

    def get_matcher(self, category: str) -> OfficialMatcher:
        return self._matchers_by_category.get((category or "").upper(), self._default_matcher)


def build_default_registry() -> ReconcileRegistry:
    return ReconcileRegistry()
