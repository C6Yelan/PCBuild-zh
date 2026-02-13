# backend/services/crawler/official_reconcile_gate/matchers/base.py
from __future__ import annotations

from typing import Protocol

from ..types import MatchResult, RetailRecord


class OfficialMatcher(Protocol):
    def match(self, record: RetailRecord) -> MatchResult:
        ...
