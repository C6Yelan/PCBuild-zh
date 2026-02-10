# backend/services/crawler/link_consistency_gate/strategies/base.py
# 定義了 Link Consistency Gate 的基礎策略接口和一個預設的未實作策略。
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..types import ListingInput, MatchDecision, PageSignals


class Strategy(Protocol): # 定義了 Link Consistency Gate 的策略接口，要求實作 decide 方法來根據 listing 和 page signals 做出決策。
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision: ...


@dataclass(frozen=True)
class NotImplementedStrategy: # 提供了一個預設的未實作策略，當 decide 方法被調用時，會返回一個不確定的決策，並附帶一個說明未實作的 reason code。
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        # Keep evidence keys stable; per-category logic is intentionally absent.
        evidence: dict[str, Any] = {
            "listing_tokens": [],
            "page_tokens": [],
            "matched_tokens": [],
            "notes": [],
        }
        return MatchDecision(
            status="uncertain",
            score=None,
            reason_code="STRATEGY_NOT_IMPLEMENTED",
            evidence=evidence,
        )
