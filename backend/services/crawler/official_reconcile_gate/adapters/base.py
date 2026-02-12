# backend/services/crawler/official_reconcile_gate/adapters/base.py
"""Source adapter protocol for T6 official reconciliation."""

from __future__ import annotations

from typing import Protocol

from ..types import ListingInput, OfficialCandidate, OfficialSignals


class SourceAdapter(Protocol):
    official_source: str

    def search_candidates(self, item: ListingInput) -> list[OfficialCandidate]:
        # 給一筆零售端商品（ListingInput），去官網（或官網索引）找可能對應的候選商品清單。
        ...

    def fetch_signals(self, candidate: OfficialCandidate) -> OfficialSignals:
        # 對某個候選 URL/物件抓頁並抽規格信號（型號、規格、識別碼等），回傳 OfficialSignals 給 matcher 做比對。
        ...
