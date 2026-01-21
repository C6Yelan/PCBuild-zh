# backend/services/crawler/parsers/base.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ListingCandidate:
    title: str
    price: int | None          # 先用 int（TWD）；抽不到就 None
    currency: str
    category: str | None       # 先用字串；之後再做 enum/對照表
    url: str
    sku_hint: str | None       # 從品名抽出的「可能型號」，先不保證正確


class ListingParser(Protocol):
    source_id: str

    def parse_listings(self, *, html: str, page_url: str) -> list[ListingCandidate]:
        ...
