# backend/services/crawler/parsers/coolpc.py
from __future__ import annotations

from .base import ListingCandidate, ListingParser


class CoolpcListingParser:
    """
    原價屋 listing parser（骨架）：
    - 目前先回傳空陣列
    - 下一步才會針對 CPU/MB/VGA 的頁面結構做解析
    """
    source_id = "coolpc"

    def parse_listings(self, *, html: str, page_url: str) -> list[ListingCandidate]:
        # TODO: Step 5 針對特定頁型實作解析
        return []
