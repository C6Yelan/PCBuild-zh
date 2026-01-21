# backend/services/crawler/sources.py
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SourceId(StrEnum):
    COOLPC = "coolpc"          # 原價屋（零售 listing）
    OFFICIAL = "official"      # 品牌官網（規格真相層；先保留）


@dataclass(frozen=True)
class Source:
    id: SourceId
    name: str
    base_url: str
    default_currency: str = "TWD"


SOURCES: dict[SourceId, Source] = {
    SourceId.COOLPC: Source(
        id=SourceId.COOLPC,
        name="原價屋 CoolPC",
        base_url="https://www.coolpc.com.tw",
        default_currency="TWD",
    ),
    SourceId.OFFICIAL: Source(
        id=SourceId.OFFICIAL,
        name="Brand Official Sites",
        base_url="https://example.com",
    ),
}
