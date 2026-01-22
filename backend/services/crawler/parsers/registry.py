# backend/services/crawler/parsers/registry.py
from __future__ import annotations

from backend.services.crawler.sources import SourceId

from .base import ListingParser
from .coolpc import CoolpcListingParser

_LISTING_PARSERS: dict[SourceId, ListingParser] = {
    SourceId.COOLPC: CoolpcListingParser(),
}


def get_listing_parser(source_id: SourceId) -> ListingParser:
    parser = _LISTING_PARSERS.get(source_id)
    if parser is None:
        raise ValueError(f"Unsupported source_id: {source_id}")
    return parser
