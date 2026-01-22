# backend/services/crawler/parsers/registry.py
from __future__ import annotations

from backend.services.crawler.sources import SourceId
from .base import ListingParser
from .coolpc import CoolpcListingParser


def get_listing_parser(source_id: SourceId) -> ListingParser:
    if source_id == SourceId.COOLPC:
        return CoolpcListingParser()
    raise KeyError(f"No listing parser for source: {source_id}")
