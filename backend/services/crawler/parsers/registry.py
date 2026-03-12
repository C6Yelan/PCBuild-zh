# backend/services/crawler/parsers/registry.py
from __future__ import annotations

from collections.abc import Callable

from backend.services.crawler.registry_primitives import lookup_registry_entry
from backend.services.crawler.sources import SourceId
from .base import ListingParser
from .coolpc import CoolpcListingParser

_PARSER_FACTORIES: dict[SourceId, Callable[[], ListingParser]] = {
    SourceId.COOLPC: CoolpcListingParser,
}


def get_listing_parser(source_id: SourceId) -> ListingParser:
    factory = lookup_registry_entry(
        _PARSER_FACTORIES,
        source_id,
        missing_factory=lambda key: KeyError(f"No listing parser for source: {key}"),
    )
    return factory()
