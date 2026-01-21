# backend/services/crawler/parsers/__init__.py
from .base import ListingCandidate, ListingParser
from .registry import get_listing_parser

__all__ = ["ListingCandidate", "ListingParser", "get_listing_parser"]
