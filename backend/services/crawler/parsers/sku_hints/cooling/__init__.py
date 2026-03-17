# backend/services/crawler/parsers/sku_hints/cooling/__init__.py
from .cooler import extract_cooler_hints, extract_cooler_sku_hint
from .liquid_cooling import extract_liquid_cooling_hints, extract_liquid_cooling_sku_hint

__all__ = [
    "extract_cooler_hints",
    "extract_cooler_sku_hint",
    "extract_liquid_cooling_hints",
    "extract_liquid_cooling_sku_hint",
]
