# backend/services/crawler/parsers/sku_hints/liquid_cooling.py
from .cooling.liquid_cooling import (
    extract_liquid_cooling_hints,
    extract_liquid_cooling_sku_hint,
)

__all__ = ["extract_liquid_cooling_hints", "extract_liquid_cooling_sku_hint"]
