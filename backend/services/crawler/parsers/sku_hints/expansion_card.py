# backend/services/crawler/parsers/sku_hints/expansion_card.py
from .chassis_power_io.expansion_card import (
    extract_expansion_card_hints,
    extract_expansion_card_sku_hint,
)

__all__ = ["extract_expansion_card_hints", "extract_expansion_card_sku_hint"]
