# backend/services/crawler/parsers/sku_hints/chassis_power_io/expansion_card_specs.py
from .expansion_card_detail_specs import extract_expansion_card_spec_hints
from .expansion_card_identity_specs import (
    extract_expansion_card_brand_hint,
    extract_expansion_card_model_hint,
)

__all__ = [
    "extract_expansion_card_brand_hint",
    "extract_expansion_card_model_hint",
    "extract_expansion_card_spec_hints",
]
