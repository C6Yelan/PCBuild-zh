# backend/services/crawler/parsers/sku_hints/cooling/cooler_primitives.py
from .cooler_detail_specs import extract_cooler_detail_hints
from .cooler_identity_specs import (
    detect_cooler_kind,
    extract_cooler_brand_hint,
    extract_cooler_limit_hint,
    extract_cooler_model_hint,
    infer_cooler_accessory,
    infer_cooler_bundle,
)

__all__ = [
    "detect_cooler_kind",
    "extract_cooler_brand_hint",
    "extract_cooler_detail_hints",
    "extract_cooler_limit_hint",
    "extract_cooler_model_hint",
    "infer_cooler_accessory",
    "infer_cooler_bundle",
]
