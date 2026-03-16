from __future__ import annotations

from .cooler_primitives import (
    detect_cooler_kind,
    extract_cooler_brand_hint,
    extract_cooler_detail_hints,
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
