# backend/services/crawler/parsers/sku_hints/shared_specs.py
"""Low-risk shared spec parsing façade for sku_hints extractors."""

from .shared_text_specs import (
    build_title_desc_texts,
    extract_brand_hint,
    extract_model_head,
    extract_model_hint,
    normalize_nonempty_lines,
    normalized_title_line,
    strip_leading_bracket_tags,
)
from .shared_value_specs import (
    extract_capacity_gib,
    extract_limit_hint,
    extract_warranty_years,
    extract_warranty_years_with_registration,
    normalize_length_mm,
)

__all__ = [
    "build_title_desc_texts",
    "extract_brand_hint",
    "extract_capacity_gib",
    "extract_limit_hint",
    "extract_model_head",
    "extract_model_hint",
    "extract_warranty_years",
    "extract_warranty_years_with_registration",
    "normalize_length_mm",
    "normalize_nonempty_lines",
    "normalized_title_line",
    "strip_leading_bracket_tags",
]
