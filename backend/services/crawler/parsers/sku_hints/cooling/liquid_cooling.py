# backend/services/crawler/parsers/sku_hints/cooling/liquid_cooling.py
from __future__ import annotations

from ..common import head_before_brackets, normalize_spaces, strip_leading_note
from ..shared_specs import normalized_title_line
from .liquid_cooling_specs import (
    extract_liquid_cooling_accessory_hint,
    extract_liquid_cooling_brand_hint,
    extract_liquid_cooling_limit_hint,
    extract_liquid_cooling_model_hint,
    extract_liquid_cooling_spec_hints,
    extract_liquid_cooling_warranty_years,
    infer_liquid_cooling_bundle,
)


def extract_liquid_cooling_sku_hint(title: str) -> str | None:
    line = normalized_title_line(title)
    return extract_liquid_cooling_model_hint(line)


def extract_liquid_cooling_hints(title: str) -> tuple[str | None, dict[str, object]]:
    line = normalized_title_line(title)
    head = head_before_brackets(line)
    full = normalize_spaces(strip_leading_note((title or "").replace("\n", " ")))
    sku_hint = extract_liquid_cooling_model_hint(line)
    extra = {
        "brand_hint": extract_liquid_cooling_brand_hint(head or line),
        "model_hint": sku_hint,
        "warranty_years": extract_liquid_cooling_warranty_years([full]),
        "limit_hint": extract_liquid_cooling_limit_hint(full),
        "is_bundle": infer_liquid_cooling_bundle(full),
        "is_accessory": extract_liquid_cooling_accessory_hint(full),
    }
    extra.update(extract_liquid_cooling_spec_hints(full))
    return sku_hint, extra


__all__ = ["extract_liquid_cooling_hints", "extract_liquid_cooling_sku_hint"]
