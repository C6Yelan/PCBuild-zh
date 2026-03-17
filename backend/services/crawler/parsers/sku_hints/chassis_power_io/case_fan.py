# backend/services/crawler/parsers/sku_hints/chassis_power_io/case_fan.py
from __future__ import annotations

from typing import Any

from ..shared_specs import build_title_desc_texts
from .case_fan_specs import (
    detect_case_fan_accessory_hints,
    extract_case_fan_model_hint,
    extract_case_fan_spec_hints,
)


def extract_case_fan_sku_hint(title: str) -> str | None:
    return extract_case_fan_model_hint(title)


def extract_case_fan_listing_hints(title: str, desc_lines: list[str] | None) -> tuple[str | None, dict[str, Any]]:
    line, _desc, texts = build_title_desc_texts(title, desc_lines)
    sku_hint = extract_case_fan_model_hint(line)
    is_accessory, accessory_kind_hint = detect_case_fan_accessory_hints(texts)
    extra = extract_case_fan_spec_hints(
        texts,
        is_accessory=is_accessory,
        accessory_kind_hint=accessory_kind_hint,
    )
    return sku_hint, extra


__all__ = ["extract_case_fan_listing_hints", "extract_case_fan_sku_hint"]
