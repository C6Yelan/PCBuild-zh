# backend/services/crawler/parsers/sku_hints/core_parts/gpu_parsing.py
from __future__ import annotations

from .gpu_specs import (
    extract_gpu_aib_hint,
    extract_gpu_chip_and_brand,
    extract_gpu_product_model_hint,
    extract_gpu_vram_gb,
    infer_gpu_accessory,
    infer_gpu_bundle,
)
from ..shared_specs import normalized_title_line


def extract_gpu_hints(title: str) -> tuple[str | None, dict[str, object]]:
    full_text = title or ""
    line = normalized_title_line(full_text)
    sku_hint, brand_hint = extract_gpu_chip_and_brand(line, full_text)
    aib_hint = extract_gpu_aib_hint(line)

    extra = {
        "aib_hint": aib_hint,
        "brand_hint": brand_hint,
        "chip_hint": sku_hint,
        "product_model_hint": extract_gpu_product_model_hint(line, aib_hint),
        "vram_gb_hint": extract_gpu_vram_gb(full_text),
        "is_bundle": infer_gpu_bundle(full_text),
        "is_accessory": infer_gpu_accessory(full_text),
    }
    return sku_hint, extra


def extract_gpu_sku_hint(title: str) -> str | None:
    sku_hint, _extra = extract_gpu_hints(title)
    return sku_hint
