# backend/services/crawler/parsers/sku_hints/core_parts/mb_parsing.py
from __future__ import annotations

from .mb_specs import (
    extract_mb_head,
    extract_mb_spec_hints,
    extract_mb_sku_model_hint,
    infer_mb_brand_hint,
)


def extract_mb_hints(title: str) -> tuple[str | None, dict[str, object]]:
    sku_hint = extract_mb_sku_model_hint(title)
    head = extract_mb_head(title)
    extra = {
        "brand_hint": infer_mb_brand_hint(head) or infer_mb_brand_hint(sku_hint or "") or infer_mb_brand_hint(title or ""),
        "model_hint": sku_hint,
    }
    extra.update(
        extract_mb_spec_hints(
            title=title,
            head=head,
            sku_hint=sku_hint,
        )
    )
    return sku_hint, extra


def extract_mb_sku_hint(title: str) -> str | None:
    return extract_mb_sku_model_hint(title)
