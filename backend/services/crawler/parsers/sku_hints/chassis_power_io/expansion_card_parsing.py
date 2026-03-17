# backend/services/crawler/parsers/sku_hints/chassis_power_io/expansion_card_parsing.py
from __future__ import annotations

from .expansion_card_specs import (
    extract_expansion_card_brand_hint,
    extract_expansion_card_model_hint,
    extract_expansion_card_spec_hints,
)
from ..shared_specs import build_title_desc_texts
from ..shared_specs import normalized_title_line


def extract_expansion_card_sku_hint(title: str) -> str | None:
    line = normalized_title_line(title)
    return extract_expansion_card_model_hint(line)


def extract_expansion_card_hints(title: str, desc_lines: list[str] | None) -> tuple[str | None, dict[str, object]]:
    line, desc, texts = build_title_desc_texts(
        title,
        desc_lines,
        skip_substrings=("含稅",),
    )

    sku_hint = extract_expansion_card_model_hint(line)
    extra = {
        "brand_hint": extract_expansion_card_brand_hint(line),
        "model_hint": sku_hint,
    }
    extra.update(
        extract_expansion_card_spec_hints(
            line=line,
            desc=desc,
            texts=texts,
        )
    )
    return sku_hint, extra
