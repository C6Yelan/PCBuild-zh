from __future__ import annotations

from ..common import first_line, head_before_brackets, normalize_spaces, strip_leading_note
from ..shared_specs import extract_warranty_years
from ..shared_specs import normalized_title_line
from .cooler_specs import (
    detect_cooler_kind,
    extract_cooler_brand_hint,
    extract_cooler_detail_hints,
    extract_cooler_limit_hint,
    extract_cooler_model_hint,
    infer_cooler_accessory,
    infer_cooler_bundle,
)


def extract_cooler_sku_hint(title: str) -> str | None:
    line = normalized_title_line(title)
    return extract_cooler_model_hint(line)


def extract_cooler_hints(title: str) -> tuple[str | None, dict[str, object]]:
    raw = strip_leading_note(title)
    line = normalize_spaces(first_line(raw))
    full = normalize_spaces(raw)
    head = head_before_brackets(line)

    cooler_kind_hint = detect_cooler_kind(line)
    sku_hint = extract_cooler_model_hint(line)
    extra = {
        "brand_hint": extract_cooler_brand_hint(head or line),
        "model_hint": sku_hint,
        "cooler_kind_hint": cooler_kind_hint,
        "warranty_years": extract_warranty_years([full]),
        "limit_hint": extract_cooler_limit_hint([full]),
        "is_bundle": infer_cooler_bundle(head),
        "is_accessory": infer_cooler_accessory(line, cooler_kind_hint),
    }
    extra.update(
        extract_cooler_detail_hints(
            line=line,
            full=full,
            cooler_kind_hint=cooler_kind_hint,
        )
    )
    return sku_hint, extra
