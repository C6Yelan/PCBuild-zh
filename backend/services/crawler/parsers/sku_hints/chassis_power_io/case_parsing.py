from __future__ import annotations

from .case_specs import (
    extract_case_brand_hint,
    extract_case_model_hint,
    extract_case_spec_hints,
)
from ..shared_specs import build_title_desc_texts
from ..shared_specs import normalized_title_line
from ..shared_specs import strip_leading_bracket_tags


def extract_case_sku_hint(title: str) -> str | None:
    line = normalized_title_line(title)
    return extract_case_model_hint(strip_leading_bracket_tags(line))


def extract_case_hints(title: str, desc_lines: list[str] | None) -> tuple[str | None, dict[str, object]]:
    text = title or ""
    line, lines, _texts = build_title_desc_texts(text, desc_lines)
    clean_line = strip_leading_bracket_tags(line)
    head = clean_line.split("(", 1)[0].split("（", 1)[0].strip()

    sku_hint = extract_case_model_hint(clean_line)
    extra = {
        "brand_hint": extract_case_brand_hint(head or clean_line),
        "model_hint": sku_hint,
    }
    extra.update(
        extract_case_spec_hints(
            line=line,
            lines=lines,
            head=head,
            clean_line=clean_line,
        )
    )
    return sku_hint, extra
